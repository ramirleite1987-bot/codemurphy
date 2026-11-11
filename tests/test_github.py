from unittest import TestCase

from codemurphy.config import load_config
from codemurphy.github import GitHub, GitHubError, Skipped, publish, snapshot
from codemurphy.review import run_review

BASE, HEAD = "a" * 40, "b" * 40
REPO = "owner/demo"
PREFIX = "/repos/owner/demo/pulls/5"


def pull(head=HEAD, repo=REPO, count=1, branch="main"):
    return {"state": "open", "base": {"sha": BASE, "ref": branch, "repo": {"full_name": REPO}},
            "head": {"sha": head, "repo": {"full_name": repo}},
            "changed_files": count, "title": "Untrusted PR title", "body": None}


def changed(path="x.py"):
    return {"filename": path, "additions": 1, "deletions": 0,
            "patch": "@@ -0,0 +1 @@\n+test = True"}


class FakeGitHub(GitHub):
    def __init__(self, responses):
        super().__init__("fake-token")
        self.responses = responses
        self.calls = []

    def request(self, path, body=None):
        self.calls.append((path, body))
        if body is not None:
            return {"id": 100}
        value = self.responses[path]
        return value.pop(0) if isinstance(value, list) and value and isinstance(value[0], list) else value


class GitHubTests(TestCase):
    def test_metadata_then_all_diff_pages_then_metadata(self):
        files = [changed(f"src/{i}.py") for i in range(100)]
        api = FakeGitHub({PREFIX: pull(count=101), PREFIX + "/files?per_page=100&page=1": files,
                          PREFIX + "/files?per_page=100&page=2": [changed("end.py")]})
        pr = snapshot(api, REPO, 5, expected_head=HEAD, trusted_base="main")
        self.assertEqual(len(pr.files), 101)
        self.assertEqual(pr.files[-1].path, "end.py")
        self.assertEqual([x[0] for x in api.calls].count(PREFIX), 2)

    def test_fork_and_untrusted_base_are_skipped_before_diff_is_read(self):
        for metadata in (pull(repo="somebody/demo"), pull(branch="feature")):
            api = FakeGitHub({PREFIX: metadata})
            with self.assertRaises(Skipped):
                snapshot(api, REPO, 5, trusted_base="main")
            self.assertEqual(api.calls, [(PREFIX, None)])

    def test_stale_head_never_publishes(self):
        api = FakeGitHub({PREFIX: pull(), PREFIX + "/files?per_page=100&page=1": [changed()]})
        pr = snapshot(api, REPO, 5)
        report = run_review(load_config(), pr.files, static_only=True)
        api.responses[PREFIX] = pull("c"*40)
        with self.assertRaises(GitHubError):
            publish(api, pr, report, load_config(), publisher="github-actions[bot]")
        self.assertTrue(all(body is None for _, body in api.calls))

    def test_only_actual_publisher_can_dedupe_and_comments_are_plain(self):
        key = PREFIX + "/reviews?per_page=100&page=1"
        api = FakeGitHub({PREFIX: pull(), PREFIX + "/files?per_page=100&page=1": [changed()]})
        pr = snapshot(api, REPO, 5)
        report = run_review(load_config(), pr.files, static_only=True)
        report["findings"] = [{"path": "x.py", "line": 1, "side": "RIGHT", "category": "security",
                              "severity": "high", "title": "@team [click](https://bad.test)",
                              "detail": "<img src=https://bad.test> #42", "suggestion": "Fix it",
                              "sources": ["static"], "citations": []}]
        api.responses[key] = [{"user": {"login": "spoof"}, "body": pr.marker}]
        self.assertEqual(publish(api, pr, report, load_config(), publisher="github-actions[bot]", scope="combined"), "posted")
        body = api.calls[-1][1]
        self.assertEqual(body["event"], "COMMENT")
        self.assertEqual(body["commit_id"], HEAD)
        [comment] = body["comments"]
        self.assertNotIn("@team", comment["body"])
        self.assertNotIn("https://", comment["body"])
        self.assertNotIn("<img", comment["body"])
        self.assertNotIn("#42", comment["body"])
        api.responses[key] = [{"user": {"login": "github-actions[bot]"}, "body": pr.marker}]
        self.assertEqual(publish(api, pr, report, load_config(), publisher="github-actions[bot]"), "already-posted")

    def test_private_context_cannot_be_posted(self):
        api = FakeGitHub({PREFIX: pull(), PREFIX + "/files?per_page=100&page=1": [changed()]})
        pr = snapshot(api, REPO, 5)
        report = run_review(load_config(), pr.files, static_only=True)
        report["private_context"] = True
        with self.assertRaisesRegex(GitHubError, "Private"):
            publish(api, pr, report, load_config(), publisher="github-actions[bot]")

    def test_blob_refuses_symlinks(self):
        api = FakeGitHub({f"/repos/{REPO}/git/commits/{BASE}": {"sha": BASE, "tree": {"sha": HEAD}},
                          f"/repos/{REPO}/git/trees/{HEAD}": {"tree": [
                              {"path": "config.json", "mode": "120000", "type": "blob", "sha": "c"*40}]}})
        with self.assertRaisesRegex(GitHubError, "regular file"):
            api.blob(REPO, BASE, "config.json")

    def test_rename_cannot_bypass_sensitive_path_exclusions(self):
        entry = {**changed("settings.txt"), "previous_filename": ".env", "status": "renamed",
                 "patch": "@@ -1 +1,2 @@\n SESSION=keep-it-private\n+safe = True"}
        api = FakeGitHub({PREFIX: pull(), PREFIX + "/files?per_page=100&page=1": [entry]})
        pr = snapshot(api, REPO, 5)
        report = run_review(load_config(), pr.files, static_only=True)
        self.assertEqual(report["coverage"]["excluded_files"], 1)
