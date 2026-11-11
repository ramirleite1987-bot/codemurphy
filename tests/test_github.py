import json
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from codemurphy.cli import main

from codemurphy.config import load_config
from codemurphy.github import GitHub, GitHubError, Skipped, publish, snapshot
from codemurphy.providers import ModelError, Reply
from codemurphy.review import run_review

BASE, HEAD = "a" * 40, "b" * 40
REPO = "owner/demo"
PREFIX = "/repos/owner/demo/pulls/5"


def compare_path(base):
    return f"/repos/owner/demo/compare/{base}...{HEAD}?per_page=1"


def comparison(base, files, *, merge=None):
    return {"base_commit": {"sha": base}, "merge_base_commit": {"sha": merge or base}, "files": list(files)}


def pull(head=HEAD, repo=REPO, count=1, branch="main", author="contributor", draft=False):
    return {"state": "open", "base": {"sha": BASE, "ref": branch, "repo": {"full_name": REPO}},
            "head": {"sha": head, "repo": {"full_name": repo}},
            "changed_files": count, "draft": draft, "title": "Untrusted PR title", "body": None,
            "user": {"login": author}}


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

    def test_expected_base_mismatch_does_not_read_diff(self):
        api = FakeGitHub({PREFIX: pull()})
        with self.assertRaisesRegex(Skipped, "base commit changed"):
            snapshot(api, REPO, 5, expected_base="d"*40)
        self.assertEqual(api.calls, [(PREFIX, None)])

    def test_duplicate_review_cannot_bypass_severity_gate(self):
        entry = changed("settings.py")
        entry["patch"] = '@@ -0,0 +1 @@\n+CLIENT_SECRET = "synthetic_credential_for_gate_fixture"'
        api = FakeGitHub({PREFIX: pull(), PREFIX + "/files?per_page=100&page=1": [entry]})
        pr = snapshot(api, REPO, 5)
        api.responses[PREFIX + "/reviews?per_page=100&page=1"] = [
            {"user": {"login": "github-actions[bot]"}, "body": pr.marker}]
        with patch.dict("os.environ", {"CODEMURPHY_GITHUB_TOKEN": "fixture"}), \
             patch("codemurphy.cli.GitHub", return_value=api), redirect_stdout(StringIO()):
            code = main(["github", "--repo", REPO, "--pr", "5", "--static-only", "--publish",
                         "--fail-on", "high", "--publisher-login", "github-actions[bot]"])
        self.assertEqual(code, 1)
        self.assertTrue(all(body is None for _, body in api.calls))



def formal_config(verify=True, **review):
    return {"models": [{"id": "main", "model": "reviewer"}, {"id": "check", "model": "verifier"}],
            "review": {"verify_with": "check" if verify else None, **review}}


def review_provider(proposals=0, *, confirm=True, failure=None):
    def provider(model, system, data, timeout):
        if model.id == failure:
            raise ModelError("Fixture provider failure")
        if model.id == "main":
            result = {"findings": [
                {"path": "x.py", "line": i + 1, "side": "RIGHT", "quote": "test = True",
                 "category": "correctness", "severity": "high", "confidence": .95,
                 "title": "This update always enables test mode",
                 "detail": "The flag enables test mode for production requests.",
                 "suggestion": "Preserve the existing environment check.", "citations": []}
                for i in range(proposals)]}
        else:
            result = {"confirmed": [
                {"id": item["id"], "quote": item["evidence"]}
                for item in json.loads(data).get("candidates", []) if confirm]}
        return Reply(json.dumps(result), 20, 10)
    return provider


class FormalReviewTests(TestCase):
    def fixture(self, *files, author="contributor", reviews=()):
        entries = files or (changed(),)
        return FakeGitHub({PREFIX: pull(count=len(entries), author=author),
                           compare_path(BASE): comparison(BASE, entries),
                           PREFIX + "/reviews?per_page=100&page=1": list(reviews),
                           "/user": {"login": "review-bot"}})

    def writes(self, api):
        return [body for _, body in api.calls if body is not None]

    def test_formal_snapshot_uses_the_exact_merge_base_diff(self):
        merge = "c" * 40
        api = self.fixture()
        api.responses[compare_path(BASE)] = comparison(BASE, [changed("different-comparison.py")], merge=merge)
        api.responses[compare_path(merge)] = comparison(merge, [changed()])
        api.responses[PREFIX + "/files?per_page=100&page=1"] = [changed("other-head.py")]
        pr = snapshot(api, REPO, 5, pinned_diff=True)
        self.assertEqual([file.path for file in pr.files], ["x.py"])
        self.assertEqual([path for path, _ in api.calls], [PREFIX, compare_path(BASE), compare_path(merge), PREFIX])
        config = load_config(formal_config())
        report = run_review(config, pr.files, provider=review_provider(1))
        publish(api, pr, report, config, review_mode="approve-reject")
        self.assertEqual([review["event"] for review in self.writes(api)], ["REQUEST_CHANGES"])

    def test_formal_snapshot_rejects_an_unverified_or_incomplete_comparison(self):
        wrong_base, merge = "c" * 40, "d" * 40
        for bad, message in (
            (comparison(wrong_base, [changed()]), "base"),
            (comparison(BASE, [changed()], merge="main"), "merge base"),
            (comparison(BASE, []), "incomplete"),
            ({**comparison(BASE, [changed()]), "truncated": True}, "truncated"),
            (comparison(BASE, [changed()], merge=merge), "merge base"),
        ):
            with self.subTest(message=message, bad=bad):
                api = self.fixture()
                api.responses[compare_path(BASE)] = bad
                api.responses[compare_path(merge)] = comparison(merge, [changed()], merge=wrong_base)
                with self.assertRaisesRegex(GitHubError, message):
                    snapshot(api, REPO, 5, pinned_diff=True)
                self.assertEqual(self.writes(api), [])
        api = FakeGitHub({PREFIX: pull(count=301)})
        with self.assertRaisesRegex(GitHubError, "300"):
            snapshot(api, REPO, 5, pinned_diff=True)
        self.assertEqual(api.calls, [(PREFIX, None)])

    def test_formal_publisher_rejects_a_snapshot_from_mutable_pr_files(self):
        api = self.fixture()
        api.responses[PREFIX + "/files?per_page=100&page=1"] = [changed()]
        pr = snapshot(api, REPO, 5)
        config = load_config(formal_config())
        report = run_review(config, pr.files, provider=review_provider())
        with self.assertRaisesRegex(GitHubError, "pinned"):
            publish(api, pr, report, config, review_mode="approve-reject")
        self.assertEqual(self.writes(api), [])

    def test_completed_verified_review_submits_the_matching_disposition(self):
        config = load_config(formal_config())
        for proposals, confirm, event in ((0, True, "APPROVE"), (1, False, "APPROVE"),
                                          (1, True, "REQUEST_CHANGES")):
            with self.subTest(proposals=proposals, confirm=confirm):
                api = self.fixture()
                pr = snapshot(api, REPO, 5, pinned_diff=True)
                report = run_review(config, pr.files, provider=review_provider(proposals, confirm=confirm))
                publication = publish(api, pr, report, config, review_mode="approve-reject")
                [review] = self.writes(api)
                self.assertEqual(review["event"], event)
                self.assertIn(event, publication)
                self.assertEqual(review["commit_id"], HEAD)
                self.assertIn(pr.marker, review["body"].splitlines())
                self.assertEqual([(c["path"], c["side"], c["line"]) for c in review["comments"]],
                                 [("x.py", "RIGHT", 1)] if event == "REQUEST_CHANGES" else [])

    def test_unverified_review_cannot_submit_formal_disposition(self):
        for static in (True, False):
            with self.subTest(static=static):
                api = self.fixture()
                pr = snapshot(api, REPO, 5, pinned_diff=True)
                config = load_config(formal_config(verify=static))
                report = run_review(config, pr.files, provider=review_provider(), static_only=static)
                with self.assertRaisesRegex(GitHubError, "static|verif"):
                    publish(api, pr, report, config, review_mode="approve-reject")
                self.assertEqual(self.writes(api), [])

    def test_failed_primary_or_verification_request_withholds_the_disposition(self):
        config = load_config(formal_config())
        for failure in ("main", "check"):
            with self.subTest(failure=failure):
                api = self.fixture()
                pr = snapshot(api, REPO, 5, pinned_diff=True)
                report = run_review(config, pr.files, provider=review_provider(1, failure=failure))
                with self.assertRaisesRegex(GitHubError, "failed"):
                    publish(api, pr, report, config, review_mode="approve-reject")
                self.assertEqual(self.writes(api), [])

    def test_ungrounded_primary_response_does_not_turn_into_approval(self):
        api = self.fixture()
        pr = snapshot(api, REPO, 5, pinned_diff=True)
        config = load_config(formal_config())

        def provider(*args):
            reply = review_provider(1)(*args)
            return Reply(reply.content.replace("test = True", "a line that does not exist"), 20, 10)

        report = run_review(config, pr.files, provider=provider)
        self.assertEqual(report["models"]["main"]["rejected"], 1)
        self.assertEqual(report["verification"]["requests"], 0)
        with self.assertRaisesRegex(GitHubError, "evidence|rejected"):
            publish(api, pr, report, config, review_mode="approve-reject")
        self.assertEqual(self.writes(api), [])

    def test_changed_target_cannot_be_approved_even_with_same_commits(self):
        base_moved = pull()
        base_moved["base"]["repo"]["full_name"] = "other/demo"
        for changed_metadata in (pull(branch="release"), pull(repo="other/demo"), base_moved, pull(draft=True)):
            with self.subTest(metadata=changed_metadata):
                api = self.fixture()
                pr = snapshot(api, REPO, 5, trusted_base="main", pinned_diff=True)
                config = load_config(formal_config())
                report = run_review(config, pr.files, provider=review_provider())
                api.responses[PREFIX] = changed_metadata
                with self.assertRaisesRegex(GitHubError, "changed"):
                    publish(api, pr, report, config, review_mode="approve-reject")
                self.assertEqual(self.writes(api), [])

    def test_same_sha_retarget_during_comparison_invalidates_snapshot(self):
        class RetargetingGitHub(FakeGitHub):
            def request(self, path, body=None):
                response = super().request(path, body)
                if path == compare_path(BASE):
                    self.responses[PREFIX] = pull(branch="release")
                return response

        api = RetargetingGitHub(self.fixture().responses)
        with self.assertRaisesRegex(GitHubError, "changed"):
            snapshot(api, REPO, 5, trusted_base="main", pinned_diff=True)
        self.assertEqual(self.writes(api), [])

    def test_draft_is_observable_but_cannot_receive_a_formal_verdict(self):
        api = self.fixture()
        api.responses[PREFIX]["draft"] = True
        pr = snapshot(api, REPO, 5, pinned_diff=True)
        config = load_config(formal_config())
        report = run_review(config, pr.files, provider=review_provider())
        with self.assertRaisesRegex(GitHubError, "draft"):
            publish(api, pr, report, config, review_mode="approve-reject")
        self.assertEqual(self.writes(api), [])

    def test_unreviewable_or_excluded_file_prevents_a_formal_disposition(self):
        config = load_config(formal_config())
        for entry in ({"filename": "binary.png", "additions": 0, "deletions": 0},
                      {"filename": "truncated.py", "additions": 2, "deletions": 0},
                      changed(".env")):
            with self.subTest(path=entry["filename"]):
                api = self.fixture(changed(), entry)
                pr = snapshot(api, REPO, 5, pinned_diff=True)
                report = run_review(config, pr.files, provider=review_provider(1))
                with self.assertRaisesRegex(GitHubError, "coverage"):
                    publish(api, pr, report, config, review_mode="approve-reject")
                self.assertEqual(self.writes(api), [])

    def test_verification_cap_withholds_even_with_other_confirmed_findings(self):
        api = self.fixture({**changed(), "additions": 13,
                            "patch": "@@ -0,0 +1,13 @@\n" + "+test = True\n" * 13})
        pr = snapshot(api, REPO, 5, pinned_diff=True)
        config = load_config(formal_config())
        report = run_review(config, pr.files, provider=review_provider(13))
        self.assertEqual(report["verification"]["withheld"], 1)
        self.assertEqual(report["verification"]["confirmed"], 12)
        with self.assertRaisesRegex(GitHubError, "verification.*cap"):
            publish(api, pr, report, config, review_mode="approve-reject")
        self.assertEqual(self.writes(api), [])

    def test_no_primary_requests_cannot_produce_an_approval(self):
        api = FakeGitHub({PREFIX: pull(count=0), compare_path(BASE): comparison(BASE, [])})
        pr = snapshot(api, REPO, 5, pinned_diff=True)
        config = load_config(formal_config())
        report = run_review(config, pr.files, provider=review_provider())
        with self.assertRaisesRegex(GitHubError, "primary"):
            publish(api, pr, report, config, review_mode="approve-reject")
        self.assertEqual(self.writes(api), [])

    def test_a_blocking_review_requires_an_actionable_inline_finding(self):
        api = self.fixture()
        pr = snapshot(api, REPO, 5, pinned_diff=True)
        config = load_config(formal_config(max_comments=0))
        report = run_review(config, pr.files, provider=review_provider(1))
        with self.assertRaisesRegex(GitHubError, "inline"):
            publish(api, pr, report, config, review_mode="approve-reject")
        self.assertEqual(self.writes(api), [])

    def test_only_latest_matching_formal_disposition_dedupes_exact_snapshot(self):
        config = load_config(formal_config())
        exact = f"<!-- codemurphy:{BASE}:{HEAD} -->"
        approval = {"user": {"login": "Review-Bot"}, "state": "APPROVED", "body": exact, "commit_id": HEAD}
        for prior, should_post in (
            ([approval], False),
            ([approval, {**approval, "state": "COMMENTED"}], False),
            ([approval, {**approval, "state": "CHANGES_REQUESTED"}], True),
            ([approval, {**approval, "state": "DISMISSED"}], True),
            ([{**approval, "state": "COMMENTED"}], True),
            ([{**approval, "user": {"login": "someone-else"}}], True),
            ([{**approval, "body": f"<!-- codemurphy:{'c' * 40}:{HEAD} -->"}], True),
            ([{**approval, "commit_id": "c" * 40}], True),
        ):
            with self.subTest(prior=prior):
                api = self.fixture(reviews=prior)
                pr = snapshot(api, REPO, 5, pinned_diff=True)
                report = run_review(config, pr.files, provider=review_provider())
                publish(api, pr, report, config, review_mode="approve-reject")
                self.assertEqual([review["event"] for review in self.writes(api)],
                                 ["APPROVE"] if should_post else [])

    def test_formal_review_does_not_dedupe_comment_mode(self):
        review = {"user": {"login": "review-bot"}, "state": "APPROVED", "commit_id": HEAD,
                  "body": f"<!-- codemurphy:{BASE}:{HEAD} -->"}
        api = self.fixture(reviews=[review])
        pr = snapshot(api, REPO, 5, pinned_diff=True)
        config = load_config()
        report = run_review(config, pr.files, static_only=True)
        self.assertEqual(publish(api, pr, report, config), "posted")
        self.assertEqual([review["event"] for review in self.writes(api)], ["COMMENT"])

    def test_self_approval_is_withheld_without_falling_back_to_a_comment(self):
        api = self.fixture(author="Review-Bot")
        pr = snapshot(api, REPO, 5, pinned_diff=True)
        config = load_config(formal_config())
        report = run_review(config, pr.files, provider=review_provider())
        with self.assertRaisesRegex(GitHubError, "own pull request"):
            publish(api, pr, report, config, review_mode="approve-reject")
        self.assertEqual(self.writes(api), [])

    def test_api_refusal_never_downgrades_approval_or_exposes_the_response(self):
        class RejectingGitHub(FakeGitHub):
            def request(self, path, body=None):
                result = super().request(path, body)
                if body is not None:
                    raise GitHubError("Sensitive upstream response detail", 422)
                return result

        api = RejectingGitHub(self.fixture().responses)
        pr = snapshot(api, REPO, 5, pinned_diff=True)
        config = load_config(formal_config())
        report = run_review(config, pr.files, provider=review_provider())
        with self.assertRaisesRegex(GitHubError, "GitHub declined APPROVE") as error:
            publish(api, pr, report, config, review_mode="approve-reject")
        self.assertNotIn("Sensitive", str(error.exception))
        self.assertEqual([review["event"] for review in self.writes(api)], ["APPROVE"])

    def test_cli_publishes_formal_disposition_only_when_requested(self):
        for publish_flag in ([], ["--publish"]):
            with self.subTest(publish=bool(publish_flag)), TemporaryDirectory() as folder:
                api = self.fixture()
                config = Path(folder) / "config.json"
                config.write_text(json.dumps(formal_config()))
                output = StringIO()
                def review(*args, **kwargs):
                    return run_review(*args, **kwargs, provider=review_provider(1))
                with patch.dict("os.environ", {"CODEMURPHY_GITHUB_TOKEN": "fixture"}), \
                     patch("codemurphy.cli.GitHub", return_value=api), \
                     patch("codemurphy.cli.run_review", side_effect=review), redirect_stdout(output):
                    code = main(["github", "--repo", REPO, "--pr", "5", "--config", str(config),
                                 "--review-mode", "approve-reject", "--format", "json", "--fail-on", "high",
                                 *publish_flag])
                self.assertEqual(code, 1)
                report = json.loads(output.getvalue())
                if publish_flag:
                    self.assertIn("REQUEST_CHANGES", report["publication"])
                    self.assertEqual([review["event"] for review in self.writes(api)], ["REQUEST_CHANGES"])
                else:
                    self.assertEqual(report["review_mode"], "approve-reject")
                    self.assertNotIn("publication", report)
                    self.assertEqual(self.writes(api), [])
                    self.assertTrue(all(path in (PREFIX, compare_path(BASE)) for path, _ in api.calls))

    def test_cli_reports_a_formal_hold_and_a_skipped_pr_without_writing(self):
        for extra_flags, status, field, reason in (
            ([], 2, "publication", "static"),
            (["--expected-head", "c" * 40], 0, "skipped", "superseded"),
        ):
            with self.subTest(extra_flags=extra_flags):
                api = self.fixture()
                output = StringIO()
                with patch.dict("os.environ", {"CODEMURPHY_GITHUB_TOKEN": "fixture"}), \
                     patch("codemurphy.cli.GitHub", return_value=api), redirect_stdout(output):
                    code = main(["github", "--repo", REPO, "--pr", "5", "--static-only", "--publish",
                                 "--review-mode", "approve-reject", "--format", "json", *extra_flags])
                self.assertEqual(code, status)
                self.assertIn(reason, json.loads(output.getvalue())[field])
                self.assertEqual(self.writes(api), [])

    def test_cli_rejects_conflicting_formal_publication_options(self):
        for flags in (["--only-findings"], ["--publish-scope", "combined"]):
            with self.subTest(flags=flags):
                error = StringIO()
                with patch("codemurphy.cli.GitHub") as api, redirect_stderr(error):
                    code = main(["github", "--repo", REPO, "--pr", "5", "--static-only", "--publish",
                                 "--review-mode", "approve-reject", *flags])
                self.assertEqual(code, 2)
                self.assertIn(flags[0], error.getvalue())
                api.assert_not_called()
