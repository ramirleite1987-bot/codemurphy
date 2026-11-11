"""Read PRs from GitHub and publish only anchored comments against a stable snapshot."""
import base64
from dataclasses import dataclass

from .config import SHA, repo_name, safe_path, sensitive_path
from .context import MAX_CONTEXT_BYTES, reference
from .diff import parse_patch
from .http import RequestError, json_request
from .render import comment, markdown
from .review import publication_findings


class GitHubError(RuntimeError):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class Skipped(GitHubError):
    pass


class GitHub:
    def __init__(self, token=None, transport=json_request):
        self.transport = transport
        self.headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                        "User-Agent": "CodeMurphy"}
        if token:
            self.headers["Authorization"] = f"Bearer {token}"
        self._trees = {}
        self._commits = {}

    def request(self, path, body=None):
        try:
            return self.transport("https://api.github.com" + path, headers={
                **self.headers, **({"Content-Type": "application/json"} if body is not None else {})},
                method="POST" if body is not None else "GET", body=body, limit=8_000_000)
        except RequestError as exc:
            raise GitHubError(f"GitHub {exc}", exc.status) from None

    def blob(self, repo, commit, path, limit=MAX_CONTEXT_BYTES):
        if not repo_name(repo) or not SHA.fullmatch(commit) or not safe_path(path) or sensitive_path(path):
            raise GitHubError("GitHub context requires a safe path and a pinned commit")
        root = f"/repos/{repo}/git"
        key = (repo, commit)
        try:
            if key not in self._commits:
                doc = self.request(f"{root}/commits/{commit}")
                tree = doc["tree"]["sha"]
                if doc["sha"] != commit or not SHA.fullmatch(tree):
                    raise GitHubError("GitHub did not resolve the exact context commit")
                self._commits[key] = tree
            current = self._commits[key]
            segments = path.split("/")
            for i, name in enumerate(segments):
                tree_key = (repo, current)
                if tree_key not in self._trees:
                    tree = self.request(f"{root}/trees/{current}")
                    if tree.get("truncated"):
                        raise GitHubError("GitHub tree is truncated; cannot verify the context path")
                    self._trees[tree_key] = {e["path"]: e for e in tree["tree"]}
                entry = self._trees[tree_key].get(name)
                if not entry:
                    raise GitHubError("Context path does not exist at the pinned commit", 404)
                current = entry["sha"]
                if not SHA.fullmatch(current):
                    raise GitHubError("Invalid GitHub tree object")
                if i + 1 < len(segments):
                    if entry["type"] != "tree":
                        raise GitHubError("Context path does not resolve through a directory")
                elif entry["type"] != "blob" or entry["mode"] not in ("100644", "100755"):
                    raise GitHubError("Context path must be a regular file")
            if entry.get("size", 0) > limit:
                raise GitHubError("Context file exceeds its size limit")
            data = self.request(f"{root}/blobs/{current}")
            if data["encoding"] != "base64" or data.get("sha") != current or data["size"] > limit:
                raise GitHubError("Invalid or oversized context blob")
            raw = base64.b64decode("".join(data["content"].split()), validate=True)
            if len(raw) != data["size"]:
                raise GitHubError("GitHub context blob is incomplete")
            return raw
        except (TypeError, AttributeError, KeyError, ValueError):
            raise GitHubError("Invalid GitHub object response") from None

    def linked_refs(self, linked):
        meta = self.request(f"/repos/{linked.repo}")
        public = isinstance(meta, dict) and meta.get("private") is False and meta.get("visibility") == "public"
        return [reference(f"{linked.id}:{i}", linked.repo, linked.commit, path,
                          self.blob(linked.repo, linked.commit, path), private=not public)
                for i, path in enumerate(linked.files, 1)]


@dataclass(frozen=True)
class Pull:
    repo: str
    number: int
    base: str
    head: str
    files: tuple
    text: str

    @property
    def endpoint(self):
        return f"/repos/{self.repo}/pulls/{self.number}"

    @property
    def marker(self):
        return f"<!-- codemurphy:{self.base}:{self.head} -->"


def _identity(metadata):
    try:
        base, head = metadata["base"]["sha"], metadata["head"]["sha"]
        if not SHA.fullmatch(base) or not SHA.fullmatch(head):
            raise ValueError
        return base, head
    except (KeyError, TypeError, ValueError):
        raise GitHubError("Invalid GitHub PR commit metadata") from None


def snapshot(api, repo, number, *, expected_head=None, expected_base=None, trusted_base=None, allow_forks=False):
    if not repo_name(repo) or type(number) is not int or not 1 <= number <= 10**9:
        raise GitHubError("GitHub review requires owner/repo and a positive PR number")
    endpoint = f"/repos/{repo}/pulls/{number}"
    metadata = api.request(endpoint)
    base, head = _identity(metadata)
    try:
        if metadata["state"] != "open":
            raise Skipped("PR is closed")
        if expected_head is not None and head != expected_head:
            raise Skipped("Event was superseded by a newer PR head")
        if expected_base is not None and base != expected_base:
            raise Skipped("The selected PR base commit changed")
        if metadata["base"]["repo"]["full_name"].casefold() != repo.casefold():
            raise GitHubError("PR base repository does not match the requested repository")
        if trusted_base is not None and metadata["base"]["ref"] != trusted_base:
            raise Skipped("PR base branch is outside the trusted configuration")
        head_repo = (metadata["head"]["repo"] or {}).get("full_name", "")
        if not allow_forks and head_repo.casefold() != repo.casefold():
            raise Skipped("Fork PR reviews are disabled")
        count = metadata["changed_files"]
        if type(count) is not int or not 0 <= count <= 500:
            raise GitHubError("PR exceeds the GitHub review limit of 500 changed files")
        patches, names = [], set()
        for i in range((count + 99) // 100):
            page = api.request(f"{endpoint}/files?per_page=100&page={i+1}")
            if not isinstance(page, list):
                raise ValueError
            for entry in page:
                path, additions, deletions = entry["filename"], entry["additions"], entry["deletions"]
                if (not isinstance(path, str) or path in names or
                        any(type(v) is not int or not 0 <= v <= 10**8 for v in (additions, deletions))):
                    raise ValueError
                patch = entry.get("patch")
                if patch is not None and not isinstance(patch, str):
                    raise ValueError
                previous = entry.get("previous_filename")
                if previous is not None and not isinstance(previous, str):
                    raise ValueError
                if entry.get("status") in ("renamed", "copied") and not previous:
                    raise GitHubError("GitHub did not provide the source path for a renamed file")
                names.add(path)
                patches.append(parse_patch(path, patch, additions + deletions, previous))
        if len(patches) != count:
            raise GitHubError("GitHub returned an incomplete or changed PR file list")
        latest = api.request(endpoint)
        if _identity(latest) != (base, head) or latest.get("state") != "open":
            raise GitHubError("PR changed while reading the diff; rerun on the new head")
        title = metadata.get("title") or ""
        body = metadata.get("body") or ""
        return Pull(repo, number, base, head, tuple(patches), (title + "\n\n" + body)[:12000])
    except (TypeError, ValueError, KeyError, AttributeError):
        raise GitHubError("Invalid GitHub PR metadata or file response") from None


def github_refs(api, context_api, pull, config):
    refs, warnings = [], []
    for i, path in enumerate(config.files, 1):
        try:
            raw = api.blob(pull.repo, pull.base, path)
        except GitHubError as exc:
            if exc.status != 404:
                raise
            warnings.append(f"Project context missing at the base commit: {path}")
            continue
        refs.append(reference(f"project:{i}", pull.repo, pull.base, path, raw))
    for linked in config.linked:
        if linked.local:
            raise GitHubError("Local linked repositories are unavailable in GitHub reviews")
        refs.extend(context_api.linked_refs(linked))
    return refs, warnings


def _verify(api, pull):
    metadata = api.request(pull.endpoint)
    if _identity(metadata) != (pull.base, pull.head) or metadata.get("state") != "open":
        raise GitHubError("PR changed before publication; no review was posted")


def review_publisher(api, publisher=None):
    if publisher is None:
        publisher = api.request("/user").get("login")
    if not isinstance(publisher, str) or not publisher:
        raise GitHubError("Cannot identify the GitHub review publisher")
    return publisher


def already_reviewed(api, pull, publisher):
    for page in range(1, 11):
        reviews = api.request(f"{pull.endpoint}/reviews?per_page=100&page={page}")
        if not isinstance(reviews, list):
            raise GitHubError("Invalid GitHub review list")
        if any((r.get("user") or {}).get("login", "").casefold() == publisher.casefold() and
               pull.marker in (r.get("body") or "").splitlines() for r in reviews):
            return True
        if len(reviews) < 100:
            return False
    raise GitHubError("Too many existing reviews to deduplicate safely")


def publish(api, pull, report, config, *, publisher=None, scope="primary"):
    if report["private_context"]:
        raise GitHubError("Private linked context cannot be published to GitHub")
    if (report.get("verification") or {}).get("failed_requests"):
        raise GitHubError("An incomplete second review cannot be published")
    _verify(api, pull)
    publisher = review_publisher(api, publisher)
    if already_reviewed(api, pull, publisher):
        return "already-posted"
    findings = publication_findings(report, scope)
    known = {(x.path, x.side, x.number) for file in pull.files for x in file.lines if x.changed}
    comments = [{"path": i["path"], "line": i["line"], "side": i["side"], "body": comment(i, language=config.language)}
                for i in findings[:config.max_comments] if (i["path"], i["side"], i["line"]) in known]
    body = markdown(report, summary=True, issues=findings)
    if len(findings) > len(comments):
        body += f"\nPosted {len(comments)} of {len(findings)} findings inline (comment cap or unavailable anchor).\n"
    _verify(api, pull)
    api.request(f"{pull.endpoint}/reviews", {"event": "COMMENT", "commit_id": pull.head,
                                            "body": body + "\n" + pull.marker, "comments": comments})
    return "posted"
