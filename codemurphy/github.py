"""Read PRs from GitHub and publish reviews against a stable snapshot."""
import base64
from dataclasses import dataclass

from .config import SHA, repo_name, safe_path, sensitive_path
from .context import MAX_CONTEXT_BYTES, project_excerpts, reference
from .diff import parse_patch
from .http import RequestError, json_request
from .render import comment, markdown
from .review import publication_findings

REVIEW_MODES = ("comment", "approve-reject")
_REVIEW_STATES = {"COMMENT": "COMMENTED", "APPROVE": "APPROVED", "REQUEST_CHANGES": "CHANGES_REQUESTED"}


class GitHubError(RuntimeError):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class Skipped(GitHubError):
    pass


class PublicationWithheld(GitHubError):
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
class _PullTarget:
    base_ref: str
    base_repo: str
    head_repo: str | None
    draft: bool | None
    base_repo_id: int | None
    head_repo_id: int | None


@dataclass(frozen=True)
class Pull:
    repo: str
    number: int
    base: str
    head: str
    files: tuple
    text: str
    target: _PullTarget | None = None
    diff_base: str | None = None

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


def _target(metadata):
    try:
        base_ref = metadata["base"]["ref"]
        base_repo = metadata["base"]["repo"]
        head_repo = metadata["head"]["repo"]
        base_name = base_repo["full_name"]
        head_name = head_repo["full_name"] if head_repo is not None else None
        draft = metadata.get("draft")
        if (not isinstance(base_ref, str) or not base_ref or not repo_name(base_name) or
                (head_repo is not None and not repo_name(head_name)) or
                (draft is not None and type(draft) is not bool)):
            raise ValueError
        return _PullTarget(base_ref, base_name.casefold(), head_name.casefold() if head_name else None,
                           draft, base_repo.get("id"), head_repo.get("id") if head_repo is not None else None)
    except (KeyError, TypeError, ValueError, AttributeError):
        raise GitHubError("Invalid GitHub PR target metadata") from None


def _pinned_compare(api, repo, base, head):
    comparison = api.request(f"/repos/{repo}/compare/{base}...{head}?per_page=1")
    if comparison["base_commit"]["sha"] != base:
        raise GitHubError("GitHub compare did not return the pinned base commit")
    merge_base = comparison["merge_base_commit"]["sha"]
    if not isinstance(merge_base, str) or not SHA.fullmatch(merge_base):
        raise GitHubError("GitHub compare did not return a valid merge base")
    if comparison.get("truncated"):
        raise GitHubError("GitHub compare returned a truncated diff")
    return merge_base, comparison


def _pinned_files(api, repo, base, head):
    merge_base, comparison = _pinned_compare(api, repo, base, head)
    # The PR shows changes from the merge base. Pin both endpoints of
    # that diff explicitly when the base branch has advanced or diverged.
    if merge_base != base:
        verified_base, comparison = _pinned_compare(api, repo, merge_base, head)
        if verified_base != merge_base:
            raise GitHubError("GitHub compare did not verify the PR merge base")
    return merge_base, comparison["files"]


def snapshot(api, repo, number, *, expected_head=None, expected_base=None, trusted_base=None, allow_forks=False,
             pinned_diff=False):
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
        target = _target(metadata)
        if target.base_repo != repo.casefold():
            raise GitHubError("PR base repository does not match the requested repository")
        if trusted_base is not None and target.base_ref != trusted_base:
            raise Skipped("PR base branch is outside the trusted configuration")
        if not allow_forks and target.head_repo != repo.casefold():
            raise Skipped("Fork PR reviews are disabled")
        count = metadata["changed_files"]
        limit = 300 if pinned_diff else 500
        if type(count) is not int or not 0 <= count <= limit:
            raise GitHubError(f"PR exceeds the GitHub review limit of {limit} changed files")
        diff_base = None
        if pinned_diff:
            diff_base, files = _pinned_files(api, repo, base, head)
            pages = (files,)
        else:
            pages = (api.request(f"{endpoint}/files?per_page=100&page={i+1}") for i in range((count + 99) // 100))
        patches, names = [], set()
        for page in pages:
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
        if (_identity(latest) != (base, head) or latest.get("state") != "open" or
                _target(latest) != target or latest.get("changed_files") != count):
            raise GitHubError("PR changed while reading the diff; rerun on the current PR")
        title = metadata.get("title") or ""
        body = metadata.get("body") or ""
        return Pull(repo, number, base, head, tuple(patches), (title + "\n\n" + body)[:12000],
                    target=target, diff_base=diff_base)
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
    def read_blob(path):
        try:
            return api.blob(pull.repo, pull.base, path)
        except GitHubError as exc:
            if exc.status != 404:
                raise
            return None
    excerpts, excerpt_warnings = project_excerpts(config, pull.repo, pull.base, read_blob)
    refs.extend(excerpts)
    warnings.extend(excerpt_warnings)
    for linked in config.linked:
        if linked.local:
            raise GitHubError("Local linked repositories are unavailable in GitHub reviews")
        refs.extend(context_api.linked_refs(linked))
    return refs, warnings


def _verify(api, pull):
    metadata = api.request(pull.endpoint)
    if (_identity(metadata) != (pull.base, pull.head) or metadata.get("state") != "open" or
            (pull.target is not None and _target(metadata) != pull.target) or
            (pull.diff_base is not None and metadata.get("changed_files") != len(pull.files))):
        raise GitHubError("PR changed before publication; no review was posted")
    return metadata


def review_publisher(api, publisher=None):
    if publisher is None:
        publisher = api.request("/user").get("login")
    if not isinstance(publisher, str) or not publisher:
        raise GitHubError("Cannot identify the GitHub review publisher")
    return publisher


def already_reviewed(api, pull, publisher, *, event="COMMENT"):
    state = _REVIEW_STATES[event]
    matches_latest = False
    for page in range(1, 11):
        reviews = api.request(f"{pull.endpoint}/reviews?per_page=100&page={page}")
        if not isinstance(reviews, list):
            raise GitHubError("Invalid GitHub review list")
        for review in reviews:
            if (review.get("user") or {}).get("login", "").casefold() != publisher.casefold():
                continue
            submitted = review.get("state")
            exact = pull.marker in (review.get("body") or "").splitlines()
            if event == "COMMENT":
                if submitted in (None, state) and exact:
                    return True
            elif submitted in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED"):
                # GitHub lists reviews in chronological order. A later verdict or
                # dismissal means an older match cannot stand in for this review.
                matches_latest = submitted == state and exact and review.get("commit_id") == pull.head
        if len(reviews) < 100:
            return matches_latest
    raise GitHubError("Too many existing reviews to deduplicate safely")


def _require_formal_review(pull, report, config, scope):
    if not pull.diff_base or pull.target is None:
        raise PublicationWithheld("A formal review requires a pinned GitHub diff")
    if pull.target.draft is not False:
        raise PublicationWithheld("The PR is a draft or its draft status could not be verified")
    if pull.target.head_repo is None:
        raise PublicationWithheld("Could not verify the PR head repository")
    if scope != "primary":
        raise PublicationWithheld("A formal review requires primary publication scope")
    if report.get("skipped"):
        raise PublicationWithheld("The review was skipped")
    if report.get("mode") == "static":
        raise PublicationWithheld("A static-only review cannot submit a formal verdict")
    verification = report.get("verification") or {}
    if not config.verify_with or verification.get("reviewer") != config.verify_with:
        raise PublicationWithheld("A formal review requires a second reviewer (review.verify_with)")
    coverage = report["coverage"]
    if coverage["partial"] or coverage["excluded_files"] or coverage["unreviewable_files"]:
        raise PublicationWithheld("Diff coverage is incomplete, excluded, or unavailable")
    primary = report["models"].get(config.primary)
    if not primary or not primary["requests"]:
        raise PublicationWithheld("No primary model batches were reviewed")
    if primary["requests"] != coverage["batches"]:
        raise PublicationWithheld("The primary reviewer did not cover every diff batch")
    if any(stats["failed_requests"] for stats in report["models"].values()):
        raise PublicationWithheld("A model review request failed")
    if primary["rejected"]:
        raise PublicationWithheld("Some primary findings were rejected because their evidence could not be validated")
    if verification["failed_requests"]:
        raise PublicationWithheld("A verification request failed")
    if verification["withheld"]:
        raise PublicationWithheld("Some findings exceeded the verification cap")
    if verification["checked"] < len(report["candidates"][config.primary]):
        raise PublicationWithheld("Some primary findings were not verified")


def publish(api, pull, report, config, *, publisher=None, scope="primary", review_mode="comment"):
    if review_mode not in REVIEW_MODES:
        raise GitHubError("Invalid GitHub review mode")
    formal = review_mode == "approve-reject"
    if report.get("private_context"):
        raise GitHubError("Private linked context cannot be published to GitHub")
    if formal:
        _require_formal_review(pull, report, config, scope)
    elif (report.get("verification") or {}).get("failed_requests"):
        raise GitHubError("An incomplete second review cannot be published")
    findings = publication_findings(report, scope)
    event = ("REQUEST_CHANGES" if findings else "APPROVE") if formal else "COMMENT"
    disposition = f" ({event})" if formal else ""
    _verify(api, pull)
    publisher = review_publisher(api, publisher)
    if already_reviewed(api, pull, publisher, event=event):
        return "already-posted" + disposition
    known = {(x.path, x.side, x.number) for file in pull.files for x in file.lines if x.changed}
    comments = [{"path": i["path"], "line": i["line"], "side": i["side"], "body": comment(i, language=config.language)}
                for i in findings[:config.max_comments] if (i["path"], i["side"], i["line"]) in known]
    if event == "REQUEST_CHANGES" and not comments:
        raise PublicationWithheld("Requesting changes requires a confirmed finding that can be posted inline")
    body = markdown(report, summary=True, issues=findings)
    if len(findings) > len(comments):
        body += f"\nPosted {len(comments)} of {len(findings)} findings inline (comment cap or unavailable anchor).\n"
    latest = _verify(api, pull)
    if event == "APPROVE":
        author = (latest.get("user") or {}).get("login")
        if not isinstance(author, str) or not author:
            raise PublicationWithheld("Could not verify the PR author's identity")
        if author.casefold() == publisher.casefold():
            raise PublicationWithheld("GitHub does not allow approving your own pull request; use a separate reviewer")
    try:
        api.request(f"{pull.endpoint}/reviews", {"event": event, "commit_id": pull.head,
                                                "body": body + "\n" + pull.marker, "comments": comments})
    except GitHubError as exc:
        if formal and exc.status in (403, 422):
            hint = "Check the review token and repository permissions."
            if event == "APPROVE":
                hint += " GitHub also requires an approver other than the PR author."
            raise GitHubError(f"GitHub declined {event} (HTTP {exc.status}). {hint}", exc.status) from None
        raise
    return "posted" + disposition
