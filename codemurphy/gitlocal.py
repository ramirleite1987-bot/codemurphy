"""Read Git data without executing tools supplied by the reviewed project."""
import os
from pathlib import Path
import subprocess

from .config import SHA


class GitError(RuntimeError):
    pass


def git(root, *args, limit=16_000_000):
    cmd = ["git", "--no-replace-objects", "-C", str(root), "-c", "core.quotePath=true", "-c", "core.fsmonitor=false", *args]
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          env={**os.environ, "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_LAZY_FETCH": "1"}) as p:
        try:
            output = p.stdout.read(limit + 1)
            if len(output) > limit:
                p.kill()
                raise GitError("Git output exceeds the limit; review a smaller change")
            if p.wait(timeout=30):
                raise GitError(f"git {args[0]} failed; check the repository and refs")
            return output
        finally:
            if p.poll() is None:
                p.kill()


def root_of(root):
    return Path(os.fsdecode(git(root, "rev-parse", "--show-toplevel").rstrip(b"\n")))


def commit_at(root, ref):
    return git(root, "rev-parse", "--verify", "--end-of-options", ref + "^{commit}", limit=100).decode().strip()


def snapshot(root, base, head, staged):
    head_sha = commit_at(root, "HEAD" if staged else head)
    base_sha = head_sha if staged else commit_at(root, base)
    if not staged:
        base_sha = git(root, "merge-base", base_sha, head_sha, limit=100).decode().strip()
    args = ["--cached", base_sha] if staged else [base_sha, head_sha]
    patch = git(root, "diff", "--no-ext-diff", "--no-textconv", "--find-renames", "-l500", "--no-color",
                "--src-prefix=a/", "--dst-prefix=b/", "--unified=3", *args, "--")
    return base_sha, None if staged else head_sha, patch.decode("utf-8", "replace")


def blob_at(root, sha, path, limit=32000):
    if not SHA.fullmatch(sha):
        raise GitError("Context requires a commit SHA")
    spec = f"{sha}:{path}"
    if git(root, "cat-file", "-t", spec, limit=100).strip() != b"blob":
        raise GitError("Context path is not a blob")
    return git(root, "cat-file", "blob", spec, limit=limit)
