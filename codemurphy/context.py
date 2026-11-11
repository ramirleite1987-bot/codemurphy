"""Explicit, pinned context with deterministic relevance and provenance."""
from dataclasses import dataclass, replace
import json
import re
from pathlib import Path

from .config import match_path
from .gitlocal import GitError, blob_at, commit_at
from .redact import redact

MAX_CONTEXT_BYTES = 32000


@dataclass(frozen=True)
class Reference:
    id: str
    repo: str
    commit: str
    path: str
    text: str
    private: bool = False
    start_line: int = 1
    applies_to: tuple[str, ...] = ()

    def payload(self, *, numbered=False):
        origin = {"id": self.id, "repo": self.repo, "commit": self.commit, "path": self.path}
        if numbered:
            return {**origin, "lines": list(enumerate(self.text.split("\n"), self.start_line))}
        return {**origin, "start_line": self.start_line, "text": self.text}


def reference(identifier, repo, commit, path, blob, private=False):
    if b"\0" in blob or len(blob) > MAX_CONTEXT_BYTES:
        raise GitError("Context must be bounded UTF-8 text")
    try:
        value = blob.decode("utf-8")
    except UnicodeError:
        raise GitError("Context must be UTF-8 text") from None
    return Reference(identifier, redact(repo), commit, redact(path), redact(value), private)


def project_excerpts(config, repo, base, read_blob):
    refs, warnings, blobs = [], [], {}
    for i, excerpt in enumerate(config.excerpts, 1):
        path = excerpt.path
        if path not in blobs:
            blobs[path] = read_blob(path)
        raw = blobs[path]
        if raw is None:
            warnings.append(f"Project excerpt file unavailable at the base commit: {redact(path)} (excerpt {i})")
            continue
        ref = reference(f"project:excerpt:{i:02d}", repo, base, path, raw)
        lines = ref.text.split("\n")
        hits = [j for j, line in enumerate(lines) if excerpt.anchor in line]
        if len(hits) != 1:
            warnings.append(f"Project excerpt anchor missing or ambiguous: {ref.path} (excerpt {i})")
            continue
        start = hits[0]
        refs.append(replace(ref, start_line=start + 1, text="\n".join(lines[start:start + excerpt.lines]),
                            applies_to=excerpt.applies_to))
    return refs, warnings


def local_refs(config, root, base, remote=None):
    refs, warnings = [], []
    for i, path in enumerate(config.files, 1):
        try:
            refs.append(reference(f"project:{i}", "project", base, path, blob_at(root, base, path)))
        except GitError:
            warnings.append(f"Project context unavailable: {redact(path)}")
    def read_blob(path):
        try:
            return blob_at(root, base, path)
        except GitError:
            return None
    excerpts, excerpt_warnings = project_excerpts(config, "project", base, read_blob)
    refs.extend(excerpts)
    warnings.extend(excerpt_warnings)
    for item in config.linked:
        if item.repo:
            if remote is None:
                raise GitError("Linked GitHub repositories require a GitHub context reader")
            refs.extend(remote.linked_refs(item))
            continue
        linked = (Path(root) / item.local).resolve()
        if commit_at(linked, item.commit) != item.commit:
            raise GitError(f"Linked context {item.id} is not a commit")
        for i, path in enumerate(item.files, 1):
            refs.append(reference(f"{item.id}:{i}", item.id, item.commit, path,
                                  blob_at(linked, item.commit, path), private=True))
    return refs, warnings


def _terms(text):
    words = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    return set(re.findall(r"[a-z0-9]{3,}", words.lower())) - {
        "return", "const", "function", "true", "false", "def", "null", "none", "var", "let",
        "self", "this", "the", "for", "and", "from", "with", "not", "class", "import"}


def select_refs(refs, batch, budget, *, numbered=False):
    terms = _terms(" ".join(f"{line.path} {line.text}" for line in batch if line.changed))
    candidates = []
    paths = {line.path for line in batch}
    for ref in refs:
        if ref.applies_to:
            if any(match_path(path, pattern) for path in paths for pattern in ref.applies_to):
                candidates.append((1, 0, ref.id, 0, ref))
            continue
        # Preserve source line numbers while allowing a focused excerpt from long contracts.
        lines = ref.text.split("\n")
        for start in range(0, len(lines), 32):
            snippet = "\n".join(lines[start:start+40])
            score = 3 * len(terms & _terms(ref.path)) + len(terms & _terms(snippet))
            candidates.append((0, score, ref.id, start, replace(ref, start_line=ref.start_line + start, text=snippet)))
    picked, used = [], set()
    for _, _, _, _, ref in sorted(candidates, key=lambda x: (-x[0], -x[1], x[2], x[3])):
        if ref.id in used:
            continue
        cost = len(json.dumps(ref.payload(numbered=numbered), ensure_ascii=False, separators=(",", ":"))) + 1
        if cost > budget:
            continue
        picked.append(ref)
        used.add(ref.id)
        budget -= cost
    return tuple(picked)
