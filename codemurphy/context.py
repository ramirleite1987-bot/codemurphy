"""Explicit, pinned context with deterministic relevance and provenance."""
from dataclasses import dataclass, replace
import json
import re
from pathlib import Path

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

    def payload(self):
        return {"id": self.id, "repo": self.repo, "commit": self.commit, "path": self.path,
                "start_line": self.start_line, "text": self.text}


def reference(identifier, repo, commit, path, blob, private=False):
    if b"\0" in blob or len(blob) > MAX_CONTEXT_BYTES:
        raise GitError("Context must be bounded UTF-8 text")
    try:
        value = blob.decode("utf-8")
    except UnicodeError:
        raise GitError("Context must be UTF-8 text") from None
    return Reference(identifier, redact(repo), commit, redact(path), redact(value), private)


def local_refs(config, root, base, remote=None):
    refs, warnings = [], []
    for i, path in enumerate(config.files, 1):
        try:
            refs.append(reference(f"project:{i}", "project", base, path, blob_at(root, base, path)))
        except GitError:
            warnings.append(f"Project context unavailable: {redact(path)}")
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


def select_refs(refs, batch, budget):
    terms = _terms(" ".join(f"{line.path} {line.text}" for line in batch if line.changed))
    candidates = []
    for ref in refs:
        # Preserve source line numbers while allowing a focused excerpt from long contracts.
        lines = ref.text.split("\n")
        for start in range(0, len(lines), 32):
            snippet = "\n".join(lines[start:start+40])
            score = 3 * len(terms & _terms(ref.path)) + len(terms & _terms(snippet))
            candidates.append((score, ref.id, start, replace(ref, start_line=ref.start_line + start, text=snippet)))
    picked, used = [], set()
    for _, _, _, ref in sorted(candidates, key=lambda x: (-x[0], x[1], x[2])):
        if ref.id in used:
            continue
        cost = len(json.dumps(ref.payload(), ensure_ascii=False, separators=(",", ":"))) + 1
        if cost > budget:
            continue
        picked.append(ref)
        used.add(ref.id)
        budget -= cost
    return tuple(picked)
