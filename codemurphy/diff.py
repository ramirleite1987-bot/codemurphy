"""Turn unified patches into bounded, verifiable review input."""
from dataclasses import dataclass
import json
import re

from .config import Config
from .redact import Scrubber, redact

_HUNK = re.compile(r"^@@ -(\d{1,9})(?:,(\d{1,9}))? \+(\d{1,9})(?:,(\d{1,9}))? @@")
_ESC = re.compile(rb'\\([0-7]{3}|.)')
_ESCAPE = {b"n": b"\n", b"t": b"\t", b"r": b"\r", b'"': b'"', b"\\": b"\\"}


@dataclass(frozen=True)
class Line:
    path: str
    side: str
    number: int
    kind: str
    text: str
    secret: bool = False

    @property
    def changed(self):
        return self.kind != " "

    def row(self):
        return [self.path, self.side, self.number, self.kind, self.text]


@dataclass(frozen=True)
class Patch:
    path: str
    lines: tuple[Line, ...]
    expected: int
    incomplete: bool
    missing: bool
    previous_path: str | None = None


def parse_patch(path, patch, expected=None, previous_path=None):
    lines = []
    left, right = Scrubber(), Scrubber()
    old = new = remaining_old = remaining_new = 0
    active = incomplete = False
    for raw in (patch or "").split("\n"):
        h = _HUNK.match(raw)
        if h:
            incomplete |= bool(remaining_old or remaining_new)
            old, new = int(h[1]), int(h[3])
            remaining_old = int(h[2]) if h[2] is not None else 1
            remaining_new = int(h[4]) if h[4] is not None else 1
            active = True
            continue
        kind = raw[:1]
        if not active or not kind or kind == "\\":
            continue
        if kind not in ("+", "-", " "):
            incomplete = True
            active = False
            continue
        take_old, take_new = kind != "+", kind != "-"
        if take_old and remaining_old <= 0 or take_new and remaining_new <= 0:
            incomplete = True
            active = False
            continue
        value = raw[1:].rstrip("\r")
        a = left.line(value) if take_old else (value, False)
        b = right.line(value) if take_new else (value, False)
        clean = a[0] if a[0] != value else b[0]
        side = "RIGHT" if take_new else "LEFT"
        lines.append(Line(path, side, new if take_new else old, kind, clean, a[1] or b[1]))
        if take_old:
            old += 1
            remaining_old -= 1
        if take_new:
            new += 1
            remaining_new -= 1
    count = sum(line.changed for line in lines)
    incomplete |= bool(remaining_old or remaining_new) or expected is not None and expected != count
    return Patch(path, tuple(lines), max(count, expected or 0), incomplete, not lines, previous_path)


def _unquote(path):
    if path.startswith('"') and path.endswith('"'):
        def sub(match):
            code = match[1]
            return bytes([int(code, 8)]) if len(code) == 3 and int(code, 8) < 256 else _ESCAPE.get(code, code)
        return _ESC.sub(sub, path[1:-1].encode()).decode("utf-8", "surrogateescape")
    return path


def from_unified(diff):
    """Parse Git-generated patches; files with no text hunks remain visible as skipped."""
    files, header, hunk = [], [], []
    def finish():
        if not header:
            return
        paths = {}
        old_name = new_name = None
        for raw in header:
            if raw.startswith(("--- ", "+++ ")):
                paths[raw[:3]] = _unquote(raw[4:].rstrip("\t"))
            elif raw.startswith(("rename from ", "copy from ")):
                old_name = _unquote(raw.split(" ", 2)[2])
            elif raw.startswith(("rename to ", "copy to ")):
                new_name = _unquote(raw.split(" ", 2)[2])
        path = paths.get("+++", "")
        if path in ("", "/dev/null"):
            path = paths.get("---", "")
        if not path:
            # Binary and mode-only patches can have only a diff header.
            pair = header[0][len("diff --git "):]
            index = next((i for i, c in enumerate(pair) if c == " " and
                          _unquote(pair[:i]).removeprefix("a/") ==
                          _unquote(pair[i+1:]).removeprefix("b/")), -1)
            if index >= 0:
                path = _unquote(pair[index+1:])
        destination = new_name or (path[2:] if path.startswith(("a/", "b/")) else path)
        old = old_name or paths.get("---", "").removeprefix("a/")
        if destination:
            previous = old if old not in ("", "/dev/null", destination) else None
            files.append(parse_patch(destination, "\n".join(hunk), previous_path=previous))

    for line in diff.split("\n"):
        if line.startswith("diff --git "):
            finish()
            header, hunk = [line], []
        elif header:
            (hunk if hunk or line.startswith("@@ ") else header).append(line)
    finish()
    return files


def make_batches(files, config: Config):
    batches, batch = [], []
    spent = size = reviewed = total = excluded = missing = truncated = 0
    def flush():
        nonlocal size, batch
        if any(x.changed for x in batch):
            batches.append(tuple(batch))
        batch, size = [], 0

    for file in files:
        names = [file.path, file.previous_path] if file.previous_path is not None else [file.path]
        if any(config.excluded(path) or redact(path) != path for path in names):
            excluded += 1
            continue
        total += file.expected
        missing += file.missing
        truncated += file.incomplete
        for line in file.lines:
            cost = len(json.dumps(line.row(), ensure_ascii=False, separators=(",", ":"))) + 1
            if config.anchored_evidence:
                cost += 10  # Reserve room for the per-row anchor ID or null.
            if cost > config.chunk_chars:
                continue
            if size + cost > config.chunk_chars:
                flush()
            if len(batches) >= config.max_batches or spent + cost > config.max_diff_chars:
                continue
            # Don't let unchanged context alone exhaust the whole diff budget.
            if not line.changed and config.max_diff_chars - spent < config.chunk_chars // 3:
                continue
            batch.append(line)
            spent += cost
            size += cost
            reviewed += line.changed
    flush()
    return batches, {"files": len(files), "excluded_files": excluded, "unreviewable_files": missing,
                     "incomplete_patches": truncated, "eligible_lines": total, "reviewed_lines": reviewed,
                     "omitted_lines": max(0, total - reviewed), "batches": len(batches),
                     "partial": reviewed != total or bool(truncated)}
