"""Fetch and normalize Socket metadata without passing PR data to the client."""
from importlib.resources import files
import json
from pathlib import Path
import re
import shutil
import subprocess
from tempfile import TemporaryDirectory
from urllib.parse import quote

from .dependencies import MAX_RELEASES, SOCKET_CVE_TYPES, npm_name, release_version

_ALERT_TYPE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}")
_ADVISORY = re.compile(r"\b(?:CVE-[0-9]{4}-[0-9]{4,}|GHSA-(?:[a-z0-9]{4}-){2}[a-z0-9]{4}|"
                       r"MAL-[0-9]{4}-[0-9]+|OSV-[0-9]{4}-[0-9]+)\b", re.IGNORECASE)


def _error(reason):
    return {"status": "error", "reason": reason, "covered": 0, "alerts": []}


def _canonical(identifier):
    return "GHSA-" + identifier[5:].lower() if identifier.upper().startswith("GHSA-") else identifier.upper()


def normalize(rows, eligible):
    if not isinstance(rows, list) or len(rows) > len(eligible):
        return _error("unexpected_response")
    seen, covered, result = set(), 0, []
    for row in rows:
        if not isinstance(row, dict) or not npm_name(row.get("package")) or not release_version(row.get("version")):
            return _error("unexpected_response")
        package, version = pair = (row["package"], row["version"])
        if pair not in eligible or pair in seen:
            return _error("unexpected_response")
        seen.add(pair)
        alerts = row.get("alerts")
        if not isinstance(alerts, list) or len(alerts) > 512:
            continue
        normalized = {}
        for alert in alerts:
            kind = alert.get("type") if isinstance(alert, dict) else None
            if not isinstance(kind, str) or not _ALERT_TYPE.fullmatch(kind) or kind in {"pendingScan", "notFound"}:
                break
            severity = alert.get("severity")
            if severity not in ("low", "medium", "high", "critical"):
                severity = "unknown"
            raw_ids = alert.get("ids", ()) if kind in SOCKET_CVE_TYPES or kind == "malware" else ()
            ids = {_canonical(m) for value in (raw_ids[:16] if isinstance(raw_ids, list) else ())
                   if isinstance(value, str) and len(value) <= 192 for m in _ADVISORY.findall(value)}
            key = kind, severity, tuple(sorted(ids))
            normalized[key] = {"package": package, "version": version, "type": kind, "severity": severity,
                               "ids": sorted(ids), "source": ("https://socket.dev/npm/package/"
                                    + quote(package, safe="@/") + "/overview/" + quote(version, safe=""))}
        else:
            covered += 1
            result.extend(normalized[key] for key in sorted(normalized))
    return {"status": "ok" if covered == len(eligible) else "partial", "covered": covered, "alerts": result}


def query_socket(tool_root, eligible):
    """Run the pinned public VLT Socket client with filesystem restrictions and no secrets."""
    if not eligible:
        return {"status": "skipped", "covered": 0, "alerts": []}
    if len(eligible) > MAX_RELEASES or any(not npm_name(name) or not release_version(version)
                                          for name, version in eligible):
        return _error("invalid_release_list")
    node = shutil.which("node")
    root = Path(tool_root).resolve()
    if not node or not (root / "node_modules/@vltpkg/security-archive/package.json").is_file():
        return _error("missing_socket_client")
    try:
        script = files("codemurphy").joinpath("socket_client.mjs").read_text(encoding="utf-8")
        with TemporaryDirectory(prefix="codemurphy-socket-") as temp:
            # Node permits comma-separated filesystem grants. Never accept extra grants in a path.
            if any("," in path or "*" in path for path in (str(root), temp)):
                return _error("invalid_tool_path")
            env = {"TMPDIR": temp, "NODE_NO_WARNINGS": "1", "DO_NOT_TRACK": "1"}
            run = subprocess.run([node, "--permission", "--max-old-space-size=128",
                                  f"--allow-fs-read={root}", f"--allow-fs-read={temp}",
                                  f"--allow-fs-write={temp}", "--input-type=module", "--eval", script],
                                 cwd=root, env=env, input=json.dumps(sorted(eligible)).encode(),
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=35)
            if run.returncode or len(run.stdout) > 3_000_000:
                return _error("socket_client_failed")
            return normalize(json.loads(run.stdout), eligible)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return _error("socket_client_unavailable")
