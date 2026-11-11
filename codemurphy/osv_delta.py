"""Match an approved set of exact npm versions with a trusted offline OSV scanner."""

import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import tempfile
import time
import zipfile


MAX_LOCKFILE_BYTES = 8_000_000
MAX_OUTPUT_BYTES = 16_000_000
MAX_SNAPSHOT_BYTES = 512_000_000
TIMEOUT_SECONDS = 90
ADVISORY_ID = re.compile(r"[A-Za-z0-9:_.-]{1,128}")


class _ScanError(Exception):
    pass


def _result(status, reason):
    return {"status": status, "reason": reason, "advisories": []}


def _run(scanner: Path, cache: Path, root: Path, lockfile: Path, config: Path) -> bytearray:
    deadline = time.monotonic() + TIMEOUT_SECONDS
    args = [
        str(scanner), "scan", "source", "--offline", "--lockfile", str(lockfile),
        "--format", "json", "--all-packages", "--no-resolve", "--verbosity", "error",
        "--config", str(config),
    ]
    # The reviewed repository supplies neither executable, arguments, config, nor environment.
    env = {
        "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": str(cache),
        "XDG_CONFIG_HOME": str(root),
        "XDG_CACHE_HOME": str(root),
        "TMPDIR": str(root),
        "PATH": "",
    }
    stdout, stderr = bytearray(), bytearray()
    with subprocess.Popen(
        args, cwd=root, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ) as process, selectors.DefaultSelector() as pending:
        try:
            pending.register(process.stdout, selectors.EVENT_READ, stdout)
            pending.register(process.stderr, selectors.EVENT_READ, stderr)
            while pending.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise _ScanError("scanner-timeout")
                for key, _ in pending.select(remaining):
                    room = MAX_OUTPUT_BYTES - len(stdout) - len(stderr)
                    block = os.read(key.fd, min(65536, room + 1))
                    if len(block) > room:
                        raise _ScanError("output-size-limit")
                    if block:
                        key.data.extend(block)
                    else:
                        pending.unregister(key.fileobj)
            if process.wait(timeout=max(0, deadline - time.monotonic())) not in (0, 1) or stderr.strip():
                raise _ScanError("scanner-failed")
        except subprocess.TimeoutExpired:
            raise _ScanError("scanner-timeout") from None
        finally:
            if process.poll() is None:
                process.kill()
    return stdout


def _rows(output: bytearray, lockfile: Path, eligible: set[tuple[str, str]]) -> list[dict]:
    covered = set()
    by_id: dict[tuple[str, str, str], set[str]] = {}
    try:
        results = json.loads(output)["results"]
        if results is None:
            results = []
        if not isinstance(results, list):
            raise ValueError
        for result in results:
            source = result["source"]
            if source["type"] != "lockfile" or source["path"] != str(lockfile):
                raise ValueError
            packages = result["packages"]
            if not isinstance(packages, list):
                raise ValueError
            for row in packages:
                package = row["package"]
                if package.get("ecosystem") != "npm":
                    continue
                name, version = package["name"], package["version"]
                if not isinstance(name, str) or not isinstance(version, str):
                    raise ValueError
                if (name, version) not in eligible:
                    continue
                covered.add((name, version))
                vulnerabilities = row.get("vulnerabilities", [])
                if not isinstance(vulnerabilities, list):
                    raise ValueError
                for vulnerability in vulnerabilities:
                    advisory = vulnerability["id"]
                    aliases = vulnerability.get("aliases", [])
                    if not ADVISORY_ID.fullmatch(advisory) or not isinstance(aliases, list):
                        raise ValueError
                    if any(not ADVISORY_ID.fullmatch(alias) for alias in aliases):
                        raise ValueError
                    by_id.setdefault((name, version, advisory), set()).update(aliases)
    except (AttributeError, KeyError, RecursionError, TypeError, ValueError):
        raise _ScanError("invalid-output") from None
    if covered != eligible:
        raise _ScanError("incomplete-coverage")
    return [
        {"package": name, "version": version, "id": advisory, "aliases": sorted(aliases - {advisory})}
        for (name, version, advisory), aliases in sorted(by_id.items())
    ]


def scan_offline(scanner: Path, db_cache: Path, lockfile: bytes, eligible: set[tuple[str, str]]) -> dict:
    """Scan one pnpm lockfile; report IDs only for the caller's approved npm version pairs.

    The caller must supply a trusted absolute path to the OSV-Scanner binary and
    a trusted local snapshot cache, both independent of the reviewed change.
    The lockfile stays local. Empty advisories are evidence only with status
    "ok", meaning the scanner returned inventory for every eligible pair.
    """
    if not eligible:
        return _result("skipped", "no-eligible-versions")
    if not 0 < len(lockfile) <= MAX_LOCKFILE_BYTES:
        return _result("error", "lockfile-size-limit")
    scanner = Path(scanner)
    if not scanner.is_absolute() or not scanner.is_file():
        return _result("error", "missing-scanner")
    try:
        cache = Path(db_cache).resolve()
        snapshot = cache / "osv-scalibr" / "npm" / "all.zip"
        if (
            not snapshot.is_file()
            or not 0 < snapshot.stat().st_size <= MAX_SNAPSHOT_BYTES
            or not zipfile.is_zipfile(snapshot)
        ):
            return _result("error", "missing-or-invalid-cache")
    except (OSError, RuntimeError):
        return _result("error", "missing-or-invalid-cache")
    try:
        with tempfile.TemporaryDirectory(prefix="codemurphy-osv-") as tmp:
            root = Path(tmp).resolve()
            source = root / "pnpm-lock.yaml"
            source.write_bytes(lockfile)
            config = root / "osv-scanner.toml"
            config.touch()
            output = _run(scanner, cache, root, source, config)
            return {"status": "ok", "advisories": _rows(output, source, eligible)}
    except _ScanError as exc:
        return _result("error", str(exc))
    except OSError:
        return _result("error", "scanner-unavailable")
