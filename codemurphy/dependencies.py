"""Report-only audit of changed public npm releases in a pnpm lockfile."""
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import time
from urllib.parse import quote, unquote, urlsplit

from .config import SHA, repo_name
from .http import RequestError, json_request

LOCKFILE = "pnpm-lock.yaml"
LOCK_LIMIT = 1_000_000
MAX_RELEASES = 128
NPM = "https://registry.npmjs.org/"
_NAME = re.compile(r"(?:@[a-z0-9][a-z0-9_.-]*/)?[a-z0-9][a-z0-9_.-]*")
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")
SOCKET_CVE_TYPES = {"cve", "criticalCVE", "mediumCVE", "mildCVE", "lowCVE"}


class DependencyError(RuntimeError):
    pass


def npm_name(value):
    return isinstance(value, str) and len(value) <= 214 and bool(_NAME.fullmatch(value))


def release_version(value):
    return isinstance(value, str) and len(value) <= 128 and bool(_VERSION.fullmatch(value))


def _packages(raw):
    if len(raw) > LOCK_LIMIT:
        raise DependencyError("pnpm lockfile exceeds the audit size limit")
    try:
        from ruamel.yaml import YAML
        from ruamel.yaml.error import YAMLError
        from ruamel.yaml.events import AliasEvent, CollectionEndEvent, CollectionStartEvent
    except ImportError:
        raise DependencyError("Install CodeMurphy with the dependency-audit extra") from None
    try:
        text = raw.decode("utf-8")
        yaml = YAML(typ="safe", pure=True)
        depth = 0
        # Bound the parser before constructing the YAML tree. pnpm emits no aliases or tags.
        for count, event in enumerate(yaml.parse(text), 1):
            depth += isinstance(event, CollectionStartEvent) - isinstance(event, CollectionEndEvent)
            if (count > 150_000 or depth > 32 or isinstance(event, AliasEvent)
                    or getattr(event, "anchor", None) is not None or getattr(event, "tag", None) is not None):
                raise DependencyError("Unsupported pnpm lockfile structure")
        yaml = YAML(typ="safe", pure=True)
        yaml.allow_duplicate_keys = False
        document = yaml.load(text)
    except (YAMLError, ValueError, UnicodeError, RecursionError):
        raise DependencyError("Invalid pnpm lockfile") from None
    if not isinstance(document, dict) or document.get("lockfileVersion") not in ("9.0", 9.0):
        raise DependencyError("Dependency audit requires pnpm lockfile version 9.0")
    packages = document.get("packages", {})
    if not isinstance(packages, dict) or any(not isinstance(k, str) or not isinstance(v, dict)
                                              for k, v in packages.items()):
        raise DependencyError("Invalid pnpm packages table")
    return {key: value.get("resolution") for key, value in packages.items()}


def delta(before, after):
    """Compare resolved artifacts, ignoring removals and peer snapshots of the same release."""
    base, head = _packages(before), _packages(after)
    result = {}
    for key, resolution in head.items():
        if key in base:
            if base[key] == resolution:
                continue
            previous = _public_resolution(key, base[key])
            if previous is not None and previous == _public_resolution(key, resolution):
                continue
        result[key] = resolution
    if len(result) > MAX_RELEASES:
        raise DependencyError("Too many changed releases for one dependency audit")
    return result


def _npm_tarball(url, name, version):
    if not isinstance(url, str):
        return False
    try:
        parts = urlsplit(url)
        filename = f"/{name}/-/{name.rsplit('/', 1)[-1]}-{version}.tgz"
        return (parts.scheme == "https" and parts.netloc == "registry.npmjs.org" and
                not parts.query and not parts.fragment and unquote(parts.path, errors="strict") == filename)
    except (ValueError, UnicodeError):
        return False


def _sri(value):
    if not isinstance(value, str) or not re.fullmatch(r"sha512-[A-Za-z0-9+/]{86}==", value):
        return False
    return base64.b64encode(base64.b64decode(value[7:], validate=True)).decode() == value[7:]


def _public_resolution(key, resolution):
    name, _, version = key.rpartition("@")
    if (not npm_name(name) or not release_version(version) or not isinstance(resolution, dict)
            or set(resolution) - {"integrity", "tarball"} or not _sri(resolution.get("integrity"))
            or ("tarball" in resolution and not _npm_tarball(resolution["tarball"], name, version))):
        return None
    return name, version, resolution["integrity"]


def npm_metadata(name):
    if not npm_name(name):
        raise DependencyError("Invalid approved npm name")
    return json_request(NPM + quote(name, safe="@"), headers={"Accept": "application/vnd.npm.install-v1+json"},
                        timeout=12, limit=16_000_000)


def public_releases(changed, allowlist, npm=npm_metadata):
    """Read packuments only for trusted names; submit a version only after exact SRI proof."""
    withheld, pending = Counter(), defaultdict(dict)
    verified = set()
    for key, resolution in changed.items():
        candidate = _public_resolution(key, resolution)
        if candidate is None:
            withheld["unsupported_resolution"] += 1
            continue
        name, version, integrity = candidate
        if name not in allowlist:
            withheld["unapproved_name"] += 1
        else:
            pending[name][version] = integrity

    def lookup(name):
        try:
            return npm(name), None
        except RequestError as exc:
            return None, "npm_not_found" if exc.status == 404 else "npm_unavailable"

    with ThreadPoolExecutor(max_workers=4) as pool:
        for name, (packument, error) in zip(pending, pool.map(lookup, pending), strict=True):
            if error:
                withheld[error] += len(pending[name])
                continue
            versions = packument.get("versions") if isinstance(packument, dict) and packument.get("name") == name else None
            for version, expected in pending[name].items():
                row = versions.get(version) if isinstance(versions, dict) else None
                dist = row.get("dist") if isinstance(row, dict) and row.get("name") == name and row.get("version") == version else None
                if not isinstance(dist, dict) or not _npm_tarball(dist.get("tarball"), name, version):
                    withheld["no_public_artifact"] += 1
                elif dist.get("integrity") != expected:
                    withheld["integrity_mismatch"] += 1
                else:
                    verified.add((name, version))
    return verified, dict(sorted(withheld.items()))


def pinned_lockfiles(api, repo, number, trusted_base):
    if not repo_name(repo) or type(number) is not int or not 1 <= number <= 10**9 or not trusted_base:
        raise DependencyError("Select a repository, PR number and trusted base branch")
    endpoint = f"/repos/{repo}/pulls/{number}"

    def identity():
        try:
            data = api.request(endpoint)
            base, head = data["base"], data["head"]
            if (data["number"] != number or data["state"] != "open" or data["draft"] is not False
                    or base["ref"] != trusted_base or base["repo"]["full_name"].casefold() != repo.casefold()
                    or head["repo"]["full_name"].casefold() != repo.casefold()):
                raise DependencyError("Dependency observation requires an open, ready, same-repository PR on the trusted base")
            if not SHA.fullmatch(base["sha"]) or not SHA.fullmatch(head["sha"]):
                raise ValueError
            return base["sha"], head["sha"]
        except (KeyError, TypeError, AttributeError, ValueError):
            raise DependencyError("Invalid GitHub PR metadata") from None

    base, head = identity()
    comparison = api.request(f"/repos/{repo}/compare/{base}...{head}?per_page=1")
    try:
        merge = comparison["merge_base_commit"]["sha"]
        if not SHA.fullmatch(merge):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise DependencyError("Could not verify the PR merge base") from None
    before, after = (api.blob(repo, sha, LOCKFILE, limit=LOCK_LIMIT) for sha in (merge, head))
    if identity() != (base, head):
        raise DependencyError("PR changed while reading the lockfiles; run the audit again")
    return {"repo": repo, "pr": number, "base": base, "head": head, "merge_base": merge}, before, after


def _compare(socket_result, osv_result):
    found = defaultdict(set)
    for item in osv_result.get("advisories", ()):
        found[item["package"], item["version"]].update(x.casefold() for x in [item["id"], *item.get("aliases", ())])
    comparison = {key: [] for key in ("shared_advisories", "socket_only_advisories", "unmatched_advisories",
                                     "socket_malware", "socket_suspected_malware", "socket_signals")}
    for item in socket_result.get("alerts", ()):
        ids = {x.casefold() for x in item["ids"]}
        matches_osv = bool(ids & found[item["package"], item["version"]])
        if item["type"] == "malware":
            key = "socket_malware"
            item = {**item, "osv_match": matches_osv if ids and osv_result["status"] == "ok" else None}
        elif item["type"] == "gptMalware":
            key = "socket_suspected_malware"
        elif item["type"] in SOCKET_CVE_TYPES:
            if matches_osv:
                key = "shared_advisories"
            else:
                key = "socket_only_advisories" if ids and osv_result["status"] == "ok" else "unmatched_advisories"
        else:
            key = "socket_signals"
        comparison[key].append(item)
    return comparison


def audit(before, after, allowlist, *, socket, osv, npm=npm_metadata):
    changed = delta(before, after)
    eligible, withheld = public_releases(changed, allowlist, npm)
    if eligible:
        with ThreadPoolExecutor(max_workers=2) as pool:
            remote = pool.submit(socket, eligible)
            local = pool.submit(osv, after, eligible)
            socket_result, osv_result = remote.result(), local.result()
    else:
        socket_result = {"status": "skipped", "covered": 0, "alerts": []}
        osv_result = {"status": "skipped", "advisories": []}
    return {"schema": 1, "mode": "observe", "scope": {"changed": len(changed), "eligible": len(eligible),
            "withheld": withheld, "packages": [{"package": n, "version": v} for n, v in sorted(eligible)]},
            "socket": socket_result, "osv": osv_result, "comparison": _compare(socket_result, osv_result)}


def _allowlist(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(32_001)
    try:
        value = json.loads(raw) if len(raw) <= 32_000 else None
        names = value.get("public_npm") if isinstance(value, dict) else None
        if not isinstance(names, list) or not names or any(not npm_name(name) for name in names):
            raise ValueError
        return set(names)
    except (ValueError, RecursionError):
        raise DependencyError("Invalid trusted public npm allowlist") from None


def add_command(subparsers):
    parser = subparsers.add_parser("dependencies", help="Compare Socket and offline OSV on a GitHub PR (report only)")
    parser.add_argument("--repo", required=True, help="GitHub owner/repository")
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--trusted-base", required=True, help="Expected base branch of an open, ready PR")
    parser.add_argument("--allowlist", required=True, help="Trusted local JSON containing exact public_npm names")
    parser.add_argument("--socket-tools", required=True, help="Local tool directory containing the pinned Socket client")
    parser.add_argument("--osv-scanner", required=True, help="Absolute path to a trusted local OSV Scanner binary")
    parser.add_argument("--osv-db", required=True, help="Cache root with osv-scalibr/npm/all.zip")
    parser.add_argument("--output", required=True, help="Create a new private JSON report at this path")
    parser.set_defaults(handler=_command)


def _command(args):
    from .github import GitHub
    from .osv_delta import scan_offline
    from .socket_reports import query_socket

    output = Path(args.output)
    if not output.parent.is_dir() or output.exists() or output.is_symlink():
        raise DependencyError("Choose a new report path in an existing private directory")
    allowed = _allowlist(args.allowlist)
    token = os.getenv("CODEMURPHY_GITHUB_TOKEN") or os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    start = time.perf_counter()
    source, before, after = pinned_lockfiles(GitHub(token), args.repo, args.pr, args.trusted_base)
    report = audit(before, after, allowed, socket=lambda pairs: query_socket(args.socket_tools, pairs),
                   osv=lambda raw, pairs: scan_offline(Path(args.osv_scanner), Path(args.osv_db), raw, pairs))
    report["source"] = {**source, "lockfile": LOCKFILE,
                        "base_lock_sha256": hashlib.sha256(before).hexdigest(),
                        "head_lock_sha256": hashlib.sha256(after).hexdigest()}
    report["elapsed_ms"] = round((time.perf_counter() - start) * 1000)
    with os.fdopen(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=True, allow_nan=False)
        f.write("\n")
    scope = report["scope"]
    print(f"PR #{args.pr}: {scope['eligible']}/{scope['changed']} public releases; "
          f"Socket {report['socket']['status']}, offline OSV {report['osv']['status']}; report only.")
    return 2 if scope["withheld"] or (scope["eligible"] and
                   (report["socket"]["status"] != "ok" or report["osv"]["status"] != "ok")) else 0
