"""Reproducible labeled comparisons, including imported incumbent reviews."""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from .config import LABEL, RUBRIC, SHA, array, integer, number, obj, safe_path, string
from .context import reference
from .diff import from_unified
from .providers import call
from .redact import redact
from .review import config_fingerprint, percentile95, publication_findings, reviewer_metadata, run_review


class BenchmarkError(ValueError):
    pass


def read_bytes(path, limit):
    with Path(path).open("rb") as file:
        content = file.read(limit + 1)
    if len(content) > limit:
        raise BenchmarkError("Input file exceeds its size limit")
    return content


def read_json(path, limit=2_000_000):
    try:
        return json.loads(read_bytes(path, limit))
    except (json.JSONDecodeError, UnicodeError, RecursionError):
        raise BenchmarkError("Invalid JSON input file") from None


@dataclass(frozen=True)
class Case:
    id: str
    files: tuple
    refs: tuple
    expected: tuple


@dataclass(frozen=True)
class Suite:
    id: str
    sha256: str
    cases: tuple[Case, ...]


def _id(value, field):
    if not LABEL.fullmatch(string(value, field, 64)):
        raise BenchmarkError(f"Invalid {field}")
    return value


def _fixture(root, name, limit):
    if not safe_path(name):
        raise BenchmarkError("Fixture paths must be relative to the suite")
    path = (root / name).resolve()
    if not path.is_relative_to(root):
        raise BenchmarkError("Fixture resolves outside the suite")
    return read_bytes(path, limit)


def _targets(raw):
    result = []
    for target in array(raw, "expected", 100):
        obj(target, "id path side start end category weight keywords", "expected finding")
        _id(target.get("id"), "finding ID")
        if not safe_path(target.get("path")) or target.get("side") not in ("LEFT", "RIGHT"):
            raise BenchmarkError("Expected finding requires a safe path and side")
        start = integer(target.get("start"), "start", 1, 10**9)
        end = integer(target.get("end", start), "end", start, 10**9)
        if target.get("category") not in tuple(RUBRIC):
            raise BenchmarkError("Invalid expected finding category")
        keywords = [string(x, "match keyword", 100)
                    for x in array(target.get("keywords", []), "keywords", 15)]
        result.append({**target, "end": end, "weight": integer(target.get("weight", 1), "weight", 1, 10),
                       "keywords": keywords})
    if len({t["id"] for t in result}) != len(result):
        raise BenchmarkError("Expected finding IDs must be unique in a case")
    return tuple(result)


def load_suite(path):
    path = Path(path).resolve()
    root = path.parent
    raw = obj(read_json(path), "id cases", "benchmark suite")
    identifier = _id(raw.get("id"), "suite ID")
    digest = hashlib.sha256(json.dumps(raw, sort_keys=True, ensure_ascii=True).encode())
    cases = []
    for case in array(raw.get("cases"), "cases", 50):
        obj(case, "id diff context expected", "benchmark case")
        case_id = _id(case.get("id"), "case ID")
        patch = _fixture(root, case.get("diff"), 1_000_000)
        digest.update(hashlib.sha256(patch).digest())
        files = tuple(from_unified(patch.decode("utf-8")))
        if not files:
            raise BenchmarkError(f"Case {case_id} needs a Git unified diff")
        refs = []
        for ref in array(case.get("context", []), "case context", 48):
            obj(ref, "id repo commit path file", "benchmark context")
            ref_id = string(ref.get("id"), "reference ID", 80)
            repo = string(ref.get("repo"), "reference repository", 200)
            commit = string(ref.get("commit"), "reference commit", 40)
            if not SHA.fullmatch(commit) or not safe_path(ref.get("path")):
                raise BenchmarkError("Benchmark context needs a pinned commit and safe source path")
            blob = _fixture(root, ref.get("file"), 32000)
            digest.update(hashlib.sha256(blob).digest())
            refs.append(reference(ref_id, repo, commit, ref["path"], blob))
        if len(refs) != len({r.id for r in refs}):
            raise BenchmarkError("Duplicate context ID")
        expected = _targets(case.get("expected"))
        changed = [(x.path, x.side, x.number) for f in files for x in f.lines if x.changed]
        for target in expected:
            if not any(p == target["path"] and s == target["side"] and target["start"] <= n <= target["end"]
                       for p, s, n in changed):
                raise BenchmarkError(f"Expected finding {target['id']} in {case_id} is not on a changed line")
        cases.append(Case(case_id, files, tuple(refs), expected))
    if not cases or len({c.id for c in cases}) != len(cases):
        raise BenchmarkError("Suite needs one or more cases with unique IDs")
    return Suite(identifier, digest.hexdigest(), tuple(cases))


def _matches(target, issue):
    text = (issue["title"] + " " + issue.get("detail", "")).casefold()
    return (issue["path"] == target["path"] and issue["side"] == target["side"] and
            target["start"] <= issue["line"] <= target["end"] and issue["category"] == target["category"] and
            (not target["keywords"] or any(term.casefold() in text for term in target["keywords"])))


def score_findings(expected, issues, anchors=None):
    """Maximum one-to-one matching; duplicates and unmatched issues count as false positives."""
    eligible = [(j, issue) for j, issue in enumerate(issues) if anchors is None or
                (issue["path"], issue["side"], issue["line"]) in anchors]
    edges = [[j for j, issue in eligible if _matches(t, issue)] for t in expected]
    assigned = {}

    def visit(i, seen):
        for j in edges[i]:
            if j in seen:
                continue
            seen.add(j)
            if j not in assigned or visit(assigned[j], seen):
                assigned[j] = i
                return True
        return False

    for i in sorted(range(len(expected)), key=lambda i: -expected[i]["weight"]):
        visit(i, set())
    matches = [{"expected": expected[i]["id"], "finding_index": j} for j, i in sorted(assigned.items())]
    return {"tp": len(matches), "fp": len(issues) - len(matches), "fn": len(expected) - len(matches),
            "expected_weight": sum(t["weight"] for t in expected),
            "matched_weight": sum(expected[i]["weight"] for i in assigned.values()),
            "matches": matches}


def _baseline(raw, suite):
    obj(raw, "suite suite_sha256 cases measurements", "baseline")
    if raw.get("suite") != suite.id or raw.get("suite_sha256") != suite.sha256:
        raise BenchmarkError("Baseline does not match this suite and snapshot hash")
    ids = {c.id for c in suite.cases}
    results, measures = raw.get("cases"), raw.get("measurements", {})
    if not isinstance(results, dict) or not isinstance(measures, dict) or results.keys() - ids or measures.keys() - results.keys():
        raise BenchmarkError("Baseline contains unknown or invalid case IDs")
    rows = {}
    for case_id, findings in results.items():
        findings = array(findings, "baseline findings", 300)
        for item in findings:
            obj(item, "path side line category title detail", "baseline finding")
            if not safe_path(item.get("path")) or item.get("side") not in ("LEFT", "RIGHT"):
                raise BenchmarkError("Baseline finding requires a path and side")
            integer(item.get("line"), "baseline line", 1, 10**9)
            if item.get("category") not in tuple(RUBRIC):
                raise BenchmarkError("Invalid baseline category")
            string(item.get("title"), "baseline title", 1000)
            if "detail" in item:
                string(item["detail"], "baseline detail", 8000)
        cost = obj(measures.get(case_id, {}), "cost_usd latency_ms", "baseline measurements")
        rows[case_id] = (findings, {k: number(v, k, 0, 10**9) for k, v in cost.items()})
    return rows


def _rollup(rows):
    if not rows:
        return None
    keys = ("tp", "fp", "fn", "expected_weight", "matched_weight")
    totals = {key: sum(r[key] for r in rows) for key in keys}
    tp, fp, fn = (totals[x] for x in ("tp", "fp", "fn"))
    def ratio(a, b):
        return round(a / b, 6) if b else None
    costs = [r["cost_usd"] for r in rows]
    return {**totals, "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn),
            "f1": ratio(2 * tp, 2 * tp + fp + fn),
            "weighted_recall": ratio(totals["matched_weight"], totals["expected_weight"]),
            "clean_cases_with_findings": sum(r["expected_weight"] == 0 and r["fp"] > 0 for r in rows),
            "cost_usd": round(sum(costs), 10) if all(v is not None for v in costs) else None,
            "measured_cost_cases": sum(v is not None for v in costs),
            "p95_latency_ms": percentile95([r["latency_ms"] for r in rows if r["latency_ms"] is not None]),
            "measured_latency_cases": sum(r["latency_ms"] is not None for r in rows)}


def evaluate(suite, config, *, static_only=False, baselines=None, provider=call):
    model_ids = [] if static_only else [m.id for m in config.models]
    labels = ["static"]
    if model_ids:
        labels += ([] if config.verify_with else ["combined"]) + ["published-primary"] + model_ids
    outputs = {k: {} for k in labels}
    imported = {}
    for label, value in (baselines or {}).items():
        if label in outputs or not LABEL.fullmatch(label):
            raise BenchmarkError("Baseline label must be unique and cannot shadow a reviewer")
        imported[label] = _baseline(value, suite)
        outputs[label] = {}
    snapshots = {}
    for case in suite.cases:
        report = run_review(config, case.files, case.refs, mode="compare",
                            static_only=static_only, provider=provider)
        snapshots[case.id] = {"input_sha256": report["input_sha256"], "coverage": report["coverage"]}
        anchors = {(x.path, x.side, x.number) for f in case.files for x in f.lines if x.changed}
        partial = report["coverage"]["partial"]
        verification = report.get("verification")
        for reviewer, rows in outputs.items():
            cost, latency, rejected, versions = None, None, 0, []
            complete = not partial
            if reviewer in imported:
                if case.id not in imported[reviewer]:
                    rows[case.id] = {"status": "missing", "cost_usd": None, "latency_ms": None}
                    continue
                issues, measured = imported[reviewer][case.id]
                cost, latency = measured.get("cost_usd"), measured.get("latency_ms")
                complete = True
            elif reviewer == "static":
                issues, cost = report["candidates"]["static"], 0
                if static_only:
                    latency = report["wall_ms"]
            elif reviewer == "combined":
                stats = list(report["models"].values())
                complete &= not any(s["failed_requests"] for s in stats)
                costs = [s["estimated_usd"] for s in stats]
                cost = sum(costs) if all(c is not None for c in costs) else None
                rejected = sum(s["rejected"] for s in stats)
                issues, latency = report["findings"], report["wall_ms"]
            elif reviewer == "published-primary":
                stats = report["models"][config.primary]
                complete &= stats["failed_requests"] == 0
                issues = publication_findings(report)[:config.max_comments]
                cost, latency, rejected = stats["estimated_usd"], stats["wall_ms"], stats["rejected"]
                versions = stats["resolved_models"]
                if verification:
                    complete &= not verification["failed_requests"]
                    extra = verification["estimated_usd"]
                    cost = cost + extra if cost is not None and extra is not None else None
                    phases = (latency, verification["wall_ms"])
                    latency = sum(ms for ms in phases if ms is not None)
            else:
                stats = report["models"][reviewer]
                complete &= stats["failed_requests"] == 0
                issues = report["candidates"][reviewer]
                cost, latency, rejected = stats["estimated_usd"], stats["wall_ms"], stats["rejected"]
                versions = stats["resolved_models"]
            rows[case.id] = {**score_findings(case.expected, issues, anchors), "status": "complete" if complete else "partial",
                             "cost_usd": cost, "latency_ms": latency, "rejected_findings": rejected,
                             "resolved_models": versions,
                             "findings": [{k: redact(i[k]) if k in ("path", "title") else i[k]
                                           for k in ("path", "line", "side", "category", "title")} for i in issues]}
    common = [c.id for c in suite.cases if all(rows[c.id]["status"] == "complete" for rows in outputs.values())]
    candidates = {}
    for label, rows in outputs.items():
        completed = [r for r in rows.values() if r["status"] == "complete"]
        costs = [r["cost_usd"] for r in rows.values()]
        candidates[label] = {"completed_cases": len(completed), "own": _rollup(completed),
                             "common": _rollup([rows[i] for i in common]),
                             "cost_usd": round(sum(costs), 10) if all(c is not None for c in costs) else None,
                             "cases": rows}
    return {"schema": 1, "suite": suite.id, "suite_sha256": suite.sha256,
            "case_count": len(suite.cases), "common_cases": common, "inputs": snapshots,
            "config_sha256": config_fingerprint(config), "models": {} if static_only else reviewer_metadata(config),
            "candidates": candidates}
