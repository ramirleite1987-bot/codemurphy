"""Local history stores IDs, outcomes, and telemetry rather than source or prompts."""
from collections import Counter, defaultdict
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3

from .review import percentile95

VERDICTS = ("useful", "false-positive", "duplicate", "uncertain")


@contextmanager
def _db(path):
    path = Path(path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        pass
    else:
        os.close(fd)
    conn = sqlite3.connect(path)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY, repo TEXT NOT NULL, created_at TEXT NOT NULL,
                input_sha256 TEXT NOT NULL, mode TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS models (
                run_id TEXT REFERENCES runs(id), label TEXT, provider TEXT, model TEXT, stats TEXT,
                PRIMARY KEY (run_id, label)
            );
            CREATE TABLE IF NOT EXISTS findings (
                run_id TEXT REFERENCES runs(id), id TEXT, sources TEXT, verdict TEXT,
                PRIMARY KEY (run_id, id)
            );
        """)
        with conn:
            yield conn
    finally:
        conn.close()


def record(path, report):
    if report.get("schema") != 1 or "run_id" not in report or report.get("skipped"):
        raise ValueError("Only completed CodeMurphy review reports can be recorded")
    with _db(path) as conn:
        inserted = conn.execute("INSERT OR IGNORE INTO runs VALUES (?, ?, ?, ?, ?)",
                                (report["run_id"], report["source"].get("repo", ""), report["created_at"],
                                 report["input_sha256"], report["mode"])).rowcount
        if not inserted:
            return
        fields = ("requests", "failed_requests", "findings", "rejected", "input_tokens", "output_tokens",
                  "estimated_usd", "latencies_ms")
        for model, stats in report["models"].items():
            conn.execute("INSERT INTO models VALUES (?, ?, ?, ?, ?)",
                         (report["run_id"], model, stats["provider"], stats["model"],
                          json.dumps({**{key: stats[key] for key in fields}, "resolved_models": stats.get("resolved_models", [])},
                                     allow_nan=False)))
        conn.executemany("INSERT INTO findings (run_id, id, sources) VALUES (?, ?, ?)",
                         [(report["run_id"], i["id"], json.dumps(i["sources"])) for i in report["findings"]])


def feedback(path, run_id, finding_id, verdict):
    if verdict not in VERDICTS:
        raise ValueError("Invalid feedback verdict")
    with _db(path) as conn:
        updated = conn.execute("UPDATE findings SET verdict=? WHERE run_id=? AND id=?",
                               (verdict, run_id, finding_id)).rowcount
        if not updated:
            raise ValueError("Finding not found in this run; record the review report first")


def metrics(path, repo=None):
    groups, rated = defaultdict(list), defaultdict(Counter)
    with _db(path) as conn:
        for label, provider, model, stats in conn.execute(
                "SELECT m.label, m.provider, m.model, m.stats FROM models m "
                "JOIN runs r ON r.id=m.run_id WHERE (? IS NULL OR r.repo=?)", (repo, repo)):
            groups[(label, provider, model)].append(json.loads(stats))
        for label, provider, model, sources, verdict in conn.execute(
                "SELECT m.label, m.provider, m.model, f.sources, f.verdict FROM models m "
                "JOIN findings f ON f.run_id=m.run_id JOIN runs r ON r.id=m.run_id "
                "WHERE f.verdict IS NOT NULL AND (? IS NULL OR r.repo=?)", (repo, repo)):
            if label in json.loads(sources):
                rated[(label, provider, model)][verdict] += 1
    rows = []
    for key, stats in sorted(groups.items()):
        votes = {v: rated[key][v] for v in VERDICTS}
        valid = votes["useful"] + votes["false-positive"] + votes["duplicate"]
        costs = [x["estimated_usd"] for x in stats]
        def known_total(field):
            values = [s[field] for s in stats]
            return sum(values) if all(x is not None for x in values) else None
        rows.append({"id": key[0], "provider": key[1], "model": key[2], "runs": len(stats),
                     "requests": known_total("requests"), "failed_requests": known_total("failed_requests"),
                     "findings": known_total("findings"), "rejected": known_total("rejected"),
                     "input_tokens": known_total("input_tokens"), "output_tokens": known_total("output_tokens"),
                     "p95_latency_ms": percentile95([ms for s in stats for ms in s["latencies_ms"]]),
                     "cost_usd": round(sum(costs), 10) if all(c is not None for c in costs) else None,
                     "priced_runs": sum(c is not None for c in costs),
                     "reported_versions": dict(sorted(Counter(v for s in stats for v in s.get("resolved_models", [])).items())),
                     "feedback": votes, "rated_findings": valid,
                     "useful_rate": round(votes["useful"] / valid, 6) if valid else None})
    return rows
