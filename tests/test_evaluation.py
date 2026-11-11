import json
from pathlib import Path
import tempfile
import unittest

from codemurphy.benchmark import evaluate, load_suite, score_findings
from codemurphy.config import load_config
from codemurphy.diff import parse_patch
from codemurphy.history import feedback, metrics, record
from codemurphy.providers import Reply, ModelError
from codemurphy.review import run_review


def target(name, start, end, weight):
    return {"id": name, "path": "x.py", "side": "RIGHT", "start": start, "end": end,
            "category": "security", "weight": weight, "keywords": ["unsafe"]}


def finding(line, title="Unsafe input"):
    return {"path": "x.py", "side": "RIGHT", "line": line, "title": title,
            "detail": "A request can reach this line", "category": "security"}


class EvaluationTests(unittest.TestCase):
    def test_one_to_one_matching_penalizes_duplicate_and_wrong_claim(self):
        result = score_findings([target("wide", 1, 2, 1), target("critical", 1, 1, 3)],
                                [finding(1), finding(2), finding(2), finding(1, "Typo")])
        self.assertEqual((result["tp"], result["fp"], result["fn"]), (2, 2, 0))
        self.assertEqual(result["matched_weight"], 4)

    def test_unchanged_line_is_not_matched_even_inside_target_range(self):
        result = score_findings([target("bug", 1, 3, 3)], [finding(2)],
                                anchors={("x.py", "RIGHT", 3)})
        self.assertEqual((result["tp"], result["fp"], result["fn"]), (0, 1, 1))

    def test_clean_cases_count_false_positives(self):
        result = score_findings([], [finding(3)])
        self.assertEqual((result["tp"], result["fp"], result["fn"]), (0, 1, 0))

    def test_head_to_head_uses_only_common_complete_cases(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            source = "diff --git a/x.py b/x.py\n--- /dev/null\n+++ b/x.py\n@@ -0,0 +1 @@\n"
            (path / "a.diff").write_text(source + "+first()\n")
            (path / "b.diff").write_text(source + "+second()\n")
            (path / "suite.json").write_text(json.dumps({"id": "small", "cases": [
                {"id": name, "diff": f"{name}.diff", "expected": [target("bug", 1, 1, 3)]}
                for name in ("a", "b")]}))
            suite = load_suite(path / "suite.json")
            cfg = load_config({"models": [{"id": label, "model": label, "api_key_env": None}
                                          for label in ("steady", "limited")],
                               "review": {"max_comments": 0}})
            def provider(model, system, data, timeout):
                if model.id == "limited" and "second()" in data:
                    raise ModelError("HTTP 429")
                issue = {**finding(1), "quote": "first()", "severity": "high",
                         "confidence": .9, "suggestion": "Check the input"}
                return Reply(json.dumps({"findings": [issue] if "first()" in data else []}),
                             20, 5, "fixture-model-v1")
            baseline = {"suite": "small", "suite_sha256": suite.sha256,
                        "cases": {"a": [finding(1)], "b": [finding(1)]}}
            result = evaluate(suite, cfg, baselines={"incumbent": baseline}, provider=provider)
        self.assertEqual(result["common_cases"], ["a"])
        self.assertEqual(result["candidates"]["limited"]["completed_cases"], 1)
        self.assertEqual(result["candidates"]["incumbent"]["common"]["recall"], 1)
        self.assertIsNone(result["candidates"]["steady"]["cost_usd"])
        self.assertEqual(result["models"]["steady"]["model"], "steady")
        self.assertEqual(result["candidates"]["steady"]["common"]["recall"], 1)
        self.assertEqual(result["candidates"]["published-primary"]["common"]["recall"], 0)

    def test_feedback_credits_independent_sources_and_does_not_store_evidence(self):
        config = load_config({"models": [{"id": label, "model": label, "api_key_env": None}
                                          for label in ("fast", "slow")]})
        def provider(model, system, data, timeout):
            item = {**finding(1), "quote": "do_it()", "severity": "high", "confidence": .9,
                    "suggestion": "Validate input", "detail": "Do not persist this review prose"}
            return Reply(json.dumps({"findings": [item]}), 20, 5)
        report = run_review(config, [parse_patch("x.py", "@@ -0,0 +1 @@\n+do_it()")],
                            mode="compare", provider=provider)
        with tempfile.TemporaryDirectory() as folder:
            db = Path(folder) / "history.sqlite3"
            record(db, report)
            record(db, report)
            feedback(db, report["run_id"], report["findings"][0]["id"], "useful")
            result = {row["id"]: row for row in metrics(db)}
            self.assertNotIn(b"Do not persist this review prose", db.read_bytes())
        for key in ("fast", "slow"):
            self.assertEqual(result[key]["runs"], 1)
            self.assertEqual(result[key]["useful_rate"], 1)
            self.assertIsNone(result[key]["cost_usd"])
