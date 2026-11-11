import json
import unittest

from codemurphy.config import ConfigError, load_config
from codemurphy.context import Reference
from codemurphy.diff import parse_patch
from codemurphy.providers import Reply
from codemurphy.render import comment
from codemurphy.review import publication_findings, run_review


class CommentQualityTests(unittest.TestCase):
    def setup_review(self, **review):
        config = load_config({"models": [
            {"id": "primary", "model": "fast", "api_key_env": None, "json_mode": True},
            {"id": "critic", "model": "precise", "api_key_env": None}],
            "review": {"structured_comments": True, "language": "Português do Brasil", **review}})
        files = [parse_patch("src/import.py", "@@ -4,0 +5 @@\n+persist(row)")]
        refs = [Reference("project:1", "project", "a" * 40, "docs/import.md",
                          "An import retry must not create a second ledger entry.")]
        issue = {"path": "src/import.py", "side": "RIGHT", "line": 5, "quote": "persist(row)",
                 "category": "correctness", "severity": "high", "confidence": .94,
                 "title": "Import retry duplicates the ledger entry",
                 "trigger": "The same statement is imported after a timeout.",
                 "impact": "Both entries contribute to the account balance.",
                 "suggestion": "Use the statement ID as the unique import key.",
                 "verification": "Import the same statement twice and assert a single ledger entry.",
                 "citations": [{"id": "project:1", "line": 1,
                                "quote": "An import retry must not create a second ledger entry."}]}
        return config, files, refs, issue

    def test_only_confirmed_findings_reach_publication_and_critics_see_context(self):
        cfg, files, refs, issue = self.setup_review(verify_with="critic")
        def provider(model, system, data, timeout):
            if model.id == "primary":
                unsupported = {**issue, "title": "Memory leak when import parses a string"}
                return Reply(json.dumps({"findings": [issue, unsupported]}), 100, 60)
            self.assertIn("An import retry must not create a second ledger entry.", data)
            payload = json.loads(data)
            candidate = next(c for c in payload["candidates"] if c["title"] == issue["title"])
            return Reply(json.dumps({"confirmed": [{"id": candidate["id"], "quote": "persist(row)"}]}), 110, 20)
        report = run_review(cfg, files, refs, provider=provider)
        self.assertEqual(len(report["candidates"]["primary"]), 2)
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["verification"]["reviewer"], "critic")
        self.assertEqual(report["verification"]["confirmed"], 1)
        self.assertEqual(report["verification"]["rejected"], 1)
        [accepted] = publication_findings(report)
        body = comment(accepted, language=cfg.language)
        for label in ("Gatilho", "Impacto", "Correção sugerida", "Como verificar", "Referências"):
            self.assertIn(label, body)

    def test_missing_reproduction_or_wrong_verifier_quote_withholds_findings(self):
        cfg, files, refs, issue = self.setup_review(verify_with="critic")
        invalid = {k: v for k, v in issue.items() if k != "verification"}
        def provider(model, system, data, timeout):
            if model.id == "primary":
                return Reply(json.dumps({"findings": [issue, invalid]}), 100, 60)
            candidate = json.loads(data)["candidates"][0]
            return Reply(json.dumps({"confirmed": [{"id": candidate["id"], "quote": "invented"}]}), 100, 10)
        report = run_review(cfg, files, refs, provider=provider)
        self.assertEqual(report["models"]["primary"]["rejected"], 1)
        self.assertEqual(report["verification"]["failed_requests"], 1)
        self.assertEqual(publication_findings(report), [])

    def test_no_second_pass_without_candidates(self):
        cfg, files, refs, _ = self.setup_review(verify_with="critic")
        def provider(model, system, data, timeout):
            if model.id != "primary":
                self.fail("verifier should not run when there is nothing to confirm")
            return Reply('{"findings":[]}', 30, 5)
        report = run_review(cfg, files, refs, provider=provider)
        self.assertEqual(report["verification"]["requests"], 0)
        self.assertEqual(report["findings"], [])

    def test_unknown_verifier_is_a_config_error(self):
        with self.assertRaisesRegex(ConfigError, "verify_with"):
            self.setup_review(verify_with="missing")

    def test_verifier_does_not_see_its_own_or_shadow_proposals(self):
        cfg, files, refs, issue = self.setup_review(verify_with="critic")
        original_inputs = {}
        def provider(model, system, data, timeout):
            payload = json.loads(data)
            if "candidates" in payload:
                self.assertEqual(payload["input"], original_inputs["primary"])
                [candidate] = payload["candidates"]
                self.assertEqual(candidate["title"], issue["title"])
                return Reply(json.dumps({"confirmed": [{"id": candidate["id"], "quote": "persist(row)"}]}), 30, 8)
            original_inputs[model.id] = payload
            finding = issue if model.id == "primary" else {**issue, "title": "Unsupported critic candidate"}
            return Reply(json.dumps({"findings": [finding]}), 100, 60)
        report = run_review(cfg, files, refs, mode="compare", provider=provider)
        self.assertEqual(len(report["candidates"]["critic"]), 1)
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["sources"], ["primary"])

    def test_same_model_cannot_verify_even_under_another_id(self):
        with self.assertRaisesRegex(ConfigError, "different model"):
            load_config({"models": [{"id": ident, "model": "same", "api_key_env": None}
                                    for ident in ("primary", "critic")],
                         "review": {"verify_with": "critic"}})
