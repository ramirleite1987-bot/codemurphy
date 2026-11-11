from dataclasses import replace
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

    def test_numbered_evidence_resolves_source_and_rejects_unknown_references(self):
        cfg, files, refs, issue = self.setup_review(verify_with="critic", anchored_evidence=True)
        cfg = replace(cfg, models=tuple(replace(m, json_schema=True) for m in cfg.models))
        refs = [replace(refs[0], start_line=45)]
        kept = {key: value for key, value in issue.items() if key not in ("path", "side", "line", "quote", "citations")}

        def provider(model, system, data, timeout, *, schema):
            payload = json.loads(data)
            if model.id == "primary":
                anchor_id = payload["diff"][0][5]
                self.assertEqual(payload["context"][0]["lines"][0], [45, refs[0].text])
                fields = schema["properties"]["findings"]["items"]["properties"]
                self.assertEqual(fields["anchor_id"]["enum"], [anchor_id])
                self.assertNotIn("quote", fields)
                valid = {**kept, "anchor_id": anchor_id,
                         "before_behavior": "The idempotency check reused the previous entry.",
                         "citations": [{"id": "project:1", "line": 45}]}
                invalid_anchor = {**valid, "anchor_id": "D9999"}
                invalid_ref = {**valid, "citations": [{"id": "project:1", "line": 44}]}
                return Reply(json.dumps({"findings": [valid, invalid_anchor, invalid_ref]}), 80, 35)
            [candidate] = payload["candidates"]
            self.assertEqual(candidate["evidence"], "persist(row)")
            fields = schema["properties"]["confirmed"]["items"]["properties"]
            self.assertNotIn("quote", fields)
            return Reply(json.dumps({"confirmed": [{"id": candidate["id"]}]}), 60, 10)

        report = run_review(cfg, files, refs, provider=provider)
        self.assertEqual(report["models"]["primary"]["rejected_reasons"],
                         {"unknown_diff_anchor": 1, "unknown_context_line": 1})
        [accepted] = publication_findings(report)
        self.assertEqual((accepted["path"], accepted["line"], accepted["citations"][0]["line"]),
                         ("src/import.py", 5, 45))
        self.assertEqual(report["verification"]["confirmed"], 1)

    def test_legacy_diagnostics_count_only_safe_reason_codes(self):
        cfg, files, refs, issue = self.setup_review()
        invalid = [
            {**issue, "quote": "synthetic raw text that must not be retained"},
            {**issue, "citations": [{**issue["citations"][0], "quote": "Wrong context text"}]},
            {**issue, "trigger": "a" * 801},
        ]

        def provider(model, system, data, timeout):
            return Reply(json.dumps({"findings": invalid}), 50, 30)

        report = run_review(cfg, files, refs, provider=provider)
        self.assertEqual(report["models"]["primary"]["rejected"], 3)
        self.assertEqual(report["models"]["primary"].get("rejected_reasons"),
                         {"diff_quote_mismatch": 1, "context_quote_mismatch": 1, "too_long_trigger": 1})
        self.assertNotIn("synthetic raw text that must not be retained", json.dumps(report))

    def test_context_trace_records_the_same_references_and_rules_used_by_both_reviewers(self):
        cfg, files, refs, issue = self.setup_review(verify_with="critic")
        cfg = replace(cfg, instructions="Global project policy.", rules=(
            (("tests/**",), "This rule does not apply."),
            (("src/**",), "Check that import retries are idempotent."),
        ))
        refs += [Reference("project:2", "project", "a" * 40, "docs/large.md", "x" * 10000)]
        calls = []

        def provider(model, system, data, timeout):
            payload = json.loads(data)
            policy = json.loads(system.rsplit("\nTrusted project policy:\n", 1)[1])
            self.assertEqual(policy["path_instructions"], [{
                "paths": ["src/**"], "instructions": "Check that import retries are idempotent.",
            }])
            calls.append(payload.get("input", payload)["context"])
            if model.id == "primary":
                return Reply(json.dumps({"findings": [issue]}), 50, 30)
            [candidate] = payload["candidates"]
            return Reply(json.dumps({"confirmed": [{"id": candidate["id"], "quote": "persist(row)"}]}), 55, 10)

        report = run_review(cfg, files, refs, provider=provider)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0], calls[1])
        self.assertEqual(report.get("context_trace"), [{
            "batch": 1,
            "diff_paths": ["src/import.py"],
            "references": [{"id": "project:1", "repo": "project", "commit": "a" * 40,
                            "path": "docs/import.md", "start_line": 1, "end_line": 1}],
            "global_instructions": True,
            "rules": [{"index": 2, "patterns": ["src/**"], "matched_paths": ["src/import.py"]}],
            "reviewers": {"primary": "completed"},
            "verifier": {"model": "critic", "status": "completed"},
        }])
        self.assertEqual(run_review(cfg, files, refs, static_only=True)["context_trace"], [])

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

    def test_strict_models_receive_distinct_review_and_confirmation_schemas(self):
        cfg, files, refs, issue = self.setup_review(verify_with="critic")
        cfg = replace(cfg, models=tuple(replace(model, json_schema=True) for model in cfg.models))
        def provider(model, system, data, timeout, *, schema):
            if model.id == "primary":
                self.assertEqual(schema["required"], ["findings"])
                fields = schema["properties"]["findings"]["items"]
                self.assertIn("verification", fields["required"])
                return Reply(json.dumps({"findings": [issue]}), 100, 60)
            self.assertEqual(schema["required"], ["confirmed"])
            [candidate] = json.loads(data)["candidates"]
            return Reply(json.dumps({"confirmed": [{"id": candidate["id"], "quote": "persist(row)"}]}), 30, 8)
        report = run_review(cfg, files, refs, provider=provider)
        self.assertEqual(len(publication_findings(report)), 1)
