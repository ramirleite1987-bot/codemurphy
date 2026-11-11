from contextlib import contextmanager
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from socketserver import TCPServer
import threading
import unittest

from codemurphy.config import load_config
from codemurphy.context import Reference
from codemurphy.diff import parse_patch
from codemurphy.providers import Reply, ModelError, call
from codemurphy.review import run_review


def finding(**changes):
    return {"path": "api.py", "side": "RIGHT", "line": 9, "quote": "load(record)",
            "category": "correctness", "severity": "high", "confidence": .94,
            "title": "Missing record validation", "detail": "An invalid record aborts the batch.",
            "suggestion": "Validate the record before loading it.", **changes}


class ReviewTests(unittest.TestCase):
    def test_same_inputs_and_grounding_per_model(self):
        models = [{"id": "fast", "model": "fake-a", "api_key_env": None,
                   "input_usd_per_million": 1, "output_usd_per_million": 2},
                  {"id": "slow", "model": "fake-b", "api_key_env": None}]
        seen = {}
        def provider(model, system, data, timeout):
            seen[model.id] = (system, data)
            return Reply(json.dumps({"findings": [
                finding(), finding(line=99), finding(quote="invented evidence"),
                finding(citations=[{"id": "invented", "line": 1, "quote": "anything"}])]}), 100, 20)
        report = run_review(load_config({"models": models}),
                            [parse_patch("api.py", "@@ -8,2 +8,2 @@\n # prep\n-old()\n+load(record)")],
                            mode="compare", provider=provider)
        self.assertEqual(seen["fast"], seen["slow"])
        self.assertEqual(report["models"]["fast"]["rejected"], 3)
        self.assertEqual(report["findings"][0]["sources"], ["fast", "slow"])
        self.assertEqual(report["models"]["fast"]["estimated_usd"], .00014)
        self.assertIsNone(report["models"]["slow"]["estimated_usd"])

    def test_private_context_and_credentials_are_not_echoed(self):
        token = "ghp_" + "Aa01" * 9
        cfg = load_config({"models": [{"id": "a", "model": "fake", "api_key_env": None}]})
        def provider(model, system, data, timeout):
            self.assertNotIn(token, data)
            raise ModelError("HTTP 429")
        report = run_review(cfg, [parse_patch("api.py", f"@@ -0,0 +1 @@\n+key = '{token}'")],
                            [Reference("sdk:1", "sdk", "a"*40, "readme.md", "SDK contract", True)],
                            provider=provider)
        self.assertTrue(report["private_context"])
        self.assertEqual(report["models"]["a"]["failed_requests"], 1)
        self.assertIn("HTTP 429", report["models"]["a"]["errors"])
        self.assertNotIn(token, json.dumps(report))
        self.assertEqual(report["findings"][0]["sources"], ["static"])

    def test_path_rules_keep_their_selectors_in_a_mixed_batch(self):
        cfg = load_config({"models": [{"id": "a", "model": "fake", "api_key_env": None}],
                           "review": {"rules": [
                               {"paths": ["api/**"], "instructions": "Empty is invalid."},
                               {"paths": ["batch/**"], "instructions": "Empty is allowed."}]}})
        def provider(model, system, data, timeout):
            policy = json.loads(system.rsplit("Trusted project policy:\n", 1)[1])
            self.assertEqual(policy["path_instructions"], [
                {"paths": ["api/**"], "instructions": "Empty is invalid."},
                {"paths": ["batch/**"], "instructions": "Empty is allowed."}])
            return Reply('{"findings":[]}', 20, 5, "fake-2026-11-11")
        files = [parse_patch(path, "@@ -0,0 +1 @@\n+execute()") for path in ("api/a.py", "batch/b.py")]
        report = run_review(cfg, files, provider=provider)
        self.assertEqual(report["models"]["a"]["resolved_models"], ["fake-2026-11-11"])
        changed = replace(cfg, models=(replace(cfg.models[0], model="fake-next"),))
        self.assertNotEqual(report["config_sha256"], run_review(changed, [], provider=provider)["config_sha256"])

    def test_deleted_lines_and_verified_context_citations(self):
        cfg = load_config({"models": [{"id": "a", "model": "fake", "api_key_env": None}]})
        def provider(model, system, data, timeout):
            item = finding(side="LEFT", line=4, quote="check_access(user)", category="security",
                           citations=[{"id": "sdk:1", "line": 10, "quote": "Access required."}])
            return Reply(json.dumps({"findings": [item]}), 20, 10)
        [issue] = run_review(cfg, [parse_patch("api.py", "@@ -4 +3,0 @@\n-check_access(user)")],
                             [Reference("sdk:1", "sdk", "a"*40, "security.md", "Access required.",
                                        start_line=10)], provider=provider)["findings"]
        self.assertEqual(issue["side"], "LEFT")
        self.assertEqual(issue["citations"][0]["commit"], "a"*40)

    def test_finding_keeps_exact_filename_with_leading_space(self):
        cfg = load_config({"models": [{"id": "a", "model": "fake", "api_key_env": None}]})
        def provider(model, system, data, timeout):
            return Reply(json.dumps({"findings": [finding(path=" api.py")]}), 20, 5)
        report = run_review(cfg, [parse_patch(path, "@@ -8,0 +9 @@\n+load(record)")
                                  for path in (" api.py", "api.py")], provider=provider)
        self.assertEqual(report["findings"][0]["path"], " api.py")

    def test_distinct_issues_on_one_line_are_not_collapsed(self):
        cfg = load_config({"models": [{"id": "a", "model": "fake", "api_key_env": None}]})
        def provider(model, system, data, timeout):
            return Reply(json.dumps({"findings": [
                finding(), finding(title="Wrong error code")]}), 20, 10)
        report = run_review(cfg, [parse_patch("api.py", "@@ -8,0 +9 @@\n+load(record)")], provider=provider)
        self.assertEqual(len(report["findings"]), 2)


class ProviderTests(unittest.TestCase):
    @contextmanager
    def endpoint(self, response, status=200, redirect=None):
        seen = []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                seen.append((self.path, json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
                self.send_response(status)
                if redirect:
                    self.send_header("Location", redirect)
                self.end_headers()
                self.wfile.write(json.dumps(response).encode())
            def log_message(self, *args):
                pass
        class Server(ThreadingHTTPServer):
            def server_bind(self):
                TCPServer.server_bind(self)
                self.server_name, self.server_port = "localhost", self.server_address[1]
        server = Server(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01})
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}/v1", seen
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_both_api_protocols(self):
        payloads = {
            "openai-compatible": ("/v1/chat/completions", {"choices": [{"message": {"content": "{}"}}],
                                 "usage": {"prompt_tokens": 90, "completion_tokens": 10}}),
            "anthropic": ("/v1/messages", {"content": [{"type": "text", "text": "{}"}],
                          "usage": {"input_tokens": 89, "cache_read_input_tokens": 1, "output_tokens": 10}}),
        }
        for name, (path, response) in payloads.items():
            with self.subTest(name=name), self.endpoint(response) as (url, seen):
                model = load_config({"models": [{"id": "a", "provider": name,
                                    "model": "fake", "api_key_env": None, "base_url": url}]}).models[0]
                self.assertEqual(call(model, "system", "input", 5), Reply("{}", 90, 10))
                self.assertEqual(seen[0][0], path)
                self.assertEqual(seen[0][1]["messages"][-1]["content"], "input")

    def test_redirects_and_error_response_bodies_are_not_followed_or_logged(self):
        with self.endpoint({"error": "private-error"}, 307, "http://127.0.0.1:1") as (url, _):
            model = load_config({"models": [{"id": "a", "model": "fake", "base_url": url,
                                            "api_key_env": None}]}).models[0]
            with self.assertRaisesRegex(ModelError, "^HTTP 307$"):
                call(model, "system", "input", 5)
