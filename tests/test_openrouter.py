import unittest
from unittest.mock import patch

from codemurphy.benchmark import evaluate, load_suite
from codemurphy.config import ConfigError, load_config
from codemurphy.providers import ModelError, call


class OpenRouterTests(unittest.TestCase):
    def model(self, **overrides):
        return load_config({"models": [{"id": "router", "provider": "openrouter",
                                        "model": "example/reviewer", **overrides}]}).models[0]

    def test_uses_official_endpoint_and_restricts_provider_routing(self):
        with patch.dict("os.environ", {"OPENROUTER_API_KEY": "synthetic-review-key"}), \
             patch("codemurphy.providers.json_request") as request:
            request.return_value = {
                "model": "example/reviewer-v1",
                "choices": [{"message": {"content": '{"findings":[]}'}}],
                "usage": {"prompt_tokens": 8, "completion_tokens": 4},
            }
            schema = {"type": "object", "required": ["findings"]}
            reply = call(self.model(json_schema=True), "system", "synthetic diff", 5, schema=schema)
        self.assertEqual(reply.resolved_model, "example/reviewer-v1")
        (url,), kwargs = request.call_args
        self.assertEqual(url, "https://openrouter.ai/api/v1/chat/completions")
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer synthetic-review-key")
        self.assertEqual(kwargs["body"]["provider"], {
            "zdr": True, "data_collection": "deny", "require_parameters": True})
        self.assertEqual(kwargs["body"]["response_format"]["json_schema"]["schema"], schema)

    def test_router_rejects_another_host_and_missing_auth_before_network(self):
        with self.assertRaises(ConfigError):
            self.model(base_url="https://example.test/v1")
        with self.assertRaises(ConfigError):
            self.model(api_key_env=None)
        with patch.dict("os.environ", {"OPENROUTER_API_KEY": ""}), \
             patch("codemurphy.providers.json_request") as request:
            with self.assertRaisesRegex(ModelError, "OPENROUTER_API_KEY"):
                call(self.model(), "system", "synthetic diff", 5)
            request.assert_not_called()

    def test_openrouter_key_cannot_be_sent_to_another_compatible_gateway(self):
        with self.assertRaisesRegex(ConfigError, "dedicated API key"):
            self.model(provider="openai-compatible", base_url="https://example.test/v1",
                       api_key_env="OPENROUTER_API_KEY")

    def test_benchmark_uses_reported_charges_separately_from_estimates(self):
        suite = load_suite("examples/benchmark/suite.json")
        cfg = load_config({"models": [{
            "id": label, "model": f"example/{label}", "provider": "openrouter",
            "input_usd_per_million": 1, "output_usd_per_million": 2,
        } for label in ("paid", "free", "unreported")]})

        def transport(url, *, body, **kwargs):
            cost = {"example/paid": 0.000451, "example/free": 0}.get(body["model"])
            return {"choices": [{"message": {"content": '{"findings":[]}'}}],
                    "usage": {"prompt_tokens": 100, "completion_tokens": 10, "cost": cost}}

        with patch.dict("os.environ", {"OPENROUTER_API_KEY": "synthetic-review-key"}), \
             patch("codemurphy.providers.json_request", side_effect=transport):
            report = evaluate(suite, cfg)
        paid, free, unknown = (report["candidates"][k]["common"] for k in ("paid", "free", "unreported"))
        self.assertEqual(paid.get("billed_usd"), 0.000451 * 8)
        self.assertEqual(paid["cost_usd"], 0.00012 * 8)
        self.assertEqual(free.get("billed_usd"), 0)
        self.assertIsNone(unknown.get("billed_usd"))
        self.assertIsNone(report["candidates"]["combined"]["common"].get("billed_usd"))
