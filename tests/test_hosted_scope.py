import json
import unittest

from codemurphy.config import ConfigError, load_config
from codemurphy.diff import parse_patch
from codemurphy.providers import Reply
from codemurphy.review import run_review


class HostedScopeTests(unittest.TestCase):
    def test_provider_gets_only_allowed_code_without_pr_description(self):
        cfg = load_config({
            "models": [{"id": "local", "model": "fixture", "api_key_env": None}],
            "review": {"include": ["app/**"], "exclude": ["app/**/*.test.ts"], "include_pr_text": False},
        })
        files = [
            parse_patch("app/api/route.ts", "@@ -0,0 +1 @@\n+export const status = 200;"),
            parse_patch("app/api/route.test.ts", "@@ -0,0 +1 @@\n+const privateFixture = 'excluded';"),
            parse_patch("data/transactions.csv", "@@ -0,0 +1 @@\n+example financial record"),
        ]
        seen = []

        def provider(model, system, data, timeout):
            seen.append(json.loads(data))
            return Reply('{"findings":[]}', 10, 4)

        report = run_review(cfg, files, pr_text="PR body with a financial reference", provider=provider)
        self.assertEqual(report["coverage"]["excluded_files"], 2)
        [payload] = seen
        self.assertNotIn("pr", payload)
        self.assertEqual({row[0] for row in payload["diff"]}, {"app/api/route.ts"})

    def test_pr_text_flag_must_be_a_boolean(self):
        with self.assertRaisesRegex(ConfigError, "boolean"):
            load_config({"review": {"include_pr_text": "false"}})
