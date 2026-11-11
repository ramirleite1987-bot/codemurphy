from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from contextlib import redirect_stderr
from io import StringIO

from codemurphy.cli import main
from codemurphy.config import ConfigError, load_config

ROOT = Path(__file__).resolve().parents[1]


class CLITests(unittest.TestCase):
    def invoke(self, *args):
        return subprocess.run([sys.executable, "-m", "codemurphy", *args],
                              cwd=ROOT, capture_output=True, text=True, timeout=20)

    def test_staged_review_uses_no_provider_and_enforces_gate(self):
        with tempfile.TemporaryDirectory() as folder:
            def git(*args):
                subprocess.run(["git", "-C", folder, *args], check=True, capture_output=True)
            git("init", "-q")
            git("-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "--allow-empty", "-qm", "base")
            token = "ghp_" + "A1a0" * 9
            (Path(folder) / "job.py").write_text("token = '" + token + "'\n")
            git("add", "job.py")
            report = self.invoke("review", "--repo", folder, "--staged", "--static-only",
                                 "--fail-on", "high", "--format", "json")
            self.assertEqual(report.returncode, 1, report.stderr)
            self.assertNotIn(token, report.stdout)
            [issue] = json.loads(report.stdout)["findings"]
            self.assertEqual(issue["title"], "Possible credential in source")

    def test_benchmark_smoke_can_run_without_credentials(self):
        result = self.invoke("benchmark", "examples/benchmark/suite.json", "--static-only", "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertGreaterEqual(report["case_count"], 6)
        self.assertEqual(len(report["common_cases"]), report["case_count"])
        self.assertEqual(report["candidates"]["static"]["common"]["fp"], 0)
        self.assertGreaterEqual(report["candidates"]["static"]["common"]["tp"], 1)

    def test_reserved_github_token_cannot_be_used_as_a_model_key(self):
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "config.json"
            file.write_text(json.dumps({"models": [{"id": "a", "model": "a",
                                                   "api_key_env": "CODEMURPHY_GITHUB_TOKEN"}]}))
            result = self.invoke("benchmark", "examples/benchmark/suite.json", "--config", str(file))
            self.assertEqual(result.returncode, 2)
            self.assertIn("reserved", result.stderr)

    def test_remote_config_requires_explicit_trust_before_github_access(self):
        for flags in ([], ["--use-base-config"]):
            with self.subTest(flags=flags), patch("codemurphy.cli.GitHub") as client, redirect_stderr(StringIO()):
                self.assertEqual(main(["github", "--repo", "stranger/demo", "--pr", "1", *flags]), 2)
                client.assert_not_called()

    def test_default_provider_credentials_are_bound_to_their_hosts(self):
        with self.assertRaisesRegex(ConfigError, "dedicated"):
            load_config({"models": [{"id": "unsafe", "model": "model",
                                    "base_url": "https://custom.example/v1"}]})
