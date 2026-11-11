from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from codemurphy.config import load_config, ConfigError
from codemurphy.diff import from_unified, parse_patch, make_batches
from codemurphy.context import local_refs, select_refs
from codemurphy.github import github_refs
from codemurphy.redact import redact


class InputsTests(unittest.TestCase):
    def test_add_delete_and_c_quoted_path(self):
        raw = ('diff --git "a/um\\303\\251.py" "b/um\\303\\251.py"\n'
               '--- "a/um\\303\\251.py"\n+++ "b/um\\303\\251.py"\n'
               '@@ -8,2 +8,2 @@\n-old()\n+new()\n # keep\n')
        [file] = from_unified(raw)
        self.assertEqual(file.path, "umé.py")
        self.assertEqual([(x.side, x.number, x.text) for x in file.lines if x.changed],
                         [("LEFT", 8, "old()"), ("RIGHT", 8, "new()")])

    def test_truncated_patch_retains_known_lines_and_reports_partial(self):
        file = parse_patch("api.py", "@@ -1 +1,2 @@\n-old\n+new", expected=3)
        _, coverage = make_batches([file], load_config({"models": []}))
        self.assertTrue(coverage["partial"])
        self.assertEqual(coverage["reviewed_lines"], 2)
        self.assertEqual(coverage["eligible_lines"], 3)

    def test_giant_line_does_not_starve_other_files(self):
        config = load_config({"review": {"chunk_chars": 256, "max_diff_chars": 512}})
        files = [parse_patch("giant.py", "@@ -0,0 +1 @@\n+" + "x"*500),
                 parse_patch("small.py", "@@ -0,0 +1 @@\n+works = True")]
        batches, coverage = make_batches(files, config)
        self.assertEqual([x.path for b in batches for x in b if x.changed], ["small.py"])
        self.assertEqual(coverage["omitted_lines"], 1)

    def test_gitignore_style_root_and_nested_rules(self):
        cfg = load_config({"review": {"exclude": ["**/*.lock"],
            "rules": [{"paths": ["src/*"], "instructions": "Check API compatibility."}]}})
        self.assertTrue(cfg.excluded("uv.lock"))
        self.assertTrue(cfg.excluded("app/build/a.lock"))
        self.assertFalse(cfg.excluded("foo.py"))
        self.assertEqual(cfg.instructions_for(["src/api.py"]), ((("src/*",), "Check API compatibility."),))
        self.assertEqual(cfg.instructions_for(["src/sub/api.py"]), ())

    def test_rejects_unknown_config_and_mutable_linked_ref(self):
        with self.assertRaises(ConfigError):
            load_config({"review": {"max_batch": 20}})
        with self.assertRaises(ConfigError):
            load_config({"context": {"linked": [{"id": "api", "repo": "me/api",
                "commit": "main", "files": ["api.md"]}]}})

    def test_context_is_pinned_and_relevant(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            def git(*args):
                return subprocess.check_output(["git", "-C", temp, *args], text=True).strip()
            git("init", "-q")
            for path, content in [("api.md", "BillingClient invoice schema"), ("other.md", "CSS styles")]:
                (root / path).write_text(content)
            git("add", ".")
            git("-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm", "contract")
            commit = git("rev-parse", "HEAD")
            (root / "api.md").write_text("uncommitted replacement")
            cfg = load_config({"context": {"linked": [{"id": "billing", "local": temp,
                "commit": commit, "files": ["other.md", "api.md"]}]}})
            refs, warnings = local_refs(cfg, root, commit)
            [batch] = make_batches([parse_patch("billing.py", "@@ -0,0 +1 @@\n+BillingClient.invoice()")], cfg)[0]
            ranked = select_refs(refs, batch, 1000)
            self.assertEqual(warnings, [])
            self.assertEqual(ranked[0].path, "api.md")
            self.assertEqual(ranked[0].commit, commit)
            self.assertEqual(ranked[0].text, "BillingClient invoice schema")

    def test_explicit_excerpt_is_pinned_and_only_used_on_matching_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            def git(*args):
                return subprocess.check_output(["git", "-C", temp, *args], text=True).strip()

            git("init", "-q")
            raw = b"unrelated\ndef verify_payment():\n    return cached_result\nother code\n"
            (root / "payment.py").write_bytes(raw)
            (root / "README.md").write_text("retry payment charge")
            git("add", ".")
            git("-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm", "base")
            base = git("rev-parse", "HEAD")
            (root / "payment.py").write_text("uncommitted content")
            cfg = load_config({"context": {"files": ["README.md"], "excerpts": [{
                "path": "payment.py", "anchor": "def verify_payment(", "lines": 2, "applies_to": ["src/billing/**"],
            }, {
                "path": "payment.py", "anchor": "uncommitted content", "lines": 1, "applies_to": ["src/billing/**"],
            }]}})
            refs, warnings = local_refs(cfg, root, base)
            self.assertEqual(len(warnings), 1)
            patch = "@@ -0,0 +1 @@\n+retry_payment_charge()"
            relevant = select_refs(refs, parse_patch("src/billing/job.py", patch).lines, 1000)
            self.assertEqual((relevant[0].path, relevant[0].start_line, relevant[0].text),
                             ("payment.py", 2, "def verify_payment():\n    return cached_result"))
            unrelated = select_refs(refs, parse_patch("src/views/job.py", patch).lines, 1000)
            self.assertEqual([ref.path for ref in unrelated], ["README.md"])
            pull = SimpleNamespace(repo="owner/project", base=base)

            def blob(repo, commit, path):
                self.assertEqual((repo, commit), ("owner/project", base))
                return raw if path == "payment.py" else b"retry payment charge"

            hosted, warnings = github_refs(SimpleNamespace(blob=blob), None, pull, cfg)
            self.assertEqual(len(warnings), 1)
            self.assertEqual([(ref.path, ref.start_line, ref.text) for ref in hosted],
                             [(ref.path, ref.start_line, ref.text) for ref in refs])

    def test_secret_patterns_are_removed(self):
        token = "ghp_" + "Aa01" * 9
        text = "access = '" + token + "'"
        self.assertNotIn(token, redact(text))
        self.assertNotIn("private-body", redact("-----BEGIN RSA PRIVATE KEY-----\nprivate-body\n"
                                                "-----END RSA PRIVATE KEY-----"))
        self.assertIn("[REDACTED]", redact(text))

    def test_prefixed_secret_assignments_are_redacted(self):
        value = "fixtureKeyWithNoVendorPrefix123"
        for line in (f'AWS_SECRET_ACCESS_KEY = "{value}"',
                     f'export AWS_SECRET_ACCESS_KEY={value}',
                     f'  INTERNAL_CLIENT_SECRET: "{value}"'):
            with self.subTest(line=line):
                self.assertNotIn(value, redact(line))

    def test_local_rename_respects_source_path_exclusions(self):
        raw = ('diff --git a/.env b/settings.txt\n'
               'similarity index 80%\nrename from .env\nrename to settings.txt\n'
               '--- a/.env\n+++ b/settings.txt\n'
               '@@ -1,2 +1,2 @@\n SESSION=keep-it-private\n-old\n+new\n')
        batches, coverage = make_batches(from_unified(raw), load_config())
        self.assertEqual(batches, [])
        self.assertEqual(coverage["excluded_files"], 1)
