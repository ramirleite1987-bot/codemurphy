from pathlib import Path
import json
import sys
import tempfile
from unittest import TestCase
from unittest.mock import patch
import zipfile

from codemurphy import osv_delta


LOCKFILE = b"lockfileVersion: '9.0'\n"


def package(name, version, vulnerabilities=(), ecosystem="npm"):
    return {
        "package": {"name": name, "version": version, "ecosystem": ecosystem},
        "vulnerabilities": list(vulnerabilities),
        "groups": [{"ids": [vulnerability["id"]]} for vulnerability in vulnerabilities],
    }


class OfflineOSVTests(TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.scanner = self.root / "scanner"
        self.cache = self.root / "cache"
        self.archive = self.cache / "osv-scalibr" / "npm" / "all.zip"
        self.archive.parent.mkdir(parents=True)
        with zipfile.ZipFile(self.archive, "w") as db:
            db.writestr("TEST-0001.json", "{}")

    def executable(self, code):
        self.scanner.write_text(f"#!{sys.executable}\n" + code, encoding="utf-8")
        self.scanner.chmod(0o700)

    def results(self, packages, *, exit_code=0, diagnostic=None):
        self.executable(
            "import json, os, sys\n"
            "from pathlib import Path\n"
            "args = sys.argv[1:]\n"
            "assert args[:2] == ['scan', 'source'] and '--offline' in args\n"
            "assert args[args.index('--format') + 1] == 'json'\n"
            "lockfile = Path(args[args.index('--lockfile') + 1])\n"
            "assert lockfile == Path.cwd() / 'pnpm-lock.yaml'\n"
            f"assert lockfile.read_bytes() == {LOCKFILE!r}\n"
            f"assert os.environ['OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY'] == {str(self.cache)!r}\n"
            "assert 'CODEMURPHY_TEST_CREDENTIAL' not in os.environ\n"
            "source = {'path': str(lockfile), 'type': 'lockfile'}\n"
            f"packages = json.loads({json.dumps(packages)!r})\n"
            "print(json.dumps({'results': [{'source': source, 'packages': packages}]}))\n"
            f"diagnostic = {diagnostic!r}\n"
            "if diagnostic:\n"
            "    print(diagnostic, file=sys.stderr)\n"
            f"sys.exit({exit_code})\n"
        )

    def scan(self, eligible, lockfile=LOCKFILE):
        return osv_delta.scan_offline(self.scanner, self.cache, lockfile, eligible)

    def test_findings_require_exact_approved_npm_name_and_version(self):
        self.results([
            package("demo", "1.0.0", [
                {"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2025-1234"],
                 "details": "advisory text should not be retained"},
            ]),
            package("demo", "1.0.0", [
                {"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2025-1234", "CVE-2025-1235"]},
            ]),
            package("demo", "2.0.0", [{"id": "OSV-old-version"}]),
            package("demo", "1.0.0", [{"id": "OSV-other-ecosystem"}], ecosystem="Go"),
            package("outside-approved-set", "1.0.0", [{"id": "OSV-other-package"}]),
        ], exit_code=1)
        with patch.dict("os.environ", {"CODEMURPHY_TEST_CREDENTIAL": "private"}):
            self.assertEqual(self.scan({("demo", "1.0.0")}), {
                "status": "ok",
                "advisories": [{
                    "package": "demo", "version": "1.0.0", "id": "GHSA-aaaa-bbbb-cccc",
                    "aliases": ["CVE-2025-1234", "CVE-2025-1235"],
                }],
            })

    def test_covered_version_without_advisories_is_clean(self):
        self.results([package("demo", "1.0.0")])
        self.assertEqual(self.scan({("demo", "1.0.0")}), {"status": "ok", "advisories": []})

    def test_partial_inventory_is_not_clean(self):
        self.results([package("demo", "1.0.0")])
        self.assertEqual(self.scan({("demo", "1.0.0"), ("missing", "1.0.0")}), {
            "status": "error", "reason": "incomplete-coverage", "advisories": [],
        })

    def test_invalid_output_is_not_clean(self):
        self.executable("print('{}')\n")
        self.assertEqual(self.scan({("demo", "1.0.0")}), {
            "status": "error", "reason": "invalid-output", "advisories": [],
        })

    def test_scanner_error_is_not_clean_and_diagnostics_are_omitted(self):
        for exit_code, diagnostic in [(127, None), (0, "private lockfile contents")]:
            with self.subTest(exit_code=exit_code):
                self.results([package("demo", "1.0.0")], exit_code=exit_code, diagnostic=diagnostic)
                self.assertEqual(self.scan({("demo", "1.0.0")}), {
                    "status": "error", "reason": "scanner-failed", "advisories": [],
                })

    def test_missing_snapshot_is_not_clean(self):
        self.archive.unlink()
        self.results([package("demo", "1.0.0")])
        self.assertEqual(self.scan({("demo", "1.0.0")}), {
            "status": "error", "reason": "missing-or-invalid-cache", "advisories": [],
        })

    def test_empty_eligible_set_needs_no_scanner(self):
        self.assertEqual(self.scan(set()), {
            "status": "skipped", "reason": "no-eligible-versions", "advisories": [],
        })

    def test_oversized_lockfile_is_rejected_before_scanning(self):
        self.results([package("demo", "1.0.0")])
        with patch.object(osv_delta, "MAX_LOCKFILE_BYTES", 8):
            self.assertEqual(self.scan({("demo", "1.0.0")}), {
                "status": "error", "reason": "lockfile-size-limit", "advisories": [],
            })

    def test_excessive_output_is_stopped(self):
        self.executable("import os, time\nos.write(1, b'x' * 1024)\ntime.sleep(10)\n")
        with patch.object(osv_delta, "MAX_OUTPUT_BYTES", 100):
            self.assertEqual(self.scan({("demo", "1.0.0")}), {
                "status": "error", "reason": "output-size-limit", "advisories": [],
            })

    def test_scan_that_stalls_is_stopped(self):
        self.executable("import time\ntime.sleep(10)\n")
        with patch.object(osv_delta, "TIMEOUT_SECONDS", 0.2):
            self.assertEqual(self.scan({("demo", "1.0.0")}), {
                "status": "error", "reason": "scanner-timeout", "advisories": [],
            })
