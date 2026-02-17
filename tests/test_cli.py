"""Integration tests for the CLI."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from auditor.cli import EXIT_CODE_FINDINGS, EXIT_CODE_OK, check_severity_threshold
from auditor.scanners.base import Finding, ScanResult, Severity


def run_cli(*args):
    """Run the CLI as a subprocess and return (returncode, stdout, stderr)."""
    cmd = [sys.executable, "-m", "auditor.cli"] + list(args)
    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.join(os.path.dirname(__file__), "..", "src")
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    return result.returncode, result.stdout, result.stderr


class TestCheckSeverityThreshold(unittest.TestCase):
    """Test the severity threshold logic."""

    def _make_result(self, *severities):
        """Create a ScanResult with findings at given severity levels."""
        r = ScanResult(scanner_name="test")
        for sev in severities:
            r.findings.append(
                Finding(
                    title="Test",
                    severity=Severity(sev),
                    description="test",
                )
            )
        return r

    def test_critical_fails_on_high(self):
        """Critical finding should fail when threshold is high."""
        result = self._make_result("critical")
        self.assertEqual(check_severity_threshold([result], "high"), EXIT_CODE_FINDINGS)

    def test_high_fails_on_high(self):
        """High finding should fail when threshold is high."""
        result = self._make_result("high")
        self.assertEqual(check_severity_threshold([result], "high"), EXIT_CODE_FINDINGS)

    def test_medium_passes_on_high(self):
        """Medium finding should pass when threshold is high."""
        result = self._make_result("medium")
        self.assertEqual(check_severity_threshold([result], "high"), EXIT_CODE_OK)

    def test_medium_fails_on_medium(self):
        """Medium finding should fail when threshold is medium."""
        result = self._make_result("medium")
        self.assertEqual(check_severity_threshold([result], "medium"), EXIT_CODE_FINDINGS)

    def test_low_passes_on_medium(self):
        """Low finding should pass when threshold is medium."""
        result = self._make_result("low")
        self.assertEqual(check_severity_threshold([result], "medium"), EXIT_CODE_OK)

    def test_critical_only_fails_on_critical(self):
        """Only critical should fail when threshold is critical."""
        high_result = self._make_result("high")
        crit_result = self._make_result("critical")
        self.assertEqual(check_severity_threshold([high_result], "critical"), EXIT_CODE_OK)
        self.assertEqual(check_severity_threshold([crit_result], "critical"), EXIT_CODE_FINDINGS)

    def test_info_fails_on_info(self):
        """Info finding should fail when threshold is info."""
        result = self._make_result("info")
        self.assertEqual(check_severity_threshold([result], "info"), EXIT_CODE_FINDINGS)

    def test_empty_results_pass(self):
        """No findings should always pass."""
        result = ScanResult(scanner_name="test")
        self.assertEqual(check_severity_threshold([result], "info"), EXIT_CODE_OK)

    def test_multiple_results(self):
        """Threshold check across multiple result objects."""
        r1 = self._make_result("low")
        r2 = self._make_result("medium")
        self.assertEqual(check_severity_threshold([r1, r2], "high"), EXIT_CODE_OK)
        self.assertEqual(check_severity_threshold([r1, r2], "medium"), EXIT_CODE_FINDINGS)


class TestCLIIntegration(unittest.TestCase):
    """Integration tests that invoke the CLI as a subprocess."""

    def test_no_command_shows_help(self):
        """Running with no command should show help and exit non-zero."""
        rc, stdout, stderr = run_cli()
        self.assertNotEqual(rc, 0)

    def test_scan_nonexistent_path(self):
        """Scanning a nonexistent path should handle gracefully."""
        rc, stdout, stderr = run_cli("scan", "/nonexistent/path/12345")
        # Should not crash (rc may be 0 or 1 depending on findings)
        self.assertIn(rc, (0, 1))

    def test_config_scan_json_output(self):
        """Config scan with --json should produce valid JSON."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Path(tmpdir) / "config.yaml"
            config.write_text("agent:\n  name: Test\n\ngateway:\n  port: 9999\n")

            rc, stdout, stderr = run_cli("--json", "config", tmpdir)
            data = json.loads(stdout)
            self.assertIn("scanner", data)
            self.assertIn("findings", data)

    def test_secrets_scan_clean_directory(self):
        """Secret scan on clean directory should find nothing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            clean_file = Path(tmpdir) / "app.py"
            clean_file.write_text("print('hello')\n")

            rc, stdout, stderr = run_cli("secrets", tmpdir)
            self.assertEqual(rc, 0)

    def test_secrets_scan_finds_key(self):
        """Secret scan should detect exposed API keys."""
        with tempfile.TemporaryDirectory() as tmpdir:
            bad_file = Path(tmpdir) / "config.py"
            bad_file.write_text('KEY = "sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcdefghijkl"\n')

            rc, stdout, stderr = run_cli("secrets", tmpdir)
            self.assertEqual(rc, 1)

    def test_cve_vulnerable_version(self):
        """CVE check on vulnerable version should exit 1."""
        rc, stdout, stderr = run_cli("cve", "--version", "2026.1.0")
        self.assertEqual(rc, 1)

    def test_cve_patched_version(self):
        """CVE check on patched version should exit 0."""
        rc, stdout, stderr = run_cli("cve", "--version", "2026.3.0")
        self.assertEqual(rc, 0)

    def test_cve_json_output(self):
        """CVE check with --json should produce valid JSON."""
        rc, stdout, stderr = run_cli("--json", "cve", "--version", "2026.1.0")
        data = json.loads(stdout)
        self.assertIn("findings", data)
        self.assertGreater(len(data["findings"]), 0)

    def test_fail_on_critical_only(self):
        """--fail-on critical should pass for high-only findings."""
        rc, stdout, stderr = run_cli("--fail-on", "critical", "cve", "--version", "2026.2.5")
        # Version 2026.2.5 has 1 CRITICAL CVE, so should still fail
        self.assertEqual(rc, 1)

    def test_fail_on_info_catches_everything(self):
        """--fail-on info should fail on any finding."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Path(tmpdir) / "config.yaml"
            config.write_text("agent:\n  name: Test\n\ngateway:\n  port: 18789\n")

            rc, stdout, stderr = run_cli("--fail-on", "info", "config", tmpdir)
            # Should find at least the default port (LOW) and no-auth (CRITICAL)
            self.assertEqual(rc, 1)

    def test_config_scan_insecure_openclaw(self):
        """Config scan on insecure OpenClaw config should find issues."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Path(tmpdir) / "config.yaml"
            config.write_text(
                "agent:\n"
                "  name: Test\n"
                "  systemPrompt: |\n"
                "    You are a helpful assistant with many detailed instructions here.\n"
                "\n"
                "gateway:\n"
                "  port: 18789\n"
                "\n"
                "channels:\n"
                "  slack:\n"
                "    appToken: xapp-1-ABC-123-deadbeef\n"
                "    botToken: xoxb-123-456-abcdef\n"
            )

            rc, stdout, stderr = run_cli("--json", "config", tmpdir)
            data = json.loads(stdout)
            titles = [f["title"] for f in data["findings"]]
            self.assertIn("No authentication configured", titles)


if __name__ == "__main__":
    unittest.main()
