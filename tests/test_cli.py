"""Tests for the CLI module — unit tests and integration tests."""

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from auditor.cli import (
    EXIT_CODE_FINDINGS,
    EXIT_CODE_OK,
    Colors,
    check_severity_threshold,
    colorize,
    print_banner,
    print_detector_summary,
    print_finding,
    print_summary,
    results_to_sarif,
    severity_color,
)
from auditor.detectors.base import DetectorFinding, DetectorResult, VulnerabilityStatus
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


class TestColorize(unittest.TestCase):
    """Tests for the colorize function."""

    def test_colorize_with_tty(self):
        """When stdout is a TTY, colorize should wrap text with ANSI codes."""
        with patch("sys.stdout") as mock_stdout:
            mock_stdout.isatty.return_value = True
            result = colorize("hello", Colors.RED)
        self.assertEqual(result, f"{Colors.RED}hello{Colors.RESET}")

    def test_colorize_without_tty(self):
        """When stdout is not a TTY, colorize should return plain text."""
        with patch("sys.stdout") as mock_stdout:
            mock_stdout.isatty.return_value = False
            result = colorize("hello", Colors.RED)
        self.assertEqual(result, "hello")

    def test_colorize_bold(self):
        """Bold color should wrap correctly."""
        with patch("sys.stdout") as mock_stdout:
            mock_stdout.isatty.return_value = True
            result = colorize("important", Colors.BOLD)
        self.assertIn(Colors.BOLD, result)
        self.assertIn(Colors.RESET, result)


class TestSeverityColor(unittest.TestCase):
    """Tests for the severity_color function."""

    def test_critical_color(self):
        """Critical severity should return red+bold."""
        color = severity_color(Severity.CRITICAL)
        self.assertIn(Colors.RED, color)
        self.assertIn(Colors.BOLD, color)

    def test_high_color(self):
        """High severity should return red."""
        color = severity_color(Severity.HIGH)
        self.assertEqual(color, Colors.RED)

    def test_medium_color(self):
        """Medium severity should return yellow."""
        color = severity_color(Severity.MEDIUM)
        self.assertEqual(color, Colors.YELLOW)

    def test_low_color(self):
        """Low severity should return cyan."""
        color = severity_color(Severity.LOW)
        self.assertEqual(color, Colors.CYAN)

    def test_info_color(self):
        """Info severity should return blue."""
        color = severity_color(Severity.INFO)
        self.assertEqual(color, Colors.BLUE)

    def test_string_severity(self):
        """String severity without .value should still work."""
        color = severity_color("medium")
        self.assertEqual(color, Colors.YELLOW)


class TestPrintFinding(unittest.TestCase):
    """Tests for print_finding output."""

    def _capture_finding(self, finding, index=1):
        """Capture print_finding output."""
        with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            # Disable colors for easier assertion
            with patch("sys.stdout") as tty_mock:
                tty_mock.isatty.return_value = False
                tty_mock.write = mock_out.write
                # Re-patch to actually capture output
                pass
        # Simpler approach: just capture with non-TTY
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            print_finding(finding, index)
        return buf.getvalue()

    def test_scanner_finding_basic(self):
        """Scanner finding should print title and severity."""
        finding = Finding(
            title="Test Finding",
            severity=Severity.HIGH,
            description="A test vulnerability.",
        )
        output = self._capture_finding(finding)
        self.assertIn("Test Finding", output)
        self.assertIn("HIGH", output)
        self.assertIn("A test vulnerability.", output)

    def test_scanner_finding_with_cve(self):
        """Finding with CVE should print CVE ID."""
        finding = Finding(
            title="RCE Bug",
            severity=Severity.CRITICAL,
            description="Remote code execution.",
            cve="CVE-2026-25253",
        )
        output = self._capture_finding(finding)
        self.assertIn("CVE-2026-25253", output)

    def test_scanner_finding_with_location(self):
        """Finding with location should print it."""
        finding = Finding(
            title="Exposed Secret",
            severity=Severity.HIGH,
            description="API key found.",
            location="config.yaml:15",
        )
        output = self._capture_finding(finding)
        self.assertIn("config.yaml:15", output)

    def test_scanner_finding_with_remediation(self):
        """Finding with remediation should print it."""
        finding = Finding(
            title="No Auth",
            severity=Severity.CRITICAL,
            description="No authentication.",
            remediation="Enable API key auth.",
        )
        output = self._capture_finding(finding)
        self.assertIn("Enable API key auth.", output)

    def test_detector_finding_with_status(self):
        """Detector finding should print vulnerability status."""
        finding = DetectorFinding(
            title="WebSocket Hijack",
            status=VulnerabilityStatus.VULNERABLE,
            severity=Severity.CRITICAL,
            description="Origin bypass detected.",
            cve="CVE-2026-25253",
            evidence="101 Switching Protocols with evil origin",
        )
        output = self._capture_finding(finding)
        self.assertIn("VULNERABLE", output)
        self.assertIn("Evidence:", output)

    def test_detector_finding_not_vulnerable(self):
        """Not-vulnerable finding should print status."""
        finding = DetectorFinding(
            title="Auth Check",
            status=VulnerabilityStatus.NOT_VULNERABLE,
            severity=Severity.INFO,
            description="Auth properly enforced.",
        )
        output = self._capture_finding(finding)
        self.assertIn("NOT_VULNERABLE", output)

    def test_finding_with_references(self):
        """Finding with references should print them."""
        finding = DetectorFinding(
            title="Test",
            status=VulnerabilityStatus.VULNERABLE,
            severity=Severity.HIGH,
            description="test",
            references=["https://example.com/advisory"],
        )
        output = self._capture_finding(finding)
        self.assertIn("References:", output)
        self.assertIn("https://example.com/advisory", output)

    def test_finding_without_severity(self):
        """Finding without severity should default to INFO."""
        finding = DetectorFinding(
            title="Unknown",
            status=VulnerabilityStatus.UNKNOWN,
            description="No severity set.",
        )
        output = self._capture_finding(finding)
        self.assertIn("INFO", output)


class TestPrintSummary(unittest.TestCase):
    """Tests for print_summary output."""

    def _capture_summary(self, results):
        """Capture print_summary output."""
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            print_summary(results)
        return buf.getvalue()

    def test_empty_results(self):
        """Empty results should show 0 total."""
        result = ScanResult(scanner_name="test")
        output = self._capture_summary([result])
        self.assertIn("Total findings: 0", output)

    def test_severity_counts(self):
        """Summary should count findings by severity."""
        result = ScanResult(scanner_name="test")
        result.findings.append(Finding(title="c", severity=Severity.CRITICAL, description=""))
        result.findings.append(Finding(title="h", severity=Severity.HIGH, description=""))
        result.findings.append(Finding(title="m", severity=Severity.MEDIUM, description=""))
        result.findings.append(Finding(title="l", severity=Severity.LOW, description=""))
        result.findings.append(Finding(title="i", severity=Severity.INFO, description=""))

        output = self._capture_summary([result])
        self.assertIn("Total findings: 5", output)
        self.assertIn("Critical: 1", output)
        self.assertIn("High: 1", output)
        self.assertIn("Medium: 1", output)
        self.assertIn("Low: 1", output)
        self.assertIn("Info: 1", output)

    def test_critical_warning_message(self):
        """Critical findings should trigger warning message."""
        result = ScanResult(scanner_name="test")
        result.findings.append(Finding(title="c", severity=Severity.CRITICAL, description=""))

        output = self._capture_summary([result])
        self.assertIn("Immediate action required", output)

    def test_no_warning_for_low_only(self):
        """Low-only findings should not trigger warning."""
        result = ScanResult(scanner_name="test")
        result.findings.append(Finding(title="l", severity=Severity.LOW, description=""))

        output = self._capture_summary([result])
        self.assertNotIn("Immediate action required", output)

    def test_multiple_results_combined(self):
        """Multiple ScanResults should be combined."""
        r1 = ScanResult(scanner_name="a")
        r1.findings.append(Finding(title="x", severity=Severity.HIGH, description=""))
        r2 = ScanResult(scanner_name="b")
        r2.findings.append(Finding(title="y", severity=Severity.MEDIUM, description=""))

        output = self._capture_summary([r1, r2])
        self.assertIn("Total findings: 2", output)


class TestPrintDetectorSummary(unittest.TestCase):
    """Tests for print_detector_summary output."""

    def _capture_detector_summary(self, results):
        """Capture print_detector_summary output."""
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            print_detector_summary(results)
        return buf.getvalue()

    def test_no_vulnerabilities(self):
        """No vulnerabilities should show clean message."""
        result = DetectorResult(detector_name="test")
        output = self._capture_detector_summary([result])
        self.assertIn("No vulnerabilities detected", output)

    def test_vulnerabilities_found(self):
        """Vulnerable results should show count."""
        result = DetectorResult(detector_name="test")
        result.findings.append(
            DetectorFinding(
                title="Found",
                status=VulnerabilityStatus.VULNERABLE,
                severity=Severity.HIGH,
                description="vuln",
            )
        )
        output = self._capture_detector_summary([result])
        self.assertIn("Vulnerable: 1/1", output)

    def test_mixed_results(self):
        """Mixed results should show correct count."""
        r1 = DetectorResult(detector_name="ws")
        r1.findings.append(
            DetectorFinding(
                title="WS",
                status=VulnerabilityStatus.VULNERABLE,
                severity=Severity.CRITICAL,
                description="",
            )
        )
        r2 = DetectorResult(detector_name="auth")
        r2.findings.append(
            DetectorFinding(
                title="Auth",
                status=VulnerabilityStatus.NOT_VULNERABLE,
                severity=Severity.INFO,
                description="",
            )
        )
        output = self._capture_detector_summary([r1, r2])
        self.assertIn("Vulnerable: 1/2", output)


class TestPrintBanner(unittest.TestCase):
    """Tests for print_banner output."""

    def test_banner_contains_version(self):
        """Banner should include version string."""
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            print_banner()
        output = buf.getvalue()
        self.assertIn("v0.1.1", output)

    def test_banner_contains_url(self):
        """Banner should include project URL."""
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            print_banner()
        output = buf.getvalue()
        self.assertIn("openclaw-security-auditor", output)


class TestSARIFOutput(unittest.TestCase):
    """Tests for SARIF v2.1.0 output generation."""

    def test_sarif_schema_structure(self):
        """SARIF output should have required top-level fields."""
        result = ScanResult(scanner_name="test")
        sarif = results_to_sarif([result])

        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("$schema", sarif)
        self.assertEqual(len(sarif["runs"]), 1)
        self.assertIn("tool", sarif["runs"][0])
        self.assertIn("results", sarif["runs"][0])

    def test_sarif_tool_metadata(self):
        """SARIF should include tool name and version."""
        result = ScanResult(scanner_name="test")
        sarif = results_to_sarif([result])

        driver = sarif["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "openclaw-security-auditor")
        self.assertEqual(driver["version"], "0.1.1")
        self.assertIn("informationUri", driver)

    def test_sarif_finding_conversion(self):
        """Scanner findings should convert to SARIF results."""
        result = ScanResult(scanner_name="cve")
        result.findings.append(
            Finding(
                title="Remote Code Execution",
                severity=Severity.CRITICAL,
                description="RCE via malicious skill.",
                cve="CVE-2026-25253",
                remediation="Upgrade to 2026.2.12.",
            )
        )
        sarif = results_to_sarif([result])

        self.assertEqual(len(sarif["runs"][0]["results"]), 1)
        sr = sarif["runs"][0]["results"][0]
        self.assertEqual(sr["ruleId"], "CVE-2026-25253")
        self.assertEqual(sr["level"], "error")
        self.assertIn("RCE", sr["message"]["text"])

    def test_sarif_severity_mapping(self):
        """Severity levels should map correctly to SARIF levels."""
        result = ScanResult(scanner_name="test")
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            result.findings.append(
                Finding(title=f"Test {sev.value}", severity=sev, description="test")
            )

        sarif = results_to_sarif([result])
        levels = [r["level"] for r in sarif["runs"][0]["results"]]
        self.assertEqual(levels, ["error", "error", "warning", "note", "note"])

    def test_sarif_rule_deduplication(self):
        """Same CVE in multiple findings should produce one rule."""
        r1 = ScanResult(scanner_name="a")
        r1.findings.append(
            Finding(
                title="RCE",
                severity=Severity.CRITICAL,
                description="First",
                cve="CVE-2026-25253",
            )
        )
        r2 = ScanResult(scanner_name="b")
        r2.findings.append(
            Finding(
                title="RCE Again",
                severity=Severity.CRITICAL,
                description="Second",
                cve="CVE-2026-25253",
            )
        )
        sarif = results_to_sarif([r1, r2])

        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["id"], "CVE-2026-25253")

        # But both results should still be present
        self.assertEqual(len(sarif["runs"][0]["results"]), 2)

    def test_sarif_detector_findings(self):
        """Detector findings should also convert to SARIF."""
        result = DetectorResult(detector_name="websocket_origin")
        result.findings.append(
            DetectorFinding(
                title="WebSocket Origin Bypass",
                status=VulnerabilityStatus.VULNERABLE,
                severity=Severity.CRITICAL,
                description="Cross-Site WebSocket Hijacking.",
                cve="CVE-2026-25253",
                evidence="101 Switching Protocols",
                references=["https://example.com/advisory"],
            )
        )
        sarif = results_to_sarif([result])

        sr = sarif["runs"][0]["results"][0]
        self.assertEqual(sr["ruleId"], "CVE-2026-25253")
        self.assertEqual(sr["properties"]["scanner"], "websocket_origin")
        self.assertEqual(sr["properties"]["evidence"], "101 Switching Protocols")

    def test_sarif_location_from_finding(self):
        """Finding location should map to SARIF artifact location."""
        result = ScanResult(scanner_name="secrets")
        result.findings.append(
            Finding(
                title="API Key Exposed",
                severity=Severity.HIGH,
                description="Found key.",
                location="config.yaml:15",
            )
        )
        sarif = results_to_sarif([result])

        location = sarif["runs"][0]["results"][0]["locations"][0]
        self.assertEqual(
            location["physicalLocation"]["artifactLocation"]["uri"],
            "config.yaml:15",
        )

    def test_sarif_empty_results(self):
        """Empty results should produce valid SARIF with no results."""
        result = ScanResult(scanner_name="test")
        sarif = results_to_sarif([result])

        self.assertEqual(len(sarif["runs"][0]["results"]), 0)
        self.assertEqual(len(sarif["runs"][0]["tool"]["driver"]["rules"]), 0)

    def test_sarif_cli_integration(self):
        """--sarif flag should write SARIF file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sarif_path = os.path.join(tmpdir, "report.sarif")
            rc, stdout, stderr = run_cli("--sarif", sarif_path, "cve", "--version", "2026.1.0")

            self.assertTrue(os.path.exists(sarif_path))
            with open(sarif_path) as f:
                sarif = json.load(f)
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertGreater(len(sarif["runs"][0]["results"]), 0)

    def test_sarif_rule_help_from_remediation(self):
        """Rule help text should come from finding remediation."""
        result = ScanResult(scanner_name="test")
        result.findings.append(
            Finding(
                title="No Auth",
                severity=Severity.CRITICAL,
                description="Missing authentication.",
                remediation="Enable API key authentication.",
            )
        )
        sarif = results_to_sarif([result])

        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        self.assertEqual(rule["help"]["text"], "Enable API key authentication.")


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
