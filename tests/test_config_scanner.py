"""Tests for configuration scanner."""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from auditor.scanners.base import Severity
from auditor.scanners.config_scanner import ConfigScanner


class TestConfigScanner(unittest.TestCase):
    """Test cases for ConfigScanner."""

    def test_detect_bind_all_interfaces(self):
        """Test detection of binding to 0.0.0.0."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.yaml"
            config_file.write_text("bind_address: 0.0.0.0\nport: 18789")

            scanner = ConfigScanner()
            result = scanner.scan(tmpdir)

            self.assertGreaterEqual(len(result.findings), 1)
            critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
            self.assertTrue(any("0.0.0.0" in f.title for f in critical_findings))

    def test_detect_auth_disabled(self):
        """Test detection of disabled authentication."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.yaml"
            config_file.write_text("auth_enabled: false\nport: 18789")

            scanner = ConfigScanner()
            result = scanner.scan(tmpdir)

            self.assertGreaterEqual(len(result.findings), 1)
            self.assertTrue(any("Authentication disabled" in f.title for f in result.findings))

    def test_detect_debug_mode(self):
        """Test detection of debug mode."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.yaml"
            config_file.write_text("debug: true\nport: 8080")

            scanner = ConfigScanner()
            result = scanner.scan(tmpdir)

            self.assertTrue(any("Debug mode" in f.title for f in result.findings))

    def test_detect_weak_password(self):
        """Test detection of weak admin password."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.yaml"
            config_file.write_text("admin_password: admin\nport: 8080")

            scanner = ConfigScanner()
            result = scanner.scan(tmpdir)

            self.assertTrue(any("Weak admin password" in f.title for f in result.findings))

    def test_no_findings_for_secure_config(self):
        """Test that secure configurations don't trigger false positives."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.yaml"
            config_file.write_text(
                "bind_address: 127.0.0.1\n"
                "auth_enabled: true\n"
                "debug: false\n"
                "ssl_enabled: true\n"
            )

            scanner = ConfigScanner()
            result = scanner.scan(tmpdir)

            serious_findings = [
                f for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
            ]
            self.assertEqual(len(serious_findings), 0)

    def test_scan_nonexistent_path(self):
        """Test scanning a non-existent path."""
        scanner = ConfigScanner()
        result = scanner.scan("/nonexistent/path")

        self.assertTrue(len(result.errors) > 0)


class TestConfigScannerYAML(unittest.TestCase):
    """Test OpenClaw YAML structure checks."""

    OPENCLAW_CONFIG_INSECURE = (
        "agent:\n"
        "  name: TestAgent\n"
        "  systemPrompt: |\n"
        "    You are a helpful AI assistant that does many things.\n"
        "    You have a lot of instructions that are quite long and detailed.\n"
        "\n"
        "gateway:\n"
        "  port: 18789\n"
        "  mode: local\n"
        "\n"
        "channels:\n"
        "  slack:\n"
        "    enabled: true\n"
        "    mode: socket\n"
        '    appToken: "xapp-1-ABC-123-deadbeef"\n'
        '    botToken: "xoxb-123-456-abcdef"\n'
    )

    OPENCLAW_CONFIG_SECURE = (
        "agent:\n"
        "  name: TestAgent\n"
        "  systemPromptFile: ./SOUL.md\n"
        "\n"
        "gateway:\n"
        "  port: 9999\n"
        "  mode: local\n"
        "  allowedOrigins:\n"
        "    - https://myapp.example.com\n"
        "\n"
        "auth:\n"
        "  enabled: true\n"
        "  apiKey: ${API_KEY}\n"
        "\n"
        "channels:\n"
        "  slack:\n"
        "    enabled: true\n"
        "    mode: socket\n"
    )

    def test_detect_no_auth_section(self):
        """Test detection of missing auth config in OpenClaw YAML."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.yaml"
            config_file.write_text(self.OPENCLAW_CONFIG_INSECURE)

            scanner = ConfigScanner()
            result = scanner.scan(tmpdir)

            titles = [f.title for f in result.findings]
            self.assertIn("No authentication configured", titles)

    def test_detect_system_prompt_in_config(self):
        """Test detection of system prompt stored in config."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.yaml"
            config_file.write_text(self.OPENCLAW_CONFIG_INSECURE)

            scanner = ConfigScanner()
            result = scanner.scan(tmpdir)

            titles = [f.title for f in result.findings]
            self.assertIn("System prompt exposed in config file", titles)

    def test_detect_slack_tokens_in_config(self):
        """Test detection of Slack tokens in config."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.yaml"
            config_file.write_text(self.OPENCLAW_CONFIG_INSECURE)

            scanner = ConfigScanner()
            result = scanner.scan(tmpdir)

            titles = [f.title for f in result.findings]
            self.assertIn("Slack tokens stored in plaintext config", titles)

    def test_detect_no_cors_origin(self):
        """Test detection of missing CORS/origin config."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.yaml"
            config_file.write_text(self.OPENCLAW_CONFIG_INSECURE)

            scanner = ConfigScanner()
            result = scanner.scan(tmpdir)

            titles = [f.title for f in result.findings]
            self.assertIn("No WebSocket origin validation configured", titles)

    def test_detect_default_port(self):
        """Test detection of default gateway port."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.yaml"
            config_file.write_text(self.OPENCLAW_CONFIG_INSECURE)

            scanner = ConfigScanner()
            result = scanner.scan(tmpdir)

            titles = [f.title for f in result.findings]
            self.assertIn("Default gateway port in use", titles)

    def test_secure_config_no_yaml_findings(self):
        """Test that secure OpenClaw config has no critical/high findings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.yaml"
            config_file.write_text(self.OPENCLAW_CONFIG_SECURE)

            scanner = ConfigScanner()
            result = scanner.scan(tmpdir)

            serious = [
                f for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
            ]
            self.assertEqual(len(serious), 0)

    def test_non_openclaw_yaml_skips_checks(self):
        """Test that non-OpenClaw YAML files skip structural checks."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.yaml"
            config_file.write_text("database:\n  host: localhost\n  port: 5432\n")

            scanner = ConfigScanner()
            result = scanner.scan(tmpdir)

            # Should not have OpenClaw-specific findings
            openclaw_titles = {c["title"] for c in scanner.YAML_CHECKS}
            for f in result.findings:
                self.assertNotIn(f.title, openclaw_titles)

    def test_cve_in_findings(self):
        """Test that CVE IDs are included in relevant findings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.yaml"
            config_file.write_text(self.OPENCLAW_CONFIG_INSECURE)

            scanner = ConfigScanner()
            result = scanner.scan(tmpdir)

            auth_finding = next(
                (f for f in result.findings if f.title == "No authentication configured"),
                None,
            )
            self.assertIsNotNone(auth_finding)
            self.assertEqual(auth_finding.cve, "CVE-2026-25157")

    def test_invalid_yaml_gracefully_handled(self):
        """Test that invalid YAML doesn't crash the scanner."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.yaml"
            config_file.write_text("agent:\n  name: [invalid\n  :")

            scanner = ConfigScanner()
            scanner.scan(tmpdir)
            # Should not raise, may or may not have findings from regex


if __name__ == "__main__":
    unittest.main()
