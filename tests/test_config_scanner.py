"""Tests for configuration scanner."""

import tempfile
import unittest
from pathlib import Path

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from auditor.scanners.config_scanner import ConfigScanner
from auditor.scanners.base import Severity


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
            critical_findings = [
                f for f in result.findings if f.severity == Severity.CRITICAL
            ]
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
                f for f in result.findings
                if f.severity in (Severity.CRITICAL, Severity.HIGH)
            ]
            self.assertEqual(len(serious_findings), 0)

    def test_scan_nonexistent_path(self):
        """Test scanning a non-existent path."""
        scanner = ConfigScanner()
        result = scanner.scan("/nonexistent/path")

        self.assertTrue(len(result.errors) > 0)


if __name__ == '__main__':
    unittest.main()
