"""Tests for static analysis scanners.

These tests verify scanner logic using mock configurations and files.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from auditor.scanners.base import Severity
from auditor.scanners.config_scanner import ConfigScanner
from auditor.scanners.cve_scanner import CVEScanner
from auditor.scanners.secret_scanner import SecretScanner


class TestConfigScanner(unittest.TestCase):
    """Tests for Configuration Scanner."""

    def setUp(self):
        self.scanner = ConfigScanner()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_detect_insecure_bind(self):
        """Test detection of insecure network binding."""
        config_file = os.path.join(self.temp_dir, "config.yaml")
        with open(config_file, "w") as f:
            # Use format that matches the scanner's regex pattern
            f.write("bind_address: 0.0.0.0\nport: 18789\n")

        result = self.scanner.scan(self.temp_dir)

        # Should find insecure binding
        self.assertTrue(len(result.findings) > 0)
        binding_findings = [f for f in result.findings if "0.0.0.0" in f.title]
        self.assertTrue(len(binding_findings) > 0)

    def test_detect_auth_disabled(self):
        """Test detection of disabled authentication."""
        config_file = os.path.join(self.temp_dir, "config.yaml")
        with open(config_file, "w") as f:
            f.write("auth_enabled: false\nport: 18789\n")

        result = self.scanner.scan(self.temp_dir)

        # Should find auth issue
        auth_findings = [
            f for f in result.findings if "auth" in f.title.lower() or "Authentication" in f.title
        ]
        self.assertTrue(len(auth_findings) > 0)

    def test_safe_config(self):
        """Test that safe configuration passes."""
        config_file = os.path.join(self.temp_dir, "config.yaml")
        with open(config_file, "w") as f:
            f.write(
                "bind_address: 127.0.0.1\n"
                "auth_enabled: true\n"
                "debug: false\n"
                "ssl_enabled: true\n"
            )

        result = self.scanner.scan(self.temp_dir)

        # Should have no critical findings
        critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
        self.assertEqual(len(critical_findings), 0)


class TestCVEScanner(unittest.TestCase):
    """Tests for CVE Scanner."""

    def setUp(self):
        self.scanner = CVEScanner()

    def test_detect_vulnerable_version(self):
        """Test detection of vulnerable version."""
        result = self.scanner.scan(".", version="2026.1.0")

        # Should find CVE matches for old version
        self.assertTrue(len(result.findings) > 0)
        cve_ids = [f.cve for f in result.findings]
        self.assertIn("CVE-2026-25253", cve_ids)

    def test_patched_version(self):
        """Test that patched version has no CVE findings."""
        result = self.scanner.scan(".", version="2026.3.0")

        # Should have no CVE findings
        self.assertEqual(len(result.findings), 0)


class TestSecretScanner(unittest.TestCase):
    """Tests for Secret Scanner."""

    def setUp(self):
        self.scanner = SecretScanner()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_detect_api_key(self):
        """Test detection of exposed API keys."""
        config_file = os.path.join(self.temp_dir, "config.py")
        with open(config_file, "w") as f:
            f.write('OPENAI_API_KEY = "sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012345678"\n')

        result = self.scanner.scan(self.temp_dir)

        # Should find API key
        self.assertTrue(len(result.findings) > 0)
        key_findings = [f for f in result.findings if "key" in f.title.lower() or "Key" in f.title]
        self.assertTrue(len(key_findings) > 0)

    def test_detect_password(self):
        """Test detection of hardcoded passwords."""
        config_file = os.path.join(self.temp_dir, ".env")
        with open(config_file, "w") as f:
            f.write('DATABASE_PASSWORD="super_secret_password"\n')
            f.write('API_SECRET="another_secret_value"\n')

        result = self.scanner.scan(self.temp_dir)

        # Should find secrets
        self.assertTrue(len(result.findings) > 0)

    def test_no_secrets(self):
        """Test that file without secrets passes."""
        config_file = os.path.join(self.temp_dir, "config.json")
        with open(config_file, "w") as f:
            json.dump({"setting": "value", "number": 42}, f)

        result = self.scanner.scan(self.temp_dir)

        # Should have no secret findings
        secret_findings = [
            f for f in result.findings if f.severity in [Severity.CRITICAL, Severity.HIGH]
        ]
        self.assertEqual(len(secret_findings), 0)


class TestSeverity(unittest.TestCase):
    """Tests for Severity enum."""

    def test_severity_ordering(self):
        """Test that severity levels are properly defined."""
        self.assertEqual(Severity.CRITICAL.value, "critical")
        self.assertEqual(Severity.HIGH.value, "high")
        self.assertEqual(Severity.MEDIUM.value, "medium")
        self.assertEqual(Severity.LOW.value, "low")
        self.assertEqual(Severity.INFO.value, "info")


if __name__ == "__main__":
    unittest.main()
