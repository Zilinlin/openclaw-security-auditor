"""Tests for static analysis scanners.

These tests verify scanner logic using mock configurations and files.
"""

import tempfile
import os
import unittest
import json
import yaml

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

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
        with open(config_file, 'w') as f:
            yaml.dump({
                "server": {
                    "host": "0.0.0.0",
                    "port": 18789
                }
            }, f)

        result = self.scanner.scan(self.temp_dir)

        # Should find insecure binding
        self.assertTrue(len(result.findings) > 0)
        binding_findings = [f for f in result.findings
                           if "0.0.0.0" in f.description or "bind" in f.description.lower()]
        self.assertTrue(len(binding_findings) > 0)

    def test_detect_auth_disabled(self):
        """Test detection of disabled authentication."""
        config_file = os.path.join(self.temp_dir, "config.yaml")
        with open(config_file, 'w') as f:
            yaml.dump({
                "auth": {
                    "enabled": False,
                    "token": ""
                }
            }, f)

        result = self.scanner.scan(self.temp_dir)

        # Should find auth issue
        auth_findings = [f for f in result.findings
                        if "auth" in f.description.lower()]
        self.assertTrue(len(auth_findings) > 0)

    def test_safe_config(self):
        """Test that safe configuration passes."""
        config_file = os.path.join(self.temp_dir, "config.yaml")
        with open(config_file, 'w') as f:
            yaml.dump({
                "server": {
                    "host": "127.0.0.1",
                    "port": 18789
                },
                "auth": {
                    "enabled": True,
                    "token": "secure_token_12345"
                }
            }, f)

        result = self.scanner.scan(self.temp_dir)

        # Should have minimal findings
        critical_findings = [f for f in result.findings
                            if f.severity == Severity.CRITICAL]
        self.assertEqual(len(critical_findings), 0)


class TestCVEScanner(unittest.TestCase):
    """Tests for CVE Scanner."""

    def setUp(self):
        self.scanner = CVEScanner()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_detect_vulnerable_version(self):
        """Test detection of vulnerable version."""
        # Create version file
        version_file = os.path.join(self.temp_dir, "version.txt")
        with open(version_file, 'w') as f:
            f.write("v2026.1.0")

        result = self.scanner.scan(self.temp_dir)

        # Should find CVE matches for old version
        cve_findings = [f for f in result.findings if "CVE" in f.description]
        self.assertTrue(len(cve_findings) > 0)

    def test_patched_version(self):
        """Test that patched version has no CVE findings."""
        version_file = os.path.join(self.temp_dir, "version.txt")
        with open(version_file, 'w') as f:
            f.write("v2026.3.0")  # After all known CVE fixes

        result = self.scanner.scan(self.temp_dir)

        # Should have no critical CVE findings
        critical_cves = [f for f in result.findings
                        if f.severity == Severity.CRITICAL and "CVE" in f.description]
        self.assertEqual(len(critical_cves), 0)


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
        config_file = os.path.join(self.temp_dir, "config.json")
        with open(config_file, 'w') as f:
            json.dump({
                "openai_api_key": "sk-1234567890abcdef1234567890abcdef",
                "anthropic_key": "sk-ant-1234567890abcdef"
            }, f)

        result = self.scanner.scan(self.temp_dir)

        # Should find API keys
        key_findings = [f for f in result.findings
                       if "key" in f.description.lower() or "secret" in f.description.lower()]
        self.assertTrue(len(key_findings) > 0)

    def test_detect_password(self):
        """Test detection of hardcoded passwords."""
        config_file = os.path.join(self.temp_dir, ".env")
        with open(config_file, 'w') as f:
            f.write('DATABASE_PASSWORD="super_secret_password"\n')
            f.write('API_SECRET="another_secret"\n')

        result = self.scanner.scan(self.temp_dir)

        # Should find secrets
        self.assertTrue(len(result.findings) > 0)

    def test_no_secrets(self):
        """Test that file without secrets passes."""
        config_file = os.path.join(self.temp_dir, "config.json")
        with open(config_file, 'w') as f:
            json.dump({
                "setting": "value",
                "number": 42
            }, f)

        result = self.scanner.scan(self.temp_dir)

        # Should have no secret findings
        secret_findings = [f for f in result.findings
                         if f.severity in [Severity.CRITICAL, Severity.HIGH]]
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


if __name__ == '__main__':
    unittest.main()
