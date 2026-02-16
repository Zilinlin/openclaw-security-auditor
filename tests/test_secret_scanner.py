"""Tests for secret scanner."""

import tempfile
import unittest
from pathlib import Path

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from auditor.scanners.secret_scanner import SecretScanner
from auditor.scanners.base import Severity


class TestSecretScanner(unittest.TestCase):
    """Test cases for SecretScanner."""

    def test_detect_openai_key(self):
        """Test detection of OpenAI API key."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.py"
            # OpenAI key pattern requires exactly 48 alphanumeric chars after "sk-"
            config_file.write_text(
                'OPENAI_API_KEY = "sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcdefghijkl"'
            )

            scanner = SecretScanner()
            result = scanner.scan(tmpdir)

            self.assertGreaterEqual(len(result.findings), 1)
            self.assertTrue(any("OpenAI" in f.title for f in result.findings))

    def test_detect_aws_key(self):
        """Test detection of AWS access key."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / ".env"
            config_file.write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")

            scanner = SecretScanner()
            result = scanner.scan(tmpdir)

            self.assertGreaterEqual(len(result.findings), 1)
            self.assertTrue(any("AWS" in f.title for f in result.findings))

    def test_detect_private_key(self):
        """Test detection of private key."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Use .py extension since .pem is not in SCAN_EXTENSIONS
            key_file = Path(tmpdir) / "keys.py"
            key_file.write_text(
                'PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----\n'
                "MIIEowIBAAKCAQEA...\n"
                '-----END RSA PRIVATE KEY-----"""'
            )

            scanner = SecretScanner()
            result = scanner.scan(tmpdir)

            self.assertGreaterEqual(len(result.findings), 1)
            self.assertTrue(any("Private Key" in f.title for f in result.findings))

    def test_detect_database_url(self):
        """Test detection of database connection string."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "settings.py"
            config_file.write_text(
                'DATABASE_URL = "postgres://user:password123@localhost:5432/mydb"'
            )

            scanner = SecretScanner()
            result = scanner.scan(tmpdir)

            self.assertGreaterEqual(len(result.findings), 1)
            self.assertTrue(any("Database" in f.title for f in result.findings))

    def test_skip_example_files(self):
        """Test that example files are skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            example_file = Path(tmpdir) / ".env.example"
            example_file.write_text(
                'OPENAI_API_KEY = "sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012345678"'
            )

            scanner = SecretScanner()
            result = scanner.scan(tmpdir)

            # Should not find anything in example file
            self.assertEqual(len(result.findings), 0)

    def test_secret_redaction(self):
        """Test that secrets are properly redacted in output."""
        scanner = SecretScanner()

        redacted = scanner._redact_secret("sk-1234567890abcdefghij")
        self.assertIn("sk-1", redacted)
        self.assertIn("****" if "****" in redacted else "*", redacted)
        self.assertNotIn("1234567890abcdef", redacted)

    def test_no_false_positives_in_clean_code(self):
        """Test that clean code doesn't trigger false positives."""
        with tempfile.TemporaryDirectory() as tmpdir:
            clean_file = Path(tmpdir) / "app.py"
            clean_file.write_text(
                "import os\n"
                "API_KEY = os.environ.get('API_KEY')\n"
                "print('Hello World')\n"
            )

            scanner = SecretScanner()
            result = scanner.scan(tmpdir)

            critical_findings = [
                f for f in result.findings if f.severity == Severity.CRITICAL
            ]
            self.assertEqual(len(critical_findings), 0)


if __name__ == '__main__':
    unittest.main()
