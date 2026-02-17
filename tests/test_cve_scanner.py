"""Tests for CVE scanner."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from auditor.scanners.cve_scanner import CVEScanner


class TestCVEScanner(unittest.TestCase):
    """Test cases for CVEScanner."""

    def test_detect_vulnerable_version(self):
        """Test detection of vulnerable version."""
        scanner = CVEScanner()
        result = scanner.scan(".", version="2026.2.5")

        # Should find multiple CVEs for old version
        self.assertTrue(len(result.findings) > 0)
        cve_ids = [f.cve for f in result.findings]
        self.assertIn("CVE-2026-25253", cve_ids)

    def test_patched_version(self):
        """Test that patched version has no critical CVEs."""
        scanner = CVEScanner()
        result = scanner.scan(".", version="2026.2.12")

        # Latest version should have no findings
        self.assertEqual(len(result.findings), 0)

    def test_version_parsing(self):
        """Test version parsing and comparison."""
        scanner = CVEScanner()

        self.assertEqual(scanner._parse_version("2026.2.12"), (2026, 2, 12))
        self.assertEqual(scanner._parse_version("2026.1.0"), (2026, 1, 0))

    def test_affected_version_check(self):
        """Test affected version range checking."""
        scanner = CVEScanner()

        # Version 2026.2.5 should be affected by CVE < 2026.2.12
        self.assertTrue(scanner._is_affected("2026.2.5", ["< 2026.2.12"]))

        # Version 2026.2.12 should NOT be affected
        self.assertFalse(scanner._is_affected("2026.2.12", ["< 2026.2.12"]))

        # Version 2026.3.0 should NOT be affected
        self.assertFalse(scanner._is_affected("2026.3.0", ["< 2026.2.12"]))

    def test_missing_version_error(self):
        """Test error handling when version cannot be detected."""
        scanner = CVEScanner()
        result = scanner.scan("/nonexistent/path")

        self.assertTrue(len(result.errors) > 0)
        self.assertIn("Could not detect", result.errors[0])


if __name__ == "__main__":
    unittest.main()
