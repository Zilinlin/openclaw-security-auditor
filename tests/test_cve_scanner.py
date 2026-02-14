"""Tests for CVE scanner."""

import pytest

from auditor.scanners import CVEScanner, Severity


class TestCVEScanner:
    """Test cases for CVEScanner."""

    def test_detect_vulnerable_version(self):
        """Test detection of vulnerable version."""
        scanner = CVEScanner()
        result = scanner.scan(".", version="2026.2.5")

        # Should find multiple CVEs for old version
        assert len(result.findings) > 0
        assert any(f.cve == "CVE-2026-25253" for f in result.findings)

    def test_patched_version(self):
        """Test that patched version has no critical CVEs."""
        scanner = CVEScanner()
        result = scanner.scan(".", version="2026.2.12")

        # Latest version should have no findings
        assert len(result.findings) == 0

    def test_version_parsing(self):
        """Test version parsing and comparison."""
        scanner = CVEScanner()

        # Test various version formats
        assert scanner._parse_version("2026.2.12") == (2026, 2, 12)
        assert scanner._parse_version("2026.1.0") == (2026, 1, 0)

    def test_affected_version_check(self):
        """Test affected version range checking."""
        scanner = CVEScanner()

        # Version 2026.2.5 should be affected by CVE < 2026.2.12
        assert scanner._is_affected("2026.2.5", ["< 2026.2.12"])

        # Version 2026.2.12 should NOT be affected
        assert not scanner._is_affected("2026.2.12", ["< 2026.2.12"])

        # Version 2026.3.0 should NOT be affected
        assert not scanner._is_affected("2026.3.0", ["< 2026.2.12"])

    def test_missing_version_error(self):
        """Test error handling when version cannot be detected."""
        scanner = CVEScanner()
        result = scanner.scan("/nonexistent/path")

        assert len(result.errors) > 0
        assert "Could not detect" in result.errors[0]
