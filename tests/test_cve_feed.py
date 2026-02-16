"""Tests for CVE Feed Integration.

These tests verify the CVEFeedManager including built-in CVEs,
feed fetching, version checking, and alert generation.
"""

import unittest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'skill'))

from monitor.cve_feed import CVEFeedManager, CVEAdvisory, FeedStatus
from monitor.alerts import AlertManager, AlertSeverity


class TestCVEFeedManagerInit(unittest.TestCase):
    """Tests for CVEFeedManager initialization."""

    def test_default_init(self):
        """Test default initialization."""
        manager = CVEFeedManager()
        self.assertIsInstance(manager.alert_manager, AlertManager)
        self.assertEqual(manager.sources, [])
        self.assertEqual(manager.check_interval, 3600)
        self.assertIsNone(manager.current_version)

    def test_custom_init(self):
        """Test custom initialization."""
        alert_mgr = AlertManager()
        sources = ["https://example.com/feed.json"]
        manager = CVEFeedManager(
            alert_manager=alert_mgr,
            sources=sources,
            check_interval=1800,
            current_version="2026.2.5",
        )
        self.assertIs(manager.alert_manager, alert_mgr)
        self.assertEqual(manager.sources, sources)
        self.assertEqual(manager.check_interval, 1800)
        self.assertEqual(manager.current_version, "2026.2.5")

    def test_builtin_cves_loaded(self):
        """Test that all 5 built-in CVEs are loaded on init."""
        manager = CVEFeedManager()
        self.assertEqual(len(manager.advisories), 5)

        expected_cves = [
            "CVE-2026-25253",
            "CVE-2026-25157",
            "CVE-2026-24763",
            "CVE-2026-23891",
            "CVE-2026-22456",
        ]
        for cve_id in expected_cves:
            self.assertIn(cve_id, manager.advisories)

    def test_builtin_cve_severities(self):
        """Test built-in CVE severity levels."""
        manager = CVEFeedManager()
        self.assertEqual(manager.advisories["CVE-2026-25253"].severity, AlertSeverity.CRITICAL)
        self.assertEqual(manager.advisories["CVE-2026-25157"].severity, AlertSeverity.HIGH)
        self.assertEqual(manager.advisories["CVE-2026-24763"].severity, AlertSeverity.HIGH)
        self.assertEqual(manager.advisories["CVE-2026-23891"].severity, AlertSeverity.MEDIUM)
        self.assertEqual(manager.advisories["CVE-2026-22456"].severity, AlertSeverity.MEDIUM)

    def test_feed_statuses_initialized(self):
        """Test that feed statuses are initialized for each source."""
        sources = ["https://a.com/feed", "https://b.com/feed"]
        manager = CVEFeedManager(sources=sources)
        self.assertEqual(len(manager.feed_statuses), 2)
        for url in sources:
            self.assertIn(url, manager.feed_statuses)
            self.assertIsNone(manager.feed_statuses[url].last_checked)


class TestCVEFeedManagerVersionChecking(unittest.TestCase):
    """Tests for version checking and advisory matching."""

    def test_check_vulnerable_version(self):
        """Test check() with a vulnerable version."""
        manager = CVEFeedManager(current_version="2026.1.0")
        relevant = manager.check()

        # Version 2026.1.0 is affected by all 5 CVEs
        self.assertEqual(len(relevant), 5)
        cve_ids = [a.cve_id for a in relevant]
        self.assertIn("CVE-2026-25253", cve_ids)
        self.assertIn("CVE-2026-25157", cve_ids)

    def test_check_partially_patched_version(self):
        """Test check() with a partially patched version."""
        manager = CVEFeedManager(current_version="2026.2.9")
        relevant = manager.check()

        # Should be affected by CVEs with fixed_version > 2026.2.9
        cve_ids = [a.cve_id for a in relevant]
        self.assertIn("CVE-2026-25253", cve_ids)  # fixed in 2026.2.12
        self.assertIn("CVE-2026-25157", cve_ids)  # fixed in 2026.2.10
        self.assertIn("CVE-2026-24763", cve_ids)  # fixed in 2026.2.12
        self.assertNotIn("CVE-2026-23891", cve_ids)  # fixed in 2026.2.8
        self.assertNotIn("CVE-2026-22456", cve_ids)  # fixed in 2026.2.6

    def test_check_fully_patched_version(self):
        """Test check() with a fully patched version."""
        manager = CVEFeedManager(current_version="2026.3.0")
        relevant = manager.check()

        self.assertEqual(len(relevant), 0)

    def test_check_no_version(self):
        """Test check() with no version set returns empty."""
        manager = CVEFeedManager(current_version=None)
        relevant = manager.check()

        self.assertEqual(len(relevant), 0)


class TestCVEFeedManagerAlerting(unittest.TestCase):
    """Tests for alert generation."""

    def test_alerts_sent_for_relevant_cves(self):
        """Test that alerts are sent for relevant CVEs."""
        alert_mgr = AlertManager()
        manager = CVEFeedManager(
            alert_manager=alert_mgr,
            current_version="2026.1.0",
        )
        manager.check()

        # Should have sent alerts for all 5 CVEs
        self.assertEqual(len(alert_mgr.alerts), 5)

    def test_alert_type_is_cve_advisory(self):
        """Test that alerts have correct alert_type."""
        alert_mgr = AlertManager()
        manager = CVEFeedManager(
            alert_manager=alert_mgr,
            current_version="2026.1.0",
        )
        manager.check()

        for alert in alert_mgr.alerts:
            self.assertEqual(alert.alert_type, "cve_advisory")

    def test_alert_severity_matches_advisory(self):
        """Test that alert severity matches the advisory severity."""
        alert_mgr = AlertManager()
        manager = CVEFeedManager(
            alert_manager=alert_mgr,
            current_version="2026.1.0",
        )
        manager.check()

        # Find the critical alert (CVE-2026-25253)
        critical_alerts = [a for a in alert_mgr.alerts if a.severity == AlertSeverity.CRITICAL]
        self.assertEqual(len(critical_alerts), 1)
        self.assertIn("CVE-2026-25253", critical_alerts[0].title)

    def test_no_duplicate_alerts(self):
        """Test that duplicate alerts are not sent on repeated check()."""
        alert_mgr = AlertManager()
        manager = CVEFeedManager(
            alert_manager=alert_mgr,
            current_version="2026.1.0",
        )

        # First check
        manager.check()
        first_count = len(alert_mgr.alerts)

        # Second check - should not send duplicates
        manager.check()
        self.assertEqual(len(alert_mgr.alerts), first_count)

    def test_no_alerts_when_patched(self):
        """Test that no alerts are sent for patched version."""
        alert_mgr = AlertManager()
        manager = CVEFeedManager(
            alert_manager=alert_mgr,
            current_version="2026.3.0",
        )
        manager.check()

        self.assertEqual(len(alert_mgr.alerts), 0)

    def test_alert_metadata_includes_version(self):
        """Test that alert metadata includes version info."""
        alert_mgr = AlertManager()
        manager = CVEFeedManager(
            alert_manager=alert_mgr,
            current_version="2026.1.0",
        )
        manager.check()

        for alert in alert_mgr.alerts:
            self.assertEqual(alert.metadata["current_version"], "2026.1.0")
            self.assertIn("cve_id", alert.metadata)


class TestCVEFeedManagerVersionParsing(unittest.TestCase):
    """Tests for version parsing and comparison."""

    def setUp(self):
        self.manager = CVEFeedManager()

    def test_parse_version_valid(self):
        """Test parsing valid version strings."""
        self.assertEqual(self.manager._parse_version("2026.2.12"), (2026, 2, 12))
        self.assertEqual(self.manager._parse_version("2026.1.0"), (2026, 1, 0))
        self.assertEqual(self.manager._parse_version("1.0.0"), (1, 0, 0))

    def test_parse_version_invalid(self):
        """Test parsing invalid version strings."""
        self.assertIsNone(self.manager._parse_version("invalid"))
        self.assertIsNone(self.manager._parse_version(""))

    def test_is_affected_less_than(self):
        """Test _is_affected with < operator."""
        self.assertTrue(self.manager._is_affected("2026.2.5", ["< 2026.2.12"]))
        self.assertFalse(self.manager._is_affected("2026.2.12", ["< 2026.2.12"]))
        self.assertFalse(self.manager._is_affected("2026.3.0", ["< 2026.2.12"]))

    def test_is_affected_less_than_equal(self):
        """Test _is_affected with <= operator."""
        self.assertTrue(self.manager._is_affected("2026.2.12", ["<= 2026.2.12"]))
        self.assertFalse(self.manager._is_affected("2026.2.13", ["<= 2026.2.12"]))

    def test_is_affected_range(self):
        """Test _is_affected with range operator."""
        self.assertTrue(self.manager._is_affected("2026.2.5", [">= 2026.1.0 < 2026.2.12"]))
        self.assertFalse(self.manager._is_affected("2026.0.5", [">= 2026.1.0 < 2026.2.12"]))
        self.assertFalse(self.manager._is_affected("2026.2.12", [">= 2026.1.0 < 2026.2.12"]))

    def test_is_affected_invalid_version(self):
        """Test _is_affected with invalid version string."""
        self.assertFalse(self.manager._is_affected("invalid", ["< 2026.2.12"]))


class TestCVEFeedManagerFeedFetching(unittest.TestCase):
    """Tests for feed fetching."""

    def test_fetch_feed_success(self):
        """Test successful feed fetch."""
        manager = CVEFeedManager(sources=["https://example.com/feed.json"])
        mock_response = MagicMock()
        mock_response.json.return_value = {"advisories": []}
        mock_response.raise_for_status = MagicMock()

        mock_requests = MagicMock()
        mock_requests.get.return_value = mock_response

        with patch.dict("sys.modules", {"requests": mock_requests}):
            result = manager._fetch_feed("https://example.com/feed.json")

        self.assertEqual(result, {"advisories": []})

    def test_fetch_feed_network_error(self):
        """Test feed fetch with network error."""
        manager = CVEFeedManager(sources=["https://example.com/feed.json"])

        mock_requests = MagicMock()
        mock_requests.get.side_effect = Exception("Connection refused")

        with patch.dict("sys.modules", {"requests": mock_requests}):
            result = manager._fetch_feed("https://example.com/feed.json")

        self.assertIsNone(result)
        self.assertIn("Connection refused",
                      manager.feed_statuses["https://example.com/feed.json"].last_error)

    def test_fetch_feed_bad_json(self):
        """Test feed fetch with invalid JSON response."""
        manager = CVEFeedManager(sources=["https://example.com/feed.json"])
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.side_effect = ValueError("Invalid JSON")

        mock_requests = MagicMock()
        mock_requests.get.return_value = mock_response

        with patch.dict("sys.modules", {"requests": mock_requests}):
            result = manager._fetch_feed("https://example.com/feed.json")

        self.assertIsNone(result)

    def test_fetch_feed_requests_not_installed(self):
        """Test feed fetch when requests is not installed."""
        manager = CVEFeedManager(sources=["https://example.com/feed.json"])

        # Remove requests from sys.modules so the lazy import fails
        with patch.dict("sys.modules", {"requests": None}):
            result = manager._fetch_feed("https://example.com/feed.json")

        self.assertIsNone(result)


class TestCVEFeedManagerFeedParsing(unittest.TestCase):
    """Tests for feed response parsing."""

    def setUp(self):
        self.manager = CVEFeedManager()

    def test_parse_valid_feed(self):
        """Test parsing a valid feed response."""
        data = {
            "advisories": [
                {
                    "cve_id": "CVE-2026-99999",
                    "severity": "critical",
                    "title": "Test Vulnerability",
                    "description": "A test vulnerability",
                    "affected_versions": ["< 2026.3.0"],
                    "fixed_version": "2026.3.0",
                    "remediation": "Upgrade to 2026.3.0",
                    "references": ["https://example.com/advisory"],
                }
            ]
        }

        advisories = self.manager._parse_feed_response(data)
        self.assertEqual(len(advisories), 1)
        self.assertEqual(advisories[0].cve_id, "CVE-2026-99999")
        self.assertEqual(advisories[0].severity, AlertSeverity.CRITICAL)
        self.assertEqual(advisories[0].title, "Test Vulnerability")

    def test_parse_feed_missing_fields(self):
        """Test parsing feed with missing optional fields."""
        data = {
            "advisories": [
                {
                    "cve_id": "CVE-2026-99999",
                }
            ]
        }

        advisories = self.manager._parse_feed_response(data)
        self.assertEqual(len(advisories), 1)
        self.assertEqual(advisories[0].cve_id, "CVE-2026-99999")
        self.assertEqual(advisories[0].severity, AlertSeverity.INFO)
        self.assertEqual(advisories[0].title, "CVE-2026-99999")

    def test_parse_feed_invalid_severity(self):
        """Test parsing feed with invalid severity."""
        data = {
            "advisories": [
                {
                    "cve_id": "CVE-2026-99999",
                    "severity": "super_critical",
                }
            ]
        }

        advisories = self.manager._parse_feed_response(data)
        self.assertEqual(len(advisories), 1)
        self.assertEqual(advisories[0].severity, AlertSeverity.INFO)

    def test_parse_feed_empty(self):
        """Test parsing empty feed."""
        self.assertEqual(len(self.manager._parse_feed_response({})), 0)
        self.assertEqual(len(self.manager._parse_feed_response({"advisories": []})), 0)

    def test_parse_feed_missing_cve_id(self):
        """Test that entries without cve_id are skipped."""
        data = {
            "advisories": [
                {"title": "No CVE ID"},
                {"cve_id": "CVE-2026-11111", "title": "Has CVE ID"},
            ]
        }

        advisories = self.manager._parse_feed_response(data)
        self.assertEqual(len(advisories), 1)
        self.assertEqual(advisories[0].cve_id, "CVE-2026-11111")

    def test_parse_feed_non_list_advisories(self):
        """Test parsing feed where advisories is not a list."""
        data = {"advisories": "not a list"}
        advisories = self.manager._parse_feed_response(data)
        self.assertEqual(len(advisories), 0)

    def test_parse_feed_non_dict_items(self):
        """Test parsing feed with non-dict items in advisories."""
        data = {"advisories": ["string", 123, None]}
        advisories = self.manager._parse_feed_response(data)
        self.assertEqual(len(advisories), 0)


class TestCVEFeedManagerRefreshInterval(unittest.TestCase):
    """Tests for feed refresh interval logic."""

    def test_feed_skipped_when_recent(self):
        """Test that feeds are not fetched when recently checked."""
        url = "https://example.com/feed.json"
        manager = CVEFeedManager(
            sources=[url],
            check_interval=3600,
        )

        # Mark as recently checked
        manager.feed_statuses[url].last_checked = datetime.now()

        with patch.object(manager, "_fetch_feed") as mock_fetch:
            manager._refresh_feeds()
            mock_fetch.assert_not_called()

    def test_feed_fetched_when_stale(self):
        """Test that feeds are fetched when check interval has elapsed."""
        url = "https://example.com/feed.json"
        manager = CVEFeedManager(
            sources=[url],
            check_interval=3600,
        )

        # Mark as checked long ago
        manager.feed_statuses[url].last_checked = datetime.now() - timedelta(hours=2)

        with patch.object(manager, "_fetch_feed", return_value={"advisories": []}) as mock_fetch:
            manager._refresh_feeds()
            mock_fetch.assert_called_once_with(url)

    def test_feed_fetched_on_first_check(self):
        """Test that feeds are fetched on the first check."""
        url = "https://example.com/feed.json"
        manager = CVEFeedManager(sources=[url])

        with patch.object(manager, "_fetch_feed", return_value={"advisories": []}) as mock_fetch:
            manager._refresh_feeds()
            mock_fetch.assert_called_once()


class TestCVEFeedManagerStatus(unittest.TestCase):
    """Tests for get_status()."""

    def test_status_structure(self):
        """Test get_status() returns correct structure."""
        manager = CVEFeedManager(
            sources=["https://example.com/feed.json"],
            check_interval=1800,
            current_version="2026.2.5",
        )

        status = manager.get_status()
        self.assertEqual(status["sources"], ["https://example.com/feed.json"])
        self.assertEqual(status["check_interval"], 1800)
        self.assertEqual(status["current_version"], "2026.2.5")
        self.assertEqual(status["total_advisories"], 5)  # built-in
        self.assertIn("feeds", status)
        self.assertIn("alerted_cves", status)

    def test_status_with_feed_error(self):
        """Test get_status() with a feed error."""
        url = "https://example.com/feed.json"
        manager = CVEFeedManager(sources=[url])
        manager.feed_statuses[url].last_error = "Connection refused"
        manager.feed_statuses[url].last_checked = datetime.now()

        status = manager.get_status()
        self.assertEqual(status["feeds"][url]["last_error"], "Connection refused")
        self.assertIsNotNone(status["feeds"][url]["last_checked"])

    def test_status_no_sources(self):
        """Test get_status() with no sources."""
        manager = CVEFeedManager()
        status = manager.get_status()
        self.assertEqual(status["sources"], [])
        self.assertEqual(status["feeds"], {})

    def test_status_after_check(self):
        """Test get_status() after running check()."""
        manager = CVEFeedManager(current_version="2026.1.0")
        manager.check()

        status = manager.get_status()
        self.assertEqual(len(status["alerted_cves"]), 5)


class TestCVEFeedManagerIntegration(unittest.TestCase):
    """Integration tests for CVEFeedManager."""

    def test_feed_advisories_merge_with_builtin(self):
        """Test that feed advisories merge with built-in ones."""
        manager = CVEFeedManager(current_version="2026.2.5")

        # Simulate adding a feed advisory
        new_advisory = CVEAdvisory(
            cve_id="CVE-2026-99999",
            severity=AlertSeverity.CRITICAL,
            title="New CVE from feed",
            description="A new vulnerability",
            affected_versions=["< 2026.3.0"],
            fixed_version="2026.3.0",
            remediation="Upgrade",
        )
        manager.advisories[new_advisory.cve_id] = new_advisory

        relevant = manager.check()
        cve_ids = [a.cve_id for a in relevant]

        # Should include both built-in and feed advisories
        self.assertIn("CVE-2026-25253", cve_ids)
        self.assertIn("CVE-2026-99999", cve_ids)

    def test_feed_can_override_builtin(self):
        """Test that feed advisories can override built-in ones."""
        manager = CVEFeedManager(current_version="2026.2.5")

        # Override a built-in CVE with updated info
        updated = CVEAdvisory(
            cve_id="CVE-2026-25253",
            severity=AlertSeverity.CRITICAL,
            title="Updated title from feed",
            description="Updated description",
            affected_versions=["< 2026.2.12"],
            fixed_version="2026.2.12",
            remediation="Updated remediation",
        )
        manager.advisories[updated.cve_id] = updated

        self.assertEqual(manager.advisories["CVE-2026-25253"].title, "Updated title from feed")


if __name__ == '__main__':
    unittest.main()
