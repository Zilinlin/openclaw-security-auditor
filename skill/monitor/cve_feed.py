"""CVE Feed Integration.

Monitors CVE advisory feeds for vulnerabilities affecting the current
OpenClaw deployment, and sends alerts when relevant advisories are found.

SAFETY NOTE:
- This module only fetches and parses advisory data
- It does NOT modify any system configuration
- All advisories are informational alerts

Reference:
- https://github.com/openclaw/openclaw/security/advisories
- https://nvd.nist.gov/
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple

from .alerts import Alert, AlertManager, AlertSeverity


@dataclass
class CVEAdvisory:
    """A CVE advisory for OpenClaw."""
    cve_id: str
    severity: AlertSeverity
    title: str
    description: str
    affected_versions: List[str]
    fixed_version: Optional[str]
    remediation: str
    references: List[str] = field(default_factory=list)


@dataclass
class FeedStatus:
    """Status of a CVE feed source."""
    url: str
    last_checked: Optional[datetime] = None
    last_success: Optional[datetime] = None
    advisory_count: int = 0
    last_error: Optional[str] = None


class CVEFeedManager:
    """Manage CVE advisory feeds for OpenClaw.

    Fetches and monitors CVE feeds, checks advisories against the current
    deployment version, and sends alerts for relevant vulnerabilities.

    Includes built-in knowledge of known OpenClaw CVEs (same as the
    static CVE scanner) so advisories are available even without
    network connectivity.

    Reference:
    - https://github.com/openclaw/openclaw/security/advisories
    - https://nvd.nist.gov/

    Attributes:
        alert_manager: AlertManager for sending alerts
        sources: List of feed URLs to monitor
        check_interval: Seconds between feed refreshes
        current_version: Current OpenClaw version string
    """

    # Built-in CVE advisories (same data as src/auditor/scanners/cve_scanner.py)
    BUILTIN_CVES = [
        CVEAdvisory(
            cve_id="CVE-2026-25253",
            severity=AlertSeverity.CRITICAL,
            title="Remote Code Execution via Malicious Skill",
            description="A vulnerability in the Skills marketplace allows attackers to execute "
                       "arbitrary code on the host system through specially crafted skill packages. "
                       "This can lead to complete system compromise.",
            affected_versions=["< 2026.2.12"],
            fixed_version="2026.2.12",
            remediation="Upgrade to OpenClaw 2026.2.12 or later. Disable third-party skills "
                       "until upgrade is complete.",
            references=[
                "https://github.com/openclaw/openclaw/security/advisories/GHSA-xxxx-xxxx-xxxx",
                "https://nvd.nist.gov/vuln/detail/CVE-2026-25253",
            ],
        ),
        CVEAdvisory(
            cve_id="CVE-2026-25157",
            severity=AlertSeverity.HIGH,
            title="Authentication Bypass in Gateway API",
            description="The Gateway component fails to properly validate authentication tokens "
                       "under certain conditions, allowing unauthenticated access to protected "
                       "API endpoints.",
            affected_versions=["< 2026.2.10"],
            fixed_version="2026.2.10",
            remediation="Upgrade to OpenClaw 2026.2.10 or later. As a temporary mitigation, "
                       "restrict network access to the Gateway API.",
            references=[
                "https://github.com/openclaw/openclaw/security/advisories/GHSA-yyyy-yyyy-yyyy",
                "https://nvd.nist.gov/vuln/detail/CVE-2026-25157",
            ],
        ),
        CVEAdvisory(
            cve_id="CVE-2026-24763",
            severity=AlertSeverity.HIGH,
            title="Privilege Escalation via Prompt Injection",
            description="Attackers can inject malicious instructions through external content "
                       "(websites, messages) that the agent processes, leading to unauthorized "
                       "actions with the agent's full privileges.",
            affected_versions=["< 2026.2.12"],
            fixed_version="2026.2.12",
            remediation="Upgrade to OpenClaw 2026.2.12 or later. Enable the new 'untrusted content' "
                       "mode which sanitizes external inputs.",
            references=[
                "https://github.com/openclaw/openclaw/security/advisories/GHSA-zzzz-zzzz-zzzz",
                "https://nvd.nist.gov/vuln/detail/CVE-2026-24763",
            ],
        ),
        CVEAdvisory(
            cve_id="CVE-2026-23891",
            severity=AlertSeverity.MEDIUM,
            title="SSRF via URL Input Processing",
            description="The input_file and input_image URL handlers do not properly validate "
                       "target URLs, allowing Server-Side Request Forgery attacks to access "
                       "internal network resources.",
            affected_versions=["< 2026.2.8"],
            fixed_version="2026.2.8",
            remediation="Upgrade to OpenClaw 2026.2.8 or later. Configure URL allowlists "
                       "for external resource fetching.",
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2026-23891",
            ],
        ),
        CVEAdvisory(
            cve_id="CVE-2026-22456",
            severity=AlertSeverity.MEDIUM,
            title="Information Disclosure in Error Messages",
            description="Detailed error messages expose internal system paths, configuration "
                       "details, and stack traces to remote users.",
            affected_versions=["< 2026.2.6"],
            fixed_version="2026.2.6",
            remediation="Upgrade to OpenClaw 2026.2.6 or later. Disable debug mode in production.",
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2026-22456",
            ],
        ),
    ]

    def __init__(
        self,
        alert_manager: Optional[AlertManager] = None,
        sources: Optional[List[str]] = None,
        check_interval: int = 3600,
        current_version: Optional[str] = None,
    ):
        """Initialize the CVE feed manager.

        Args:
            alert_manager: Optional AlertManager for sending alerts
            sources: List of feed URLs to monitor
            check_interval: Seconds between feed refreshes
            current_version: Current OpenClaw version string
        """
        self.alert_manager = alert_manager or AlertManager()
        self.sources = sources or []
        self.check_interval = check_interval
        self.current_version = current_version

        # All known advisories (built-in + fetched), keyed by cve_id
        self.advisories: Dict[str, CVEAdvisory] = {}
        for cve in self.BUILTIN_CVES:
            self.advisories[cve.cve_id] = cve

        # Feed status tracking
        self.feed_statuses: Dict[str, FeedStatus] = {
            url: FeedStatus(url=url) for url in self.sources
        }

        # Track which CVEs have already been alerted
        self._alerted_cves: Set[str] = set()

    def check(self) -> List[CVEAdvisory]:
        """Check for CVE advisories affecting the current version.

        Refreshes feeds if due, finds relevant advisories, and sends
        alerts for newly discovered ones.

        Returns:
            List of relevant CVEAdvisory objects
        """
        # Refresh external feeds
        self._refresh_feeds()

        # Find advisories relevant to current version
        relevant = self._find_relevant_advisories()

        # Send alerts for new ones
        for advisory in relevant:
            if advisory.cve_id not in self._alerted_cves:
                self._send_advisory_alert(advisory)
                self._alerted_cves.add(advisory.cve_id)

        return relevant

    def _refresh_feeds(self) -> None:
        """Refresh CVE feeds that are due for checking."""
        now = datetime.now()

        for url, status in self.feed_statuses.items():
            # Skip if checked recently
            if status.last_checked:
                elapsed = (now - status.last_checked).total_seconds()
                if elapsed < self.check_interval:
                    continue

            status.last_checked = now
            data = self._fetch_feed(url)

            if data is not None:
                advisories = self._parse_feed_response(data)
                for advisory in advisories:
                    self.advisories[advisory.cve_id] = advisory
                status.last_success = now
                status.advisory_count = len(advisories)
                status.last_error = None
            # Error is already recorded in _fetch_feed

    def _fetch_feed(self, url: str) -> Optional[dict]:
        """Fetch a CVE feed from a URL.

        Args:
            url: Feed URL to fetch

        Returns:
            Parsed JSON data or None on failure
        """
        try:
            import requests
        except ImportError:
            if url in self.feed_statuses:
                self.feed_statuses[url].last_error = "requests library not installed"
            return None

        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            if url in self.feed_statuses:
                self.feed_statuses[url].last_error = str(e)
            return None

    def _parse_feed_response(self, data: dict) -> List[CVEAdvisory]:
        """Parse a CVE feed JSON response into advisories.

        Expected format:
        {
            "advisories": [
                {
                    "cve_id": "CVE-...",
                    "severity": "critical|high|medium|low|info",
                    "title": "...",
                    "description": "...",
                    "affected_versions": ["< X.Y.Z"],
                    "fixed_version": "X.Y.Z",
                    "remediation": "...",
                    "references": ["..."]
                }
            ]
        }

        Args:
            data: Parsed JSON data

        Returns:
            List of parsed CVEAdvisory objects
        """
        advisories = []

        items = data.get("advisories", [])
        if not isinstance(items, list):
            return advisories

        for item in items:
            if not isinstance(item, dict):
                continue

            cve_id = item.get("cve_id")
            if not cve_id:
                continue

            # Parse severity
            severity_str = item.get("severity", "info").lower()
            try:
                severity = AlertSeverity(severity_str)
            except ValueError:
                severity = AlertSeverity.INFO

            advisories.append(CVEAdvisory(
                cve_id=cve_id,
                severity=severity,
                title=item.get("title", cve_id),
                description=item.get("description", ""),
                affected_versions=item.get("affected_versions", []),
                fixed_version=item.get("fixed_version"),
                remediation=item.get("remediation", ""),
                references=item.get("references", []),
            ))

        return advisories

    def _find_relevant_advisories(self) -> List[CVEAdvisory]:
        """Find advisories relevant to the current version.

        Returns:
            List of advisories affecting the current version
        """
        if not self.current_version:
            return []

        relevant = []
        for advisory in self.advisories.values():
            if self._is_affected(self.current_version, advisory.affected_versions):
                relevant.append(advisory)

        return relevant

    def _is_affected(self, version: str, affected_ranges: List[str]) -> bool:
        """Check if a version is affected by the vulnerability.

        Args:
            version: Version string to check
            affected_ranges: List of version range strings

        Returns:
            True if version is affected
        """
        version_tuple = self._parse_version(version)
        if version_tuple is None:
            return False

        for range_str in affected_ranges:
            if range_str.startswith("< "):
                fixed_version = self._parse_version(range_str[2:])
                if fixed_version and version_tuple < fixed_version:
                    return True
            elif range_str.startswith("<= "):
                max_version = self._parse_version(range_str[3:])
                if max_version and version_tuple <= max_version:
                    return True
            elif range_str.startswith(">= ") and " < " in range_str:
                parts = range_str.split(" < ")
                min_ver = self._parse_version(parts[0][3:])
                max_ver = self._parse_version(parts[1])
                if min_ver and max_ver and min_ver <= version_tuple < max_ver:
                    return True

        return False

    def _parse_version(self, version_str: str) -> Optional[Tuple[int, ...]]:
        """Parse version string to comparable tuple.

        Args:
            version_str: Version string like "2026.2.12"

        Returns:
            Tuple of ints or None if parsing fails
        """
        try:
            parts = version_str.strip().split(".")
            return tuple(int(p) for p in parts)
        except (ValueError, AttributeError):
            return None

    def _send_advisory_alert(self, advisory: CVEAdvisory) -> None:
        """Send an alert for a CVE advisory.

        Args:
            advisory: The advisory to alert on
        """
        self.alert_manager.send(Alert(
            alert_type="cve_advisory",
            severity=advisory.severity,
            title=f"CVE Advisory: {advisory.cve_id} - {advisory.title}",
            description=(
                f"{advisory.description}\n\n"
                f"Affected versions: {', '.join(advisory.affected_versions)}\n"
                f"Fixed in: {advisory.fixed_version or 'Unknown'}\n"
                f"Remediation: {advisory.remediation}"
            ),
            metadata={
                "cve_id": advisory.cve_id,
                "affected_versions": advisory.affected_versions,
                "fixed_version": advisory.fixed_version,
                "current_version": self.current_version,
            },
            reference=advisory.references[0] if advisory.references else None,
        ))

    def get_status(self) -> Dict:
        """Get current CVE feed manager status.

        Returns:
            Dict with status information
        """
        return {
            "sources": self.sources,
            "check_interval": self.check_interval,
            "current_version": self.current_version,
            "total_advisories": len(self.advisories),
            "alerted_cves": list(self._alerted_cves),
            "feeds": {
                url: {
                    "last_checked": status.last_checked.isoformat() if status.last_checked else None,
                    "last_success": status.last_success.isoformat() if status.last_success else None,
                    "advisory_count": status.advisory_count,
                    "last_error": status.last_error,
                }
                for url, status in self.feed_statuses.items()
            },
        }
