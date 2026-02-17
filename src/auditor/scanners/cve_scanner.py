"""CVE vulnerability scanner for OpenClaw."""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .base import BaseScanner, Finding, ScanResult, Severity


@dataclass
class CVEInfo:
    """Information about a known CVE."""

    cve_id: str
    severity: Severity
    title: str
    description: str
    affected_versions: list[str]  # Version ranges like "< 2026.2.12"
    fixed_version: Optional[str]
    remediation: str
    references: list[str]


class CVEScanner(BaseScanner):
    """Scans for known CVE vulnerabilities based on OpenClaw version."""

    name = "cve"
    description = "Check for known CVE vulnerabilities"

    # Known CVEs for OpenClaw
    KNOWN_CVES = [
        CVEInfo(
            cve_id="CVE-2026-25253",
            severity=Severity.CRITICAL,
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
        CVEInfo(
            cve_id="CVE-2026-25157",
            severity=Severity.HIGH,
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
        CVEInfo(
            cve_id="CVE-2026-24763",
            severity=Severity.HIGH,
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
        CVEInfo(
            cve_id="CVE-2026-23891",
            severity=Severity.MEDIUM,
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
        CVEInfo(
            cve_id="CVE-2026-22456",
            severity=Severity.MEDIUM,
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

    def scan(self, target: str, version: Optional[str] = None, **kwargs) -> ScanResult:
        """
        Check for known CVEs affecting the target version.

        Args:
            target: Path to OpenClaw installation
            version: OpenClaw version string (if not provided, will attempt detection)

        Returns:
            ScanResult with CVE findings
        """
        result = ScanResult(scanner_name=self.name)

        # Try to detect version if not provided
        if version is None:
            version = self._detect_version(target)

        if version is None:
            result.errors.append(
                "Could not detect OpenClaw version. " "Use --version flag to specify manually."
            )
            return result

        result.scanned_items = 1

        # Check each CVE
        for cve in self.KNOWN_CVES:
            if self._is_affected(version, cve.affected_versions):
                result.findings.append(
                    Finding(
                        title=cve.title,
                        severity=cve.severity,
                        description=cve.description,
                        cve=cve.cve_id,
                        remediation=cve.remediation,
                        references=cve.references,
                        location=f"OpenClaw version {version}",
                    )
                )

        return result

    def _detect_version(self, target: str) -> Optional[str]:
        """Attempt to detect OpenClaw version from installation."""
        target_path = Path(target)

        # Check package.json
        package_json = target_path / "package.json"
        if package_json.exists():
            try:
                data = json.loads(package_json.read_text())
                if "version" in data:
                    return data["version"]
            except Exception:
                pass

        # Check version file
        version_file = target_path / "VERSION"
        if version_file.exists():
            try:
                return version_file.read_text().strip()
            except Exception:
                pass

        # Check pyproject.toml
        pyproject = target_path / "pyproject.toml"
        if pyproject.exists():
            try:
                content = pyproject.read_text()
                match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
                if match:
                    return match.group(1)
            except Exception:
                pass

        return None

    def _is_affected(self, version: str, affected_ranges: list[str]) -> bool:
        """Check if a version is affected by the vulnerability."""
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
                # Range like ">= 2026.1.0 < 2026.2.12"
                parts = range_str.split(" < ")
                min_ver = self._parse_version(parts[0][3:])
                max_ver = self._parse_version(parts[1])
                if min_ver and max_ver and min_ver <= version_tuple < max_ver:
                    return True

        return False

    def _parse_version(self, version_str: str) -> Optional[tuple[int, ...]]:
        """Parse version string to comparable tuple."""
        try:
            # Handle versions like "2026.2.12"
            parts = version_str.strip().split(".")
            return tuple(int(p) for p in parts)
        except (ValueError, AttributeError):
            return None
