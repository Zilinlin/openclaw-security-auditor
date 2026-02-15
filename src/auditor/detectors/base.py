"""Base detector interface for dynamic vulnerability detection.

All detectors in this module are designed for DETECTION ONLY.
They do NOT exploit vulnerabilities or exfiltrate data.

Reference: docs/DETECTION_TECHNIQUES.md
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class DetectorSeverity(Enum):
    """Severity levels for detector findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityStatus(Enum):
    """Status of vulnerability detection."""
    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    UNKNOWN = "unknown"
    ERROR = "error"


@dataclass
class DetectorFinding:
    """Represents a finding from dynamic detection.

    Attributes:
        title: Short title of the finding
        status: Whether the target is vulnerable
        severity: Severity level if vulnerable
        description: Detailed description
        cve: Associated CVE ID if applicable
        evidence: Evidence that supports the finding (safe to display)
        remediation: Steps to fix the vulnerability
        references: URLs to security research
    """
    title: str
    status: VulnerabilityStatus
    severity: Optional[DetectorSeverity] = None
    description: str = ""
    cve: Optional[str] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert finding to dictionary."""
        return {
            "title": self.title,
            "status": self.status.value,
            "severity": self.severity.value if self.severity else None,
            "description": self.description,
            "cve": self.cve,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references,
        }


@dataclass
class DetectorResult:
    """Result of a dynamic detection scan.

    Attributes:
        detector_name: Name of the detector
        target: Target that was scanned (host:port)
        findings: List of findings
        errors: Any errors encountered
        metadata: Additional metadata about the scan
    """
    detector_name: str
    target: str = ""
    findings: List[DetectorFinding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    @property
    def is_vulnerable(self) -> bool:
        """Check if any finding indicates vulnerability."""
        return any(
            f.status == VulnerabilityStatus.VULNERABLE
            for f in self.findings
        )

    @property
    def has_critical(self) -> bool:
        """Check if any critical vulnerabilities found."""
        return any(
            f.status == VulnerabilityStatus.VULNERABLE and
            f.severity == DetectorSeverity.CRITICAL
            for f in self.findings
        )

    def to_dict(self) -> dict:
        """Convert result to dictionary."""
        return {
            "detector": self.detector_name,
            "target": self.target,
            "is_vulnerable": self.is_vulnerable,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "metadata": self.metadata,
        }


class BaseDetector(ABC):
    """Abstract base class for dynamic vulnerability detectors.

    All detectors MUST follow these safety guidelines:
    1. Detection only - no actual exploitation
    2. No data exfiltration - don't capture real credentials
    3. No persistent changes - don't modify target systems
    4. Minimal requests - avoid causing denial of service
    5. Clear documentation - explain all network activity

    Reference: docs/DISCLOSURE_POLICY.md
    """

    name: str = "base"
    description: str = "Base detector"
    cve: Optional[str] = None
    references: List[str] = []

    # Safety flags
    makes_network_requests: bool = True
    modifies_target: bool = False  # Must always be False
    requires_auth: bool = False

    @abstractmethod
    def detect(
        self,
        host: str,
        port: int = 18789,
        **kwargs
    ) -> DetectorResult:
        """
        Perform vulnerability detection.

        This method should:
        - Check for the presence of a vulnerability
        - NOT exploit the vulnerability
        - NOT exfiltrate any data
        - Return clear findings with evidence

        Args:
            host: Target hostname or IP
            port: Target port (default: 18789)
            **kwargs: Additional detector-specific options

        Returns:
            DetectorResult containing findings
        """
        pass

    def _create_result(self, host: str, port: int) -> DetectorResult:
        """Create a new DetectorResult with common metadata."""
        return DetectorResult(
            detector_name=self.name,
            target=f"{host}:{port}",
            metadata={
                "detector_version": "0.1.0",
                "cve": self.cve,
                "references": self.references,
            }
        )
