"""Base scanner interface for all security scanners."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    """Severity levels for security findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """Represents a security finding."""

    title: str
    severity: Severity
    description: str
    location: Optional[str] = None
    cve: Optional[str] = None
    remediation: Optional[str] = None
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert finding to dictionary."""
        return {
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "location": self.location,
            "cve": self.cve,
            "remediation": self.remediation,
            "references": self.references,
        }


@dataclass
class ScanResult:
    """Result of a security scan."""

    scanner_name: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scanned_items: int = 0

    @property
    def has_critical(self) -> bool:
        return any(f.severity == Severity.CRITICAL for f in self.findings)

    @property
    def has_high(self) -> bool:
        return any(f.severity == Severity.HIGH for f in self.findings)

    def to_dict(self) -> dict:
        """Convert result to dictionary."""
        return {
            "scanner": self.scanner_name,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "scanned_items": self.scanned_items,
            "summary": {
                "total": len(self.findings),
                "critical": sum(1 for f in self.findings if f.severity == Severity.CRITICAL),
                "high": sum(1 for f in self.findings if f.severity == Severity.HIGH),
                "medium": sum(1 for f in self.findings if f.severity == Severity.MEDIUM),
                "low": sum(1 for f in self.findings if f.severity == Severity.LOW),
                "info": sum(1 for f in self.findings if f.severity == Severity.INFO),
            },
        }


class BaseScanner(ABC):
    """Abstract base class for all scanners."""

    name: str = "base"
    description: str = "Base scanner"

    @abstractmethod
    def scan(self, target: str, **kwargs) -> ScanResult:
        """
        Perform the security scan.

        Args:
            target: Path to scan or target identifier
            **kwargs: Additional scanner-specific options

        Returns:
            ScanResult containing all findings
        """
        pass
