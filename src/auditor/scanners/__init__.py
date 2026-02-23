"""Security scanners for OpenClaw."""

from __future__ import annotations

from .base import BaseScanner, Finding, ScanResult, Severity
from .config_scanner import ConfigScanner
from .cve_scanner import CVEScanner
from .network_scanner import NetworkScanner
from .privilege_scanner import PrivilegeScanner
from .sbom_scanner import SBOMScanner
from .secret_scanner import SecretScanner

__all__ = [
    "BaseScanner",
    "Finding",
    "ScanResult",
    "Severity",
    "ConfigScanner",
    "CVEScanner",
    "NetworkScanner",
    "PrivilegeScanner",
    "SBOMScanner",
    "SecretScanner",
]

# Registry of available scanners
SCANNERS: dict[
    str,
    type[ConfigScanner]
    | type[CVEScanner]
    | type[SecretScanner]
    | type[NetworkScanner]
    | type[PrivilegeScanner]
    | type[SBOMScanner],
] = {
    "config": ConfigScanner,
    "cve": CVEScanner,
    "secrets": SecretScanner,
    "network": NetworkScanner,
    "privilege": PrivilegeScanner,
    "sbom": SBOMScanner,
}
