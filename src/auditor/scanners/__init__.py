"""Security scanners for OpenClaw."""

from __future__ import annotations

from .base import BaseScanner, Finding, ScanResult, Severity
from .config_scanner import ConfigScanner
from .cve_scanner import CVEScanner
from .network_scanner import NetworkScanner
from .secret_scanner import SecretScanner

__all__ = [
    "BaseScanner",
    "Finding",
    "ScanResult",
    "Severity",
    "ConfigScanner",
    "CVEScanner",
    "NetworkScanner",
    "SecretScanner",
]

# Registry of available scanners
SCANNERS: dict[
    str, type[ConfigScanner] | type[CVEScanner] | type[SecretScanner] | type[NetworkScanner]
] = {
    "config": ConfigScanner,
    "cve": CVEScanner,
    "secrets": SecretScanner,
    "network": NetworkScanner,
}
