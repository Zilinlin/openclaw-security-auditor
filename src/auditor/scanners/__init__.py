"""Security scanners for OpenClaw."""

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
SCANNERS = {
    "config": ConfigScanner,
    "cve": CVEScanner,
    "secrets": SecretScanner,
    "network": NetworkScanner,
}
