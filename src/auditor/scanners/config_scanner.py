"""Configuration scanner for OpenClaw deployments."""

import os
import re
from pathlib import Path
from typing import List, Optional

import yaml

from .base import BaseScanner, Finding, ScanResult, Severity


class ConfigScanner(BaseScanner):
    """Scans OpenClaw configuration files for security issues."""

    name = "config"
    description = "Scan configuration files for security misconfigurations"

    # Dangerous default configurations
    DANGEROUS_PATTERNS = [
        {
            "pattern": r"bind[_\s]*(?:address|host)?\s*[=:]\s*['\"]?0\.0\.0\.0",
            "title": "Binding to all interfaces (0.0.0.0)",
            "severity": Severity.CRITICAL,
            "description": "OpenClaw is configured to listen on all network interfaces, "
                          "exposing it to the public internet.",
            "remediation": "Change bind address to 127.0.0.1 for local-only access, "
                          "or use a specific internal IP address.",
            "cve": None,
        },
        {
            "pattern": r"auth[_\s]*(?:enabled|required)?\s*[=:]\s*['\"]?(?:false|no|0)",
            "title": "Authentication disabled",
            "severity": Severity.CRITICAL,
            "description": "Authentication is explicitly disabled, allowing unauthorized access.",
            "remediation": "Enable authentication and configure strong credentials.",
            "cve": None,
        },
        {
            "pattern": r"debug\s*[=:]\s*['\"]?(?:true|yes|1)",
            "title": "Debug mode enabled",
            "severity": Severity.MEDIUM,
            "description": "Debug mode is enabled which may expose sensitive information.",
            "remediation": "Disable debug mode in production deployments.",
            "cve": None,
        },
        {
            "pattern": r"ssl[_\s]*(?:enabled|verify)?\s*[=:]\s*['\"]?(?:false|no|0)",
            "title": "SSL/TLS disabled or verification bypassed",
            "severity": Severity.HIGH,
            "description": "SSL/TLS is disabled or certificate verification is bypassed.",
            "remediation": "Enable SSL/TLS and proper certificate verification.",
            "cve": None,
        },
        {
            "pattern": r"allow[_\s]*(?:all|any)[_\s]*(?:origins?|hosts?)\s*[=:]\s*['\"]?(?:true|\*)",
            "title": "Unrestricted CORS/Host access",
            "severity": Severity.MEDIUM,
            "description": "CORS or host restrictions are disabled, allowing requests from any origin.",
            "remediation": "Configure specific allowed origins and hosts.",
            "cve": None,
        },
        {
            "pattern": r"sandbox[_\s]*(?:enabled|mode)?\s*[=:]\s*['\"]?(?:false|no|0|disabled)",
            "title": "Sandbox mode disabled",
            "severity": Severity.HIGH,
            "description": "Sandbox mode is disabled, allowing unrestricted system access.",
            "remediation": "Enable sandbox mode to restrict agent capabilities.",
            "cve": None,
        },
        {
            "pattern": r"port\s*[=:]\s*['\"]?18789",
            "title": "Default port 18789 in use",
            "severity": Severity.LOW,
            "description": "Using the default port makes the instance easier to discover.",
            "remediation": "Consider using a non-default port.",
            "cve": None,
        },
        {
            "pattern": r"admin[_\s]*password\s*[=:]\s*['\"]?(?:admin|password|123456|openclaw)",
            "title": "Weak admin password detected",
            "severity": Severity.CRITICAL,
            "description": "A weak or default admin password is configured.",
            "remediation": "Use a strong, unique password for admin access.",
            "cve": None,
        },
    ]

    CONFIG_FILES = [
        "config.yaml",
        "config.yml",
        "openclaw.yaml",
        "openclaw.yml",
        "settings.yaml",
        "settings.yml",
        ".env",
        "docker-compose.yaml",
        "docker-compose.yml",
    ]

    def scan(self, target: str, **kwargs) -> ScanResult:
        """
        Scan OpenClaw configuration for security issues.

        Args:
            target: Path to OpenClaw installation directory

        Returns:
            ScanResult with configuration findings
        """
        result = ScanResult(scanner_name=self.name)
        target_path = Path(target)

        if not target_path.exists():
            result.errors.append(f"Target path does not exist: {target}")
            return result

        # Find and scan all config files
        config_files = self._find_config_files(target_path)

        for config_file in config_files:
            result.scanned_items += 1
            findings = self._scan_file(config_file)
            result.findings.extend(findings)

        # Check for missing security configurations
        missing_findings = self._check_missing_security(target_path)
        result.findings.extend(missing_findings)

        return result

    def _find_config_files(self, target_path: Path) -> List[Path]:
        """Find all configuration files in the target directory."""
        found_files = []

        # Check root directory
        for config_name in self.CONFIG_FILES:
            config_path = target_path / config_name
            if config_path.exists():
                found_files.append(config_path)

        # Check common subdirectories
        for subdir in ["config", "conf", "etc", ".openclaw"]:
            subdir_path = target_path / subdir
            if subdir_path.exists() and subdir_path.is_dir():
                for config_name in self.CONFIG_FILES:
                    config_path = subdir_path / config_name
                    if config_path.exists():
                        found_files.append(config_path)

        return found_files

    def _scan_file(self, file_path: Path) -> List[Finding]:
        """Scan a single configuration file for issues."""
        findings = []

        try:
            content = file_path.read_text()
        except Exception as e:
            return findings

        for pattern_info in self.DANGEROUS_PATTERNS:
            if re.search(pattern_info["pattern"], content, re.IGNORECASE | re.MULTILINE):
                findings.append(Finding(
                    title=pattern_info["title"],
                    severity=pattern_info["severity"],
                    description=pattern_info["description"],
                    location=str(file_path),
                    cve=pattern_info["cve"],
                    remediation=pattern_info["remediation"],
                ))

        return findings

    def _check_missing_security(self, target_path: Path) -> List[Finding]:
        """Check for missing security configurations."""
        findings = []

        # Check for missing .env file with secrets management
        env_path = target_path / ".env"
        env_example_path = target_path / ".env.example"

        if env_example_path.exists() and not env_path.exists():
            findings.append(Finding(
                title="Missing .env configuration",
                severity=Severity.INFO,
                description="A .env.example file exists but no .env file was found.",
                location=str(target_path),
                remediation="Copy .env.example to .env and configure your secrets.",
            ))

        return findings
