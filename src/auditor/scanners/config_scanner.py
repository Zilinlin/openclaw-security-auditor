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

    # Dangerous default configurations (regex-based, flat key=value style)
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

    # OpenClaw-specific YAML structure checks (parsed from YAML, not regex)
    YAML_CHECKS = [
        {
            "check": "no_auth_section",
            "title": "No authentication configured",
            "severity": Severity.CRITICAL,
            "description": "The OpenClaw configuration has no 'auth' or 'security' section. "
                          "The gateway API will be accessible without authentication (CVE-2026-25157).",
            "remediation": "Add an auth section with API key or JWT authentication. "
                          "See https://docs.openclaw.ai/gateway/security",
            "cve": "CVE-2026-25157",
        },
        {
            "check": "system_prompt_in_config",
            "title": "System prompt exposed in config file",
            "severity": Severity.MEDIUM,
            "description": "The agent system prompt is stored directly in the config file. "
                          "If this file is accessible or committed to version control, "
                          "the prompt can be extracted and used for prompt injection attacks.",
            "remediation": "Store the system prompt in a separate file (e.g., SOUL.md) "
                          "and reference it from config, or use environment variables.",
            "cve": None,
        },
        {
            "check": "slack_tokens_in_config",
            "title": "Slack tokens stored in plaintext config",
            "severity": Severity.HIGH,
            "description": "Slack appToken and/or botToken are stored directly in the config file. "
                          "These tokens grant access to the Slack workspace and should be secured.",
            "remediation": "Move Slack tokens to environment variables or a secrets manager. "
                          "Use SLACK_APP_TOKEN and SLACK_BOT_TOKEN env vars instead.",
            "cve": None,
        },
        {
            "check": "no_cors_origin_config",
            "title": "No WebSocket origin validation configured",
            "severity": Severity.HIGH,
            "description": "No 'cors' or 'allowedOrigins' is configured for the gateway. "
                          "The WebSocket server may accept connections from any origin, "
                          "enabling Cross-Site WebSocket Hijacking (CVE-2026-25253).",
            "remediation": "Configure allowedOrigins in the gateway section to restrict "
                          "WebSocket connections to trusted domains.",
            "cve": "CVE-2026-25253",
        },
        {
            "check": "default_gateway_port",
            "title": "Default gateway port in use",
            "severity": Severity.LOW,
            "description": "The gateway is using a well-known default port, making it easier to discover.",
            "remediation": "Consider using a non-default port for the gateway.",
            "cve": None,
        },
    ]

    # Default ports used by OpenClaw
    DEFAULT_PORTS = {18789, 18790, 18791, 3000, 3001}

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

        # Regex-based pattern matching (flat key=value configs, .env, etc.)
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

        # YAML-aware structural checks for OpenClaw configs
        if file_path.suffix in (".yaml", ".yml"):
            yaml_findings = self._scan_yaml_structure(file_path, content)
            findings.extend(yaml_findings)

        return findings

    def _scan_yaml_structure(self, file_path: Path, content: str) -> List[Finding]:
        """Scan parsed YAML for OpenClaw-specific structural issues."""
        findings = []

        try:
            config = yaml.safe_load(content)
        except yaml.YAMLError:
            return findings

        if not isinstance(config, dict):
            return findings

        # Only run OpenClaw checks if this looks like an OpenClaw config
        if not self._is_openclaw_config(config):
            return findings

        for check_info in self.YAML_CHECKS:
            check_name = check_info["check"]
            is_issue = False

            if check_name == "no_auth_section":
                is_issue = self._check_no_auth(config)
            elif check_name == "system_prompt_in_config":
                is_issue = self._check_system_prompt_in_config(config)
            elif check_name == "slack_tokens_in_config":
                is_issue = self._check_slack_tokens_in_config(config)
            elif check_name == "no_cors_origin_config":
                is_issue = self._check_no_cors_origin(config)
            elif check_name == "default_gateway_port":
                is_issue = self._check_default_port(config)

            if is_issue:
                findings.append(Finding(
                    title=check_info["title"],
                    severity=check_info["severity"],
                    description=check_info["description"],
                    location=str(file_path),
                    cve=check_info.get("cve"),
                    remediation=check_info["remediation"],
                ))

        return findings

    def _is_openclaw_config(self, config: dict) -> bool:
        """Check if this YAML looks like an OpenClaw configuration."""
        # OpenClaw configs typically have 'agent', 'gateway', or 'channels' keys
        openclaw_keys = {"agent", "gateway", "channels", "skills", "tools"}
        return bool(openclaw_keys & set(config.keys()))

    def _check_no_auth(self, config: dict) -> bool:
        """Check if authentication is missing from config."""
        # Look for auth config in common locations
        if "auth" in config or "security" in config or "authentication" in config:
            return False
        gateway = config.get("gateway", {})
        if isinstance(gateway, dict) and ("auth" in gateway or "security" in gateway):
            return False
        return True

    def _check_system_prompt_in_config(self, config: dict) -> bool:
        """Check if system prompt is stored directly in config."""
        agent = config.get("agent", {})
        if isinstance(agent, dict):
            prompt = agent.get("systemPrompt", agent.get("system_prompt", ""))
            # Flag if prompt is a substantial inline string (not a file reference)
            if isinstance(prompt, str) and len(prompt) > 50:
                return True
        return False

    def _check_slack_tokens_in_config(self, config: dict) -> bool:
        """Check if Slack tokens are stored in plaintext config."""
        channels = config.get("channels", {})
        if not isinstance(channels, dict):
            return False
        slack = channels.get("slack", {})
        if not isinstance(slack, dict):
            return False
        has_app_token = bool(slack.get("appToken"))
        has_bot_token = bool(slack.get("botToken"))
        return has_app_token or has_bot_token

    def _check_no_cors_origin(self, config: dict) -> bool:
        """Check if WebSocket origin validation is missing."""
        gateway = config.get("gateway", {})
        if not isinstance(gateway, dict):
            return True
        # Look for origin/cors configuration
        has_cors = any(
            key in gateway
            for key in ("cors", "allowedOrigins", "allowed_origins", "origin")
        )
        return not has_cors

    def _check_default_port(self, config: dict) -> bool:
        """Check if a default gateway port is being used."""
        gateway = config.get("gateway", {})
        if isinstance(gateway, dict):
            port = gateway.get("port")
            if port in self.DEFAULT_PORTS:
                return True
        return False

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
