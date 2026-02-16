"""Secret and credential scanner for OpenClaw deployments."""

import os
import re
from pathlib import Path
from typing import Dict, List, Set

from .base import BaseScanner, Finding, ScanResult, Severity


class SecretScanner(BaseScanner):
    """Scans for exposed secrets, API keys, and credentials."""

    name = "secrets"
    description = "Scan for exposed API keys, credentials, and sensitive data"

    # Patterns for detecting secrets
    SECRET_PATTERNS: Dict[str, dict] = {
        "openai_api_key": {
            "pattern": r"sk-[a-zA-Z0-9]{48}",
            "title": "OpenAI API Key Exposed",
            "severity": Severity.CRITICAL,
            "description": "An OpenAI API key was found in the codebase.",
        },
        "anthropic_api_key": {
            "pattern": r"sk-ant-[a-zA-Z0-9\-]{80,}",
            "title": "Anthropic API Key Exposed",
            "severity": Severity.CRITICAL,
            "description": "An Anthropic API key was found in the codebase.",
        },
        "generic_api_key": {
            "pattern": r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?",
            "title": "Generic API Key Exposed",
            "severity": Severity.HIGH,
            "description": "A potential API key was found in the codebase.",
        },
        "aws_access_key": {
            "pattern": r"AKIA[0-9A-Z]{16}",
            "title": "AWS Access Key Exposed",
            "severity": Severity.CRITICAL,
            "description": "An AWS access key ID was found in the codebase.",
        },
        "aws_secret_key": {
            "pattern": r"(?i)aws[_\-]?secret[_\-]?(?:access[_\-]?)?key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
            "title": "AWS Secret Key Exposed",
            "severity": Severity.CRITICAL,
            "description": "An AWS secret access key was found in the codebase.",
        },
        "github_token": {
            "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,}",
            "title": "GitHub Token Exposed",
            "severity": Severity.CRITICAL,
            "description": "A GitHub personal access token was found in the codebase.",
        },
        "private_key": {
            "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            "title": "Private Key Exposed",
            "severity": Severity.CRITICAL,
            "description": "A private key was found in the codebase.",
        },
        "password_in_config": {
            "pattern": r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]?([^'\"\s\n]{8,})['\"]?",
            "title": "Password in Configuration",
            "severity": Severity.HIGH,
            "description": "A hardcoded password was found in the configuration.",
        },
        "database_url": {
            "pattern": r"(?i)(?:postgres|mysql|mongodb|redis)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+",
            "title": "Database Connection String with Credentials",
            "severity": Severity.CRITICAL,
            "description": "A database connection string with embedded credentials was found.",
        },
        "slack_app_token": {
            "pattern": r"xapp-[0-9]+-[A-Za-z0-9]+-[0-9]+-[a-f0-9]+",
            "title": "Slack App-Level Token Exposed",
            "severity": Severity.CRITICAL,
            "description": "A Slack app-level token (xapp-*) was found. "
                          "This token grants access to the Slack Events API and Socket Mode.",
        },
        "slack_bot_token": {
            "pattern": r"xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+",
            "title": "Slack Bot Token Exposed",
            "severity": Severity.CRITICAL,
            "description": "A Slack bot token (xoxb-*) was found. "
                          "This token grants bot-level access to the Slack workspace.",
        },
        "slack_user_token": {
            "pattern": r"xoxp-[0-9]+-[0-9]+-[0-9]+-[a-f0-9]+",
            "title": "Slack User Token Exposed",
            "severity": Severity.CRITICAL,
            "description": "A Slack user token (xoxp-*) was found. "
                          "This token grants user-level access to the Slack workspace.",
        },
        "slack_webhook": {
            "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+",
            "title": "Slack Webhook URL Exposed",
            "severity": Severity.MEDIUM,
            "description": "A Slack webhook URL was found in the codebase.",
        },
        "discord_webhook": {
            "pattern": r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
            "title": "Discord Webhook URL Exposed",
            "severity": Severity.MEDIUM,
            "description": "A Discord webhook URL was found in the codebase.",
        },
        "telegram_bot_token": {
            "pattern": r"[0-9]{8,10}:[A-Za-z0-9_-]{35}",
            "title": "Telegram Bot Token Exposed",
            "severity": Severity.HIGH,
            "description": "A Telegram bot token was found in the codebase.",
        },
        "jwt_secret": {
            "pattern": r"(?i)(?:jwt[_\-]?secret|secret[_\-]?key)\s*[=:]\s*['\"]?([A-Za-z0-9+/=]{32,})['\"]?",
            "title": "JWT Secret Exposed",
            "severity": Severity.CRITICAL,
            "description": "A JWT secret key was found in the codebase.",
        },
    }

    # Files to skip
    SKIP_PATTERNS: Set[str] = {
        ".git",
        "node_modules",
        "__pycache__",
        ".env.example",
        ".env.template",
        ".env.sample",
        "*.md",
        "*.lock",
        "*.min.js",
        "*.min.css",
    }

    # File extensions to scan
    SCAN_EXTENSIONS: Set[str] = {
        ".py", ".js", ".ts", ".jsx", ".tsx",
        ".yaml", ".yml", ".json", ".toml",
        ".env", ".conf", ".cfg", ".ini",
        ".sh", ".bash", ".zsh",
        ".xml", ".properties",
    }

    def scan(self, target: str, **kwargs) -> ScanResult:
        """
        Scan for exposed secrets in the target directory.

        Args:
            target: Path to scan

        Returns:
            ScanResult with secret findings
        """
        result = ScanResult(scanner_name=self.name)
        target_path = Path(target)

        if not target_path.exists():
            result.errors.append(f"Target path does not exist: {target}")
            return result

        # Find all files to scan
        files_to_scan = self._find_files(target_path)

        for file_path in files_to_scan:
            result.scanned_items += 1
            findings = self._scan_file(file_path)
            result.findings.extend(findings)

        return result

    def _find_files(self, target_path: Path) -> List[Path]:
        """Find all files that should be scanned."""
        files = []

        for root, dirs, filenames in os.walk(target_path):
            # Filter out skipped directories
            dirs[:] = [d for d in dirs if d not in self.SKIP_PATTERNS
                      and not d.startswith(".")]

            for filename in filenames:
                # Check if file should be scanned
                if self._should_scan_file(filename):
                    files.append(Path(root) / filename)

        return files

    def _should_scan_file(self, filename: str) -> bool:
        """Check if a file should be scanned."""
        # Skip patterns
        for pattern in self.SKIP_PATTERNS:
            if pattern.startswith("*"):
                if filename.endswith(pattern[1:]):
                    return False
            elif filename == pattern:
                return False

        # Check extension or specific filenames
        if filename.startswith(".env") or filename in {"Dockerfile", "Makefile"}:
            return True

        suffix = Path(filename).suffix
        return suffix in self.SCAN_EXTENSIONS

    def _scan_file(self, file_path: Path) -> List[Finding]:
        """Scan a single file for secrets."""
        findings = []

        try:
            content = file_path.read_text(errors="ignore")
        except Exception:
            return findings

        # Track found secrets to avoid duplicates
        found_secrets: Set[str] = set()

        for secret_type, pattern_info in self.SECRET_PATTERNS.items():
            matches = re.finditer(pattern_info["pattern"], content)

            for match in matches:
                # Get the matched secret (redacted)
                secret = match.group(0)
                redacted = self._redact_secret(secret)

                # Avoid duplicate findings for the same secret
                if redacted in found_secrets:
                    continue
                found_secrets.add(redacted)

                # Find line number
                line_num = content[:match.start()].count("\n") + 1

                findings.append(Finding(
                    title=pattern_info["title"],
                    severity=pattern_info["severity"],
                    description=f"{pattern_info['description']} Value: {redacted}",
                    location=f"{file_path}:{line_num}",
                    remediation="Remove the secret from the codebase and rotate it immediately. "
                               "Use environment variables or a secrets manager instead.",
                ))

        return findings

    def _redact_secret(self, secret: str) -> str:
        """Redact a secret for safe display."""
        if len(secret) <= 8:
            return "*" * len(secret)
        return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]
