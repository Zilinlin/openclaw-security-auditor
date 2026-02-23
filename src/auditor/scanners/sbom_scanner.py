"""Software Bill of Materials (SBOM) scanner for AI agent dependencies.

Analyzes agent configuration for supply chain risks including unpinned
versions, unverified sources, and missing integrity checks for MCP servers,
skills/plugins, and model providers.

References:
- OWASP Agentic AI Top 10 ASI03: Supply Chain Vulnerabilities
- https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- https://www.incredibuild.com/blog/the-hidden-supply-chain-in-your-ai-agent-why-sboms-for-mcp-servers-matter-now
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from .base import BaseScanner, Finding, ScanResult, Severity


class SBOMScanner(BaseScanner):
    """Scan agent dependencies for supply chain risks and generate SBOM analysis."""

    name = "sbom"
    description = "Analyze agent dependency supply chain for security risks"

    # Trusted package registries / orgs
    TRUSTED_NPM_SCOPES = {
        "@modelcontextprotocol",
        "@anthropic-ai",
        "@openai",
        "@langchain",
        "@llamaindex",
    }

    TRUSTED_DOMAINS = {
        "github.com",
        "npmjs.com",
        "registry.npmjs.org",
        "pypi.org",
        "files.pythonhosted.org",
    }

    # Config files to scan
    CONFIG_FILES = [
        "config.yaml",
        "config.yml",
        "openclaw.yaml",
        "openclaw.yml",
        "agent.yaml",
        "agent.yml",
        "settings.yaml",
        "settings.yml",
    ]

    # MCP-specific config files
    MCP_CONFIG_FILES = [
        ".mcp.json",
        "mcp.json",
        "mcp_config.json",
        "claude_desktop_config.json",
    ]

    def scan(self, target: str, **kwargs) -> ScanResult:
        """Scan agent dependencies for supply chain risks.

        Args:
            target: Path to OpenClaw installation directory

        Returns:
            ScanResult with supply chain findings
        """
        result = ScanResult(scanner_name=self.name)
        target_path = Path(target)

        if not target_path.exists():
            result.errors.append(f"Target path does not exist: {target}")
            return result

        # Scan YAML config files
        for config_file in self._find_yaml_configs(target_path):
            result.scanned_items += 1
            findings = self._scan_yaml_config(config_file)
            result.findings.extend(findings)

        # Scan MCP JSON config files
        for mcp_file in self._find_mcp_configs(target_path):
            result.scanned_items += 1
            findings = self._scan_mcp_json(mcp_file)
            result.findings.extend(findings)

        return result

    def _find_yaml_configs(self, target_path: Path) -> list[Path]:
        """Find YAML agent config files."""
        found = []
        for name in self.CONFIG_FILES:
            path = target_path / name
            if path.exists():
                found.append(path)
        for subdir in ["config", "conf", "etc", ".openclaw"]:
            subdir_path = target_path / subdir
            if subdir_path.exists() and subdir_path.is_dir():
                for name in self.CONFIG_FILES:
                    path = subdir_path / name
                    if path.exists():
                        found.append(path)
        return found

    def _find_mcp_configs(self, target_path: Path) -> list[Path]:
        """Find MCP JSON config files."""
        found = []
        for name in self.MCP_CONFIG_FILES:
            path = target_path / name
            if path.exists():
                found.append(path)
        # Also check .config subdirectory
        config_dir = target_path / ".config"
        if config_dir.exists():
            for name in self.MCP_CONFIG_FILES:
                path = config_dir / name
                if path.exists():
                    found.append(path)
        return found

    def _scan_yaml_config(self, file_path: Path) -> list[Finding]:
        """Scan a YAML config file for supply chain issues."""
        findings: list[Finding] = []

        try:
            content = file_path.read_text()
            config = yaml.safe_load(content)
        except (OSError, yaml.YAMLError):
            return findings

        if not isinstance(config, dict):
            return findings

        # Scan MCP servers in YAML
        mcp_servers = config.get("mcp_servers", config.get("mcpServers", []))
        if isinstance(mcp_servers, list):
            for server in mcp_servers:
                if isinstance(server, dict):
                    findings.extend(self._check_mcp_server(server, file_path))
        elif isinstance(mcp_servers, dict):
            for name, server_config in mcp_servers.items():
                if isinstance(server_config, dict):
                    server_config.setdefault("name", name)
                    findings.extend(self._check_mcp_server(server_config, file_path))

        # Scan skills/plugins
        skills = config.get("skills", config.get("plugins", []))
        if isinstance(skills, list):
            for skill in skills:
                if isinstance(skill, dict):
                    findings.extend(self._check_skill(skill, file_path))
        elif isinstance(skills, dict):
            for name, skill_config in skills.items():
                if isinstance(skill_config, dict):
                    skill_config.setdefault("name", name)
                    findings.extend(self._check_skill(skill_config, file_path))

        # Scan model configuration
        models = config.get("models", config.get("llm", config.get("model", {})))
        if isinstance(models, dict):
            findings.extend(self._check_model_config(models, file_path))

        return findings

    def _scan_mcp_json(self, file_path: Path) -> list[Finding]:
        """Scan an MCP JSON config file for supply chain issues."""
        findings: list[Finding] = []

        try:
            content = file_path.read_text()
            config = json.loads(content)
        except (OSError, json.JSONDecodeError):
            return findings

        if not isinstance(config, dict):
            return findings

        # Handle both {mcpServers: {...}} and direct server dict formats
        servers = config.get("mcpServers", config.get("mcp_servers", config))

        if isinstance(servers, dict):
            for name, server_config in servers.items():
                if isinstance(server_config, dict):
                    server_config.setdefault("name", name)
                    findings.extend(self._check_mcp_server(server_config, file_path))

        return findings

    def _check_mcp_server(self, server: dict, file_path: Path) -> list[Finding]:
        """Check a single MCP server configuration for supply chain risks."""
        findings: list[Finding] = []
        name = server.get("name", "unknown")

        # Get the command/source
        command = server.get("command", server.get("source", ""))
        args = server.get("args", [])

        # Build full command string for analysis
        if isinstance(args, list):
            source_str = f"{command} {' '.join(str(a) for a in args)}".strip()
        else:
            source_str = str(command)

        if not source_str:
            return findings

        # Check 1: Version pinning
        if not self._has_version_pin(source_str):
            findings.append(
                Finding(
                    title=f"MCP server version not pinned: {name}",
                    severity=Severity.HIGH,
                    description=f"MCP server '{name}' has no version pinned in its source "
                    f"({source_str}). Without version pinning, updates could introduce "
                    "malicious code (supply chain attack).",
                    location=str(file_path),
                    remediation="Pin the version explicitly, e.g., "
                    "'npx @scope/package@1.2.3' or specify a version field.",
                    references=[
                        "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks"
                    ],
                )
            )

        # Check 2: Source trust
        is_trusted, reason = self._check_source_trust(source_str)
        if not is_trusted:
            findings.append(
                Finding(
                    title=f"MCP server from unverified source: {name}",
                    severity=Severity.HIGH,
                    description=f"MCP server '{name}' is loaded from an unverified source. "
                    f"{reason}",
                    location=str(file_path),
                    remediation="Use MCP servers from trusted registries "
                    "(npm @modelcontextprotocol/*, PyPI, or verified GitHub repos).",
                    references=[
                        "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks"
                    ],
                )
            )

        # Check 3: Integrity
        integrity_keys = {"checksum", "sha256", "integrity", "hash", "signature"}
        if not (integrity_keys & set(server.keys())):
            findings.append(
                Finding(
                    title=f"MCP server without integrity check: {name}",
                    severity=Severity.MEDIUM,
                    description=f"MCP server '{name}' has no checksum or integrity verification. "
                    "A compromised package could be substituted without detection.",
                    location=str(file_path),
                    remediation="Add a checksum or integrity hash for the MCP server package.",
                    references=[
                        "https://www.incredibuild.com/blog/the-hidden-supply-chain-in-your-ai-agent-why-sboms-for-mcp-servers-matter-now"
                    ],
                )
            )

        return findings

    def _check_skill(self, skill: dict, file_path: Path) -> list[Finding]:
        """Check a single skill/plugin for supply chain risks."""
        findings: list[Finding] = []
        name = skill.get("name", "unknown")

        # Check 1: Version pinning
        version = skill.get("version", "")
        if not version or version in ("*", "latest", "newest"):
            findings.append(
                Finding(
                    title=f"Skill version not pinned: {name}",
                    severity=Severity.HIGH,
                    description=f"Skill '{name}' has no pinned version ('{version or 'missing'}'). "
                    "Automatic updates could introduce malicious code.",
                    location=str(file_path),
                    remediation="Pin the skill to a specific version, e.g., version: '1.2.3'.",
                    references=[
                        "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
                    ],
                )
            )

        # Check 2: Source trust
        source = skill.get("source", "")
        if isinstance(source, str) and source.startswith(("http://", "https://")):
            is_trusted, reason = self._check_source_trust(source)
            if not is_trusted:
                findings.append(
                    Finding(
                        title=f"Skill from unverified source: {name}",
                        severity=Severity.HIGH,
                        description=f"Skill '{name}' is loaded from an unverified source. {reason}",
                        location=str(file_path),
                        remediation="Use skills from trusted registries or verified sources.",
                        references=[
                            "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
                        ],
                    )
                )

        # Check 3: Signature
        sig_keys = {"signature", "verified", "signed", "gpg_signature"}
        if not (sig_keys & set(skill.keys())):
            findings.append(
                Finding(
                    title=f"Skill without signature verification: {name}",
                    severity=Severity.MEDIUM,
                    description=f"Skill '{name}' has no signature or verification field. "
                    "Its authenticity cannot be verified.",
                    location=str(file_path),
                    remediation="Add a signature or verified field for the skill.",
                    references=[
                        "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
                    ],
                )
            )

        return findings

    def _check_model_config(self, models: dict, file_path: Path) -> list[Finding]:
        """Check model provider configuration for supply chain risks."""
        findings: list[Finding] = []

        model_name = models.get("model", models.get("model_name", ""))
        if not isinstance(model_name, str) or not model_name:
            return findings

        # Check for unpinned model version (e.g., "gpt-4" vs "gpt-4-0613")
        # Models with dates or specific version identifiers are considered pinned
        if model_name and not self._is_model_version_pinned(model_name):
            findings.append(
                Finding(
                    title=f"Model version not pinned: {model_name}",
                    severity=Severity.LOW,
                    description=f"Model '{model_name}' does not specify an exact version. "
                    "Model behavior may change silently between updates.",
                    location=str(file_path),
                    remediation="Use a specific model version, e.g., 'gpt-4-0613' "
                    "or 'claude-sonnet-4-5-20250929' for reproducible behavior.",
                    references=[
                        "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
                    ],
                )
            )

        return findings

    def _has_version_pin(self, source: str) -> bool:
        """Check if a source string contains a version pin."""
        # npm-style: @scope/package@version
        if re.search(r"@[\w\-]+/[\w\-]+@[\d]", source):
            return True
        # pip-style: package==version
        if re.search(r"==[\d]", source):
            return True
        # URL with version tag: /v1.2.3/ or /releases/tag/
        if re.search(r"/v?\d+\.\d+", source):
            return True
        # Explicit version flag
        if "--version" in source or "-v " in source:
            return True
        return False

    def _check_source_trust(self, source: str) -> tuple[bool, str]:
        """Check if a source is from a trusted registry.

        Returns:
            (is_trusted, reason) tuple
        """
        # npx commands from trusted scopes
        for scope in self.TRUSTED_NPM_SCOPES:
            if scope in source:
                return True, ""

        # Check for trusted domains in URLs
        for domain in self.TRUSTED_DOMAINS:
            if domain in source:
                return True, ""

        # Local commands (node, python, etc.) are considered trusted
        local_commands = {"node", "python", "python3", "uvx", "pipx"}
        first_word = source.split()[0] if source.split() else ""
        if first_word in local_commands:
            return True, ""

        # npx with unknown scope
        if source.startswith("npx "):
            pkg = source.split()[1] if len(source.split()) > 1 else ""
            if pkg.startswith("@"):
                scope = pkg.split("/")[0]
                if scope not in self.TRUSTED_NPM_SCOPES:
                    return False, f"npm scope '{scope}' is not in the trusted list."
            return True, ""  # npx with non-scoped packages are acceptable

        # URLs to unknown domains
        if source.startswith(("http://", "https://")):
            return False, f"Source URL '{source[:60]}...' is from an unverified domain."

        return True, ""

    def _is_model_version_pinned(self, model_name: str) -> bool:
        """Check if a model name includes a specific version identifier."""
        # Models with date stamps (e.g., gpt-4-0613, claude-sonnet-4-5-20250929)
        if re.search(r"\d{4,8}$", model_name):
            return True
        # Models with version suffixes (e.g., gpt-4-turbo-2024-04-09)
        if re.search(r"\d{4}-\d{2}-\d{2}", model_name):
            return True
        # Models with explicit version (e.g., llama-3.1-70b)
        if re.search(r"\d+\.\d+", model_name):
            return True
        return False
