"""Agent privilege boundary scanner for OpenClaw deployments.

Analyzes agent configuration files for excessive permissions, missing access
controls, and privilege boundary violations.

References:
- OWASP Agentic AI Top 10 ASI02: Insecure Tool Use
- OWASP Agentic AI Top 10 ASI06: Excessive Agency
- https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from .base import BaseScanner, Finding, ScanResult, Severity


class PrivilegeScanner(BaseScanner):
    """Scan agent configuration for excessive permissions and privilege issues."""

    name = "privilege"
    description = "Scan agent configuration for privilege escalation, excessive permissions, and missing access controls"

    # Dangerous tool names that require restriction configs
    DANGEROUS_TOOLS: dict[str, dict] = {
        "shell_exec": {
            "severity": Severity.CRITICAL,
            "description": "Unrestricted shell execution allows arbitrary command execution.",
            "remediation": "Add allowed_commands and blocklist restrictions to shell_exec tool.",
        },
        "bash": {
            "severity": Severity.CRITICAL,
            "description": "Unrestricted bash access allows arbitrary command execution.",
            "remediation": "Add allowed_commands and blocklist restrictions to bash tool.",
        },
        "terminal": {
            "severity": Severity.CRITICAL,
            "description": "Unrestricted terminal access allows arbitrary command execution.",
            "remediation": "Add allowed_commands and blocklist restrictions to terminal tool.",
        },
        "command_exec": {
            "severity": Severity.CRITICAL,
            "description": "Unrestricted command execution allows arbitrary system commands.",
            "remediation": "Add allowed_commands and blocklist restrictions to command_exec tool.",
        },
        "code_exec": {
            "severity": Severity.CRITICAL,
            "description": "Unrestricted code execution allows running arbitrary code.",
            "remediation": "Add sandbox restrictions and language allowlist to code_exec tool.",
        },
        "eval": {
            "severity": Severity.CRITICAL,
            "description": "Eval tool allows arbitrary code execution without sandboxing.",
            "remediation": "Remove eval tool or replace with sandboxed code execution.",
        },
        "python_exec": {
            "severity": Severity.CRITICAL,
            "description": "Unrestricted Python execution allows arbitrary code.",
            "remediation": "Add sandbox restrictions and module allowlist to python_exec tool.",
        },
        "file_write": {
            "severity": Severity.HIGH,
            "description": "File write without path restrictions can overwrite critical files.",
            "remediation": "Configure allowed_paths to restrict file write locations.",
        },
        "write_file": {
            "severity": Severity.HIGH,
            "description": "File write without path restrictions can overwrite critical files.",
            "remediation": "Configure allowed_paths to restrict file write locations.",
        },
        "fs_write": {
            "severity": Severity.HIGH,
            "description": "Filesystem write without path restrictions can overwrite critical files.",
            "remediation": "Configure allowed_paths to restrict write locations.",
        },
        "file_delete": {
            "severity": Severity.HIGH,
            "description": "File deletion capability can remove critical system or config files.",
            "remediation": "Configure allowed_paths and add confirmation requirements.",
        },
        "database": {
            "severity": Severity.HIGH,
            "description": "Direct database access without query restrictions.",
            "remediation": "Use read-only connections or restrict to specific queries.",
        },
        "sql_exec": {
            "severity": Severity.HIGH,
            "description": "Direct SQL execution without parameterization or restrictions.",
            "remediation": "Use parameterized queries and restrict to read operations.",
        },
        "email": {
            "severity": Severity.MEDIUM,
            "description": "Email capability can be used for data exfiltration.",
            "remediation": "Restrict recipients to approved domains and require approval.",
        },
        "send_email": {
            "severity": Severity.MEDIUM,
            "description": "Email capability can be used for data exfiltration.",
            "remediation": "Restrict recipients to approved domains and require approval.",
        },
        "http_request": {
            "severity": Severity.MEDIUM,
            "description": "Unrestricted HTTP requests can be used for data exfiltration or SSRF.",
            "remediation": "Configure allowed_domains to restrict outbound HTTP requests.",
        },
        "fetch_url": {
            "severity": Severity.MEDIUM,
            "description": "Unrestricted URL fetching can be used for SSRF attacks.",
            "remediation": "Configure allowed_domains to restrict URL fetching.",
        },
        "web_request": {
            "severity": Severity.MEDIUM,
            "description": "Unrestricted web requests can be used for data exfiltration.",
            "remediation": "Configure allowed_domains to restrict outbound requests.",
        },
    }

    # Keys that indicate a tool has restrictions configured
    RESTRICTION_KEYS = {
        "allowed_paths",
        "allowedPaths",
        "allowed_commands",
        "allowedCommands",
        "allowed_domains",
        "allowedDomains",
        "restrictions",
        "blocklist",
        "allowlist",
        "sandbox",
        "read_only",
        "readOnly",
    }

    # Config files to scan (extends ConfigScanner's list)
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

    def scan(self, target: str, **kwargs) -> ScanResult:
        """Scan agent configuration for privilege boundary issues.

        Args:
            target: Path to OpenClaw installation directory

        Returns:
            ScanResult with privilege findings
        """
        result = ScanResult(scanner_name=self.name)
        target_path = Path(target)

        if not target_path.exists():
            result.errors.append(f"Target path does not exist: {target}")
            return result

        config_files = self._find_config_files(target_path)

        for config_file in config_files:
            result.scanned_items += 1
            findings = self._scan_file(config_file)
            result.findings.extend(findings)

        return result

    def _find_config_files(self, target_path: Path) -> list[Path]:
        """Find agent configuration files."""
        found_files = []

        for config_name in self.CONFIG_FILES:
            config_path = target_path / config_name
            if config_path.exists():
                found_files.append(config_path)

        for subdir in ["config", "conf", "etc", ".openclaw"]:
            subdir_path = target_path / subdir
            if subdir_path.exists() and subdir_path.is_dir():
                for config_name in self.CONFIG_FILES:
                    config_path = subdir_path / config_name
                    if config_path.exists():
                        found_files.append(config_path)

        return found_files

    def _scan_file(self, file_path: Path) -> list[Finding]:
        """Scan a single config file for privilege issues."""
        findings: list[Finding] = []

        try:
            content = file_path.read_text()
        except Exception:
            return findings

        if file_path.suffix not in (".yaml", ".yml"):
            return findings

        try:
            config = yaml.safe_load(content)
        except yaml.YAMLError:
            return findings

        if not isinstance(config, dict):
            return findings

        if not self._is_agent_config(config):
            return findings

        findings.extend(self._check_dangerous_tools(config, file_path))
        findings.extend(self._check_missing_approval_gates(config, file_path))
        findings.extend(self._check_unrestricted_filesystem(config, file_path))
        findings.extend(self._check_unrestricted_network(config, file_path))
        findings.extend(self._check_missing_rate_limits(config, file_path))
        findings.extend(self._check_overly_broad_scopes(config, file_path))
        findings.extend(self._check_no_sandbox(config, file_path))
        findings.extend(self._check_credential_exposure(config, file_path))

        return findings

    def _is_agent_config(self, config: dict) -> bool:
        """Check if this YAML looks like an agent configuration."""
        agent_keys = {"agent", "tools", "skills", "permissions", "gateway"}
        return bool(agent_keys & set(config.keys()))

    def _get_tools_list(self, config: dict) -> list[dict]:
        """Extract tools list from config, handling various formats."""
        tools = config.get("tools", [])
        if isinstance(tools, list):
            result = []
            for t in tools:
                if isinstance(t, dict):
                    result.append(t)
                elif isinstance(t, str):
                    result.append({"name": t})
            return result
        if isinstance(tools, dict):
            return [
                {"name": k, **v} if isinstance(v, dict) else {"name": k} for k, v in tools.items()
            ]
        return []

    def _tool_has_restrictions(self, tool: dict) -> bool:
        """Check if a tool has any restriction configuration."""
        return bool(self.RESTRICTION_KEYS & set(tool.keys()))

    def _check_dangerous_tools(self, config: dict, file_path: Path) -> list[Finding]:
        """Check for dangerous tools without restrictions."""
        findings: list[Finding] = []
        tools = self._get_tools_list(config)

        for tool in tools:
            tool_name = tool.get("name", "")
            if not tool_name:
                continue

            tool_lower = tool_name.lower()
            for dangerous_name, info in self.DANGEROUS_TOOLS.items():
                if tool_lower == dangerous_name or tool_lower.endswith(f"_{dangerous_name}"):
                    if not self._tool_has_restrictions(tool):
                        findings.append(
                            Finding(
                                title=f"Dangerous tool without restrictions: {tool_name}",
                                severity=info["severity"],
                                description=info["description"],
                                location=str(file_path),
                                remediation=info["remediation"],
                                references=[
                                    "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
                                ],
                            )
                        )
                    break

        return findings

    def _check_missing_approval_gates(self, config: dict, file_path: Path) -> list[Finding]:
        """Check for missing human-in-the-loop approval configuration."""
        agent = config.get("agent", {})
        if not isinstance(agent, dict):
            agent = {}

        approval_keys = {
            "approval_required",
            "approvalRequired",
            "human_in_loop",
            "humanInLoop",
            "confirmation",
            "confirm_actions",
            "confirmActions",
        }

        has_approval = bool(approval_keys & set(agent.keys()))

        # Also check top-level config
        if not has_approval:
            has_approval = bool(approval_keys & set(config.keys()))

        # Check if approval is explicitly disabled
        for key in approval_keys & set(agent.keys()):
            val = agent[key]
            if val is False or val == "false" or val == "no" or val == 0:
                return [
                    Finding(
                        title="Human approval explicitly disabled",
                        severity=Severity.HIGH,
                        description="Human-in-the-loop approval is explicitly disabled. "
                        "The agent can perform destructive actions without confirmation.",
                        location=str(file_path),
                        remediation="Enable approval_required for destructive actions "
                        "(file writes, shell commands, emails, API calls).",
                        references=[
                            "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
                        ],
                    )
                ]

        # If tools include dangerous ones but no approval gate exists
        tools = self._get_tools_list(config)
        has_dangerous_tools = any(
            tool.get("name", "").lower() in self.DANGEROUS_TOOLS for tool in tools
        )

        if has_dangerous_tools and not has_approval:
            return [
                Finding(
                    title="Missing approval gates for dangerous tools",
                    severity=Severity.HIGH,
                    description="Agent has access to dangerous tools but no human approval "
                    "mechanism is configured. Actions will execute without confirmation.",
                    location=str(file_path),
                    remediation="Add approval_required: true to agent config or configure "
                    "per-tool confirmation requirements.",
                    references=[
                        "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
                    ],
                )
            ]

        return []

    def _check_unrestricted_filesystem(self, config: dict, file_path: Path) -> list[Finding]:
        """Check for unrestricted filesystem access."""
        findings: list[Finding] = []

        # Check permissions section
        permissions = config.get("permissions", {})
        if isinstance(permissions, dict):
            fs_perm = permissions.get("filesystem", permissions.get("file_system", ""))
            if isinstance(fs_perm, str) and fs_perm.lower() in ("full", "unrestricted", "*", "all"):
                findings.append(
                    Finding(
                        title="Unrestricted filesystem access",
                        severity=Severity.HIGH,
                        description="Agent has unrestricted filesystem permissions. "
                        "It can read and write to any location on the system.",
                        location=str(file_path),
                        remediation="Restrict filesystem to specific directories using "
                        "allowed_paths configuration.",
                        references=[
                            "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
                        ],
                    )
                )

        # Check tools for wildcard paths
        tools = self._get_tools_list(config)
        for tool in tools:
            allowed = tool.get("allowed_paths", tool.get("allowedPaths"))
            if allowed == "*" or allowed == ["*"]:
                findings.append(
                    Finding(
                        title=f"Wildcard path access on tool: {tool.get('name', 'unknown')}",
                        severity=Severity.HIGH,
                        description="Tool has wildcard allowed_paths, granting access to "
                        "the entire filesystem.",
                        location=str(file_path),
                        remediation="Replace wildcard with specific directory paths.",
                        references=[
                            "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
                        ],
                    )
                )

        return findings

    def _check_unrestricted_network(self, config: dict, file_path: Path) -> list[Finding]:
        """Check for unrestricted outbound network access."""
        permissions = config.get("permissions", {})
        if isinstance(permissions, dict):
            net_perm = permissions.get("network", "")
            if isinstance(net_perm, str) and net_perm.lower() in (
                "unrestricted",
                "*",
                "all",
                "full",
            ):
                return [
                    Finding(
                        title="Unrestricted network access",
                        severity=Severity.HIGH,
                        description="Agent has unrestricted outbound network access. "
                        "This enables data exfiltration to arbitrary domains.",
                        location=str(file_path),
                        remediation="Configure allowed_domains to restrict outbound "
                        "connections to trusted services only.",
                        references=[
                            "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
                        ],
                    )
                ]

        # Check if network tools exist without domain restrictions
        tools = self._get_tools_list(config)
        network_tools = {"http_request", "fetch_url", "web_request"}
        for tool in tools:
            tool_name = tool.get("name", "").lower()
            if tool_name in network_tools:
                has_domain_config = any(
                    k in tool for k in ("allowed_domains", "allowedDomains", "domain_allowlist")
                )
                if not has_domain_config:
                    return [
                        Finding(
                            title=f"Network tool without domain restrictions: {tool.get('name')}",
                            severity=Severity.HIGH,
                            description="Network tool has no domain allowlist configured. "
                            "Agent can make requests to any domain.",
                            location=str(file_path),
                            remediation="Add allowed_domains to restrict outbound HTTP requests.",
                            references=[
                                "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
                            ],
                        )
                    ]

        return []

    def _check_missing_rate_limits(self, config: dict, file_path: Path) -> list[Finding]:
        """Check for missing action rate limits."""
        rate_limit_keys = {
            "rate_limits",
            "rateLimits",
            "rate_limit",
            "rateLimit",
            "max_actions",
            "maxActions",
            "throttle",
            "max_actions_per_minute",
            "maxActionsPerMinute",
        }

        has_rate_limits = bool(rate_limit_keys & set(config.keys()))

        agent = config.get("agent", {})
        if isinstance(agent, dict):
            has_rate_limits = has_rate_limits or bool(rate_limit_keys & set(agent.keys()))

        if not has_rate_limits:
            return [
                Finding(
                    title="No rate limits configured",
                    severity=Severity.MEDIUM,
                    description="No action rate limits are configured. A compromised agent "
                    "could perform unlimited actions in a short time.",
                    location=str(file_path),
                    remediation="Configure rate_limits to restrict action frequency "
                    "(e.g., max_actions_per_minute: 10).",
                    references=[
                        "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
                    ],
                )
            ]

        return []

    def _check_overly_broad_scopes(self, config: dict, file_path: Path) -> list[Finding]:
        """Check for overly broad API token scopes."""
        findings: list[Finding] = []

        overly_broad = {"admin", "write", "operator", "superuser", "root", "*"}

        # Check auth/token scopes
        auth = config.get("auth", config.get("authentication", {}))
        if isinstance(auth, dict):
            scopes = auth.get("scopes", auth.get("permissions", []))
            if isinstance(scopes, list):
                for scope in scopes:
                    scope_str = str(scope).lower()
                    if any(broad in scope_str for broad in overly_broad):
                        findings.append(
                            Finding(
                                title=f"Overly broad API scope: {scope}",
                                severity=Severity.HIGH,
                                description=f"API scope '{scope}' grants excessive permissions. "
                                "Follow the principle of least privilege.",
                                location=str(file_path),
                                remediation="Replace broad scopes with specific, "
                                "narrowly-scoped permissions (e.g., 'read:agents' instead of 'admin').",
                                references=[
                                    "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
                                ],
                            )
                        )

        return findings

    def _check_no_sandbox(self, config: dict, file_path: Path) -> list[Finding]:
        """Check for missing or disabled sandbox configuration."""
        agent = config.get("agent", {})
        if not isinstance(agent, dict):
            agent = {}

        sandbox_keys = {
            "sandbox",
            "container",
            "isolation",
            "sandboxed",
            "containerized",
        }

        # Check if sandbox is explicitly disabled
        for key in sandbox_keys:
            val = agent.get(key, config.get(key))
            if val is False or (
                isinstance(val, str) and val.lower() in ("false", "no", "0", "disabled")
            ):
                return [
                    Finding(
                        title="Sandbox explicitly disabled",
                        severity=Severity.HIGH,
                        description="Agent sandboxing is explicitly disabled. "
                        "The agent has direct access to the host system.",
                        location=str(file_path),
                        remediation="Enable sandbox mode or run the agent in a container.",
                        references=[
                            "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
                        ],
                    )
                ]

        # Check if no sandbox config exists at all (only flag if dangerous tools present)
        has_sandbox = bool(sandbox_keys & (set(agent.keys()) | set(config.keys())))
        tools = self._get_tools_list(config)
        has_dangerous = any(tool.get("name", "").lower() in self.DANGEROUS_TOOLS for tool in tools)

        if not has_sandbox and has_dangerous:
            return [
                Finding(
                    title="No sandbox configuration with dangerous tools",
                    severity=Severity.HIGH,
                    description="Agent has dangerous tools configured but no sandbox or "
                    "isolation mechanism is set up.",
                    location=str(file_path),
                    remediation="Add sandbox: true to agent config or deploy in a container.",
                    references=[
                        "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
                    ],
                )
            ]

        return []

    def _check_credential_exposure(self, config: dict, file_path: Path) -> list[Finding]:
        """Check for credentials directly exposed in agent context."""
        findings: list[Finding] = []

        agent = config.get("agent", {})
        if not isinstance(agent, dict):
            return findings

        # Check for inline secrets in agent context/environment
        context = agent.get("context", agent.get("environment", {}))
        if isinstance(context, dict):
            secret_patterns = [
                r"sk-[a-zA-Z0-9]{20,}",  # OpenAI-style keys
                r"sk-ant-[a-zA-Z0-9\-]{20,}",  # Anthropic keys
                r"AKIA[0-9A-Z]{16}",  # AWS access keys
                r"gh[pousr]_[A-Za-z0-9_]{20,}",  # GitHub tokens
                r"xox[bprs]-[0-9]+-",  # Slack tokens
            ]

            for key, value in context.items():
                if not isinstance(value, str):
                    continue
                for pattern in secret_patterns:
                    if re.search(pattern, value):
                        findings.append(
                            Finding(
                                title=f"Credential exposed in agent context: {key}",
                                severity=Severity.HIGH,
                                description="API key or token is directly embedded in the agent "
                                "context. A compromised agent could exfiltrate these credentials.",
                                location=str(file_path),
                                remediation="Use environment variables or a secrets manager "
                                "instead of embedding credentials in agent context. "
                                "Reference credentials via env: or secret_ref: directives.",
                                references=[
                                    "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
                                ],
                            )
                        )
                        break

        return findings
