"""Tests for the privilege boundary scanner.

Tests use temporary directories with YAML config files to verify
detection of excessive permissions and missing access controls.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from auditor.scanners.base import Severity
from auditor.scanners.privilege_scanner import PrivilegeScanner


class TestPrivilegeScanner(unittest.TestCase):
    """Tests for PrivilegeScanner."""

    def setUp(self):
        self.scanner = PrivilegeScanner()

    def test_scanner_metadata(self):
        """Test scanner name and description."""
        self.assertEqual(self.scanner.name, "privilege")
        self.assertIn("privilege", self.scanner.description.lower())

    # =========================================================================
    # Dangerous tools without restrictions
    # =========================================================================

    def test_detect_unrestricted_shell_exec(self):
        """Detect shell_exec tool without restrictions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "tools:\n"
                    "  - name: shell_exec\n"
                    "    enabled: true\n"
                )
            result = self.scanner.scan(tmpdir)

        self.assertTrue(len(result.findings) > 0)
        tool_findings = [f for f in result.findings if "shell_exec" in f.title]
        self.assertTrue(len(tool_findings) > 0)
        self.assertEqual(tool_findings[0].severity, Severity.CRITICAL)

    def test_detect_unrestricted_code_exec(self):
        """Detect code_exec tool without restrictions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/agent.yaml"
            with open(config, "w") as f:
                f.write("agent:\n" "  name: TestAgent\n" "tools:\n" "  - name: code_exec\n")
            result = self.scanner.scan(tmpdir)

        tool_findings = [f for f in result.findings if "code_exec" in f.title]
        self.assertTrue(len(tool_findings) > 0)
        self.assertEqual(tool_findings[0].severity, Severity.CRITICAL)

    def test_detect_unrestricted_file_write(self):
        """Detect file_write tool without restrictions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write("agent:\n" "  name: TestAgent\n" "tools:\n" "  - name: file_write\n")
            result = self.scanner.scan(tmpdir)

        tool_findings = [f for f in result.findings if "file_write" in f.title]
        self.assertTrue(len(tool_findings) > 0)
        self.assertEqual(tool_findings[0].severity, Severity.HIGH)

    def test_restricted_tool_no_finding(self):
        """Tool with restrictions should not be flagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "tools:\n"
                    "  - name: shell_exec\n"
                    "    allowed_commands:\n"
                    "      - ls\n"
                    "      - cat\n"
                )
            result = self.scanner.scan(tmpdir)

        tool_findings = [f for f in result.findings if "shell_exec" in f.title]
        self.assertEqual(len(tool_findings), 0)

    def test_safe_tool_no_finding(self):
        """Non-dangerous tool should not be flagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write("agent:\n" "  name: TestAgent\n" "tools:\n" "  - name: calculator\n")
            result = self.scanner.scan(tmpdir)

        tool_findings = [f for f in result.findings if "calculator" in f.title]
        self.assertEqual(len(tool_findings), 0)

    # =========================================================================
    # Missing approval gates
    # =========================================================================

    def test_detect_missing_approval_with_dangerous_tools(self):
        """Detect missing approval gates when dangerous tools present."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "tools:\n"
                    "  - name: shell_exec\n"
                    "    allowed_commands: [ls]\n"
                )
            result = self.scanner.scan(tmpdir)

        approval_findings = [f for f in result.findings if "approval" in f.title.lower()]
        self.assertTrue(len(approval_findings) > 0)

    def test_detect_approval_disabled(self):
        """Detect explicitly disabled approval."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "  approval_required: false\n"
                    "tools:\n"
                    "  - name: calculator\n"
                )
            result = self.scanner.scan(tmpdir)

        approval_findings = [f for f in result.findings if "approval" in f.title.lower()]
        self.assertTrue(len(approval_findings) > 0)
        self.assertEqual(approval_findings[0].severity, Severity.HIGH)

    def test_approval_enabled_no_finding(self):
        """Enabled approval should not be flagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "  approval_required: true\n"
                    "tools:\n"
                    "  - name: shell_exec\n"
                    "    allowed_commands: [ls]\n"
                )
            result = self.scanner.scan(tmpdir)

        approval_findings = [f for f in result.findings if "approval" in f.title.lower()]
        self.assertEqual(len(approval_findings), 0)

    # =========================================================================
    # Unrestricted filesystem
    # =========================================================================

    def test_detect_wildcard_path(self):
        """Detect wildcard allowed_paths on tools."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "  approval_required: true\n"
                    "tools:\n"
                    "  - name: file_write\n"
                    "    allowed_paths: '*'\n"
                )
            result = self.scanner.scan(tmpdir)

        fs_findings = [f for f in result.findings if "wildcard" in f.title.lower()]
        self.assertTrue(len(fs_findings) > 0)

    def test_detect_full_filesystem_permission(self):
        """Detect full filesystem permission in permissions section."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write("agent:\n" "  name: TestAgent\n" "permissions:\n" "  filesystem: full\n")
            result = self.scanner.scan(tmpdir)

        fs_findings = [f for f in result.findings if "filesystem" in f.title.lower()]
        self.assertTrue(len(fs_findings) > 0)

    # =========================================================================
    # Unrestricted network
    # =========================================================================

    def test_detect_unrestricted_network(self):
        """Detect unrestricted network permission."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n" "  name: TestAgent\n" "permissions:\n" "  network: unrestricted\n"
                )
            result = self.scanner.scan(tmpdir)

        net_findings = [f for f in result.findings if "network" in f.title.lower()]
        self.assertTrue(len(net_findings) > 0)

    def test_detect_network_tool_without_domain_restriction(self):
        """Detect http_request tool without domain allowlist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "  approval_required: true\n"
                    "tools:\n"
                    "  - name: http_request\n"
                )
            result = self.scanner.scan(tmpdir)

        net_findings = [
            f
            for f in result.findings
            if "network" in f.title.lower() or "domain" in f.title.lower()
        ]
        self.assertTrue(len(net_findings) > 0)

    # =========================================================================
    # Missing rate limits
    # =========================================================================

    def test_detect_missing_rate_limits(self):
        """Detect missing rate limit configuration."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "  approval_required: true\n"
                    "tools:\n"
                    "  - name: calculator\n"
                )
            result = self.scanner.scan(tmpdir)

        rate_findings = [f for f in result.findings if "rate" in f.title.lower()]
        self.assertTrue(len(rate_findings) > 0)
        self.assertEqual(rate_findings[0].severity, Severity.MEDIUM)

    def test_rate_limits_present_no_finding(self):
        """Rate limits configured should not be flagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "  approval_required: true\n"
                    "rate_limits:\n"
                    "  max_actions_per_minute: 10\n"
                    "tools:\n"
                    "  - name: calculator\n"
                )
            result = self.scanner.scan(tmpdir)

        rate_findings = [f for f in result.findings if "rate" in f.title.lower()]
        self.assertEqual(len(rate_findings), 0)

    # =========================================================================
    # Overly broad API scopes
    # =========================================================================

    def test_detect_admin_scope(self):
        """Detect admin scope in auth config."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "auth:\n"
                    "  scopes:\n"
                    "    - admin\n"
                    "    - read:agents\n"
                )
            result = self.scanner.scan(tmpdir)

        scope_findings = [f for f in result.findings if "scope" in f.title.lower()]
        self.assertTrue(len(scope_findings) > 0)

    # =========================================================================
    # No sandbox
    # =========================================================================

    def test_detect_sandbox_disabled(self):
        """Detect explicitly disabled sandbox."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "  sandbox: false\n"
                    "tools:\n"
                    "  - name: calculator\n"
                )
            result = self.scanner.scan(tmpdir)

        sandbox_findings = [f for f in result.findings if "sandbox" in f.title.lower()]
        self.assertTrue(len(sandbox_findings) > 0)
        self.assertEqual(sandbox_findings[0].severity, Severity.HIGH)

    def test_detect_no_sandbox_with_dangerous_tools(self):
        """Detect missing sandbox when dangerous tools present."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "  approval_required: true\n"
                    "tools:\n"
                    "  - name: shell_exec\n"
                    "    allowed_commands: [ls]\n"
                )
            result = self.scanner.scan(tmpdir)

        sandbox_findings = [f for f in result.findings if "sandbox" in f.title.lower()]
        self.assertTrue(len(sandbox_findings) > 0)

    # =========================================================================
    # Credential exposure
    # =========================================================================

    def test_detect_credential_in_context(self):
        """Detect API key directly in agent context."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "  context:\n"
                    "    OPENAI_KEY: sk-proj1234567890abcdef1234567890abcdef1234567890abcdef12\n"
                )
            result = self.scanner.scan(tmpdir)

        cred_findings = [f for f in result.findings if "credential" in f.title.lower()]
        self.assertTrue(len(cred_findings) > 0)

    # =========================================================================
    # Secure config (negative test)
    # =========================================================================

    def test_secure_config_minimal_findings(self):
        """Secure config should have minimal findings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: SecureAgent\n"
                    "  approval_required: true\n"
                    "  sandbox: true\n"
                    "tools:\n"
                    "  - name: file_read\n"
                    "    allowed_paths:\n"
                    "      - /data/docs\n"
                    "rate_limits:\n"
                    "  max_actions_per_minute: 10\n"
                    "permissions:\n"
                    "  filesystem: read_only\n"
                    "  network: restricted\n"
                )
            result = self.scanner.scan(tmpdir)

        # Should have no critical or high findings
        critical_high = [
            f for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        self.assertEqual(len(critical_high), 0)

    # =========================================================================
    # Edge cases
    # =========================================================================

    def test_nonexistent_path(self):
        """Nonexistent path should return error."""
        result = self.scanner.scan("/nonexistent/path/12345")
        self.assertTrue(len(result.errors) > 0)
        self.assertEqual(len(result.findings), 0)

    def test_non_agent_yaml_skipped(self):
        """Non-agent YAML should not produce privilege findings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write("database:\n" "  host: localhost\n" "  port: 5432\n")
            result = self.scanner.scan(tmpdir)

        self.assertEqual(len(result.findings), 0)

    def test_tools_as_dict_format(self):
        """Tools specified as dict should be handled."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "tools:\n"
                    "  shell_exec:\n"
                    "    enabled: true\n"
                )
            result = self.scanner.scan(tmpdir)

        tool_findings = [f for f in result.findings if "shell_exec" in f.title]
        self.assertTrue(len(tool_findings) > 0)

    def test_tools_as_string_list(self):
        """Tools specified as string list should be handled."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "tools:\n"
                    "  - shell_exec\n"
                    "  - calculator\n"
                )
            result = self.scanner.scan(tmpdir)

        tool_findings = [f for f in result.findings if "shell_exec" in f.title]
        self.assertTrue(len(tool_findings) > 0)

    def test_scanned_items_count(self):
        """Scanned items should reflect number of config files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            for name in ["config.yaml", "agent.yaml"]:
                with open(tmpdir + "/" + name, "w") as f:
                    f.write("agent:\n  name: Test\n")
            result = self.scanner.scan(tmpdir)

        self.assertEqual(result.scanned_items, 2)


if __name__ == "__main__":
    unittest.main()
