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

    # =========================================================================
    # Sensitive path detection (built-in)
    # =========================================================================

    def test_detect_ssh_path(self):
        """Detect tool with access to ~/.ssh."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "  approval_required: true\n"
                    "tools:\n"
                    "  - name: file_read\n"
                    "    allowed_paths:\n"
                    "      - ~/.ssh\n"
                )
            result = self.scanner.scan(tmpdir)

        sensitive_findings = [f for f in result.findings if "sensitive path" in f.title.lower()]
        self.assertTrue(len(sensitive_findings) > 0)
        self.assertEqual(sensitive_findings[0].severity, Severity.CRITICAL)
        self.assertIn(".ssh", sensitive_findings[0].description)

    def test_detect_aws_credentials_path(self):
        """Detect tool with access to ~/.aws."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "  approval_required: true\n"
                    "tools:\n"
                    "  - name: file_read\n"
                    "    allowed_paths:\n"
                    "      - ~/.aws\n"
                )
            result = self.scanner.scan(tmpdir)

        sensitive_findings = [f for f in result.findings if "sensitive path" in f.title.lower()]
        self.assertTrue(len(sensitive_findings) > 0)
        self.assertIn("cloud", sensitive_findings[0].description.lower())

    def test_detect_etc_path(self):
        """Detect tool with access to /etc."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "  approval_required: true\n"
                    "tools:\n"
                    "  - name: file_read\n"
                    "    allowed_paths:\n"
                    "      - /etc\n"
                )
            result = self.scanner.scan(tmpdir)

        sensitive_findings = [f for f in result.findings if "sensitive path" in f.title.lower()]
        self.assertTrue(len(sensitive_findings) > 0)

    def test_detect_home_covers_ssh(self):
        """Home directory access should flag because it covers ~/.ssh etc."""
        import os

        home = os.path.expanduser("~")
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "  approval_required: true\n"
                    "tools:\n"
                    "  - name: file_read\n"
                    f"    allowed_paths:\n"
                    f"      - {home}\n"
                )
            result = self.scanner.scan(tmpdir)

        sensitive_findings = [f for f in result.findings if "sensitive path" in f.title.lower()]
        self.assertTrue(len(sensitive_findings) > 0)

    def test_safe_path_no_sensitive_finding(self):
        """Non-sensitive path should not trigger sensitive path finding."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "  approval_required: true\n"
                    "tools:\n"
                    "  - name: file_read\n"
                    "    allowed_paths:\n"
                    "      - /data/docs\n"
                    "      - /tmp/workspace\n"
                )
            result = self.scanner.scan(tmpdir)

        sensitive_findings = [f for f in result.findings if "sensitive path" in f.title.lower()]
        self.assertEqual(len(sensitive_findings), 0)

    def test_user_extra_sensitive_path(self):
        """User-specified sensitive path should be flagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "  approval_required: true\n"
                    "tools:\n"
                    "  - name: file_read\n"
                    "    allowed_paths:\n"
                    "      - /data/secret-reports\n"
                )
            result = self.scanner.scan(tmpdir, sensitive_paths=["/data/secret-reports"])

        sensitive_findings = [f for f in result.findings if "sensitive path" in f.title.lower()]
        self.assertTrue(len(sensitive_findings) > 0)

    def test_root_path_sensitive(self):
        """Root path / should be flagged as sensitive."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "  approval_required: true\n"
                    "tools:\n"
                    "  - name: file_read\n"
                    "    allowed_paths:\n"
                    "      - /\n"
                )
            result = self.scanner.scan(tmpdir)

        sensitive_findings = [f for f in result.findings if "sensitive path" in f.title.lower()]
        self.assertTrue(len(sensitive_findings) > 0)

    # =========================================================================
    # Allowed path whitelist (policy enforcement)
    # =========================================================================

    def test_path_within_policy_no_finding(self):
        """Path within allowed policy should not be flagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "  approval_required: true\n"
                    "tools:\n"
                    "  - name: file_read\n"
                    "    allowed_paths:\n"
                    "      - /data/docs\n"
                    "      - /data/docs/reports\n"
                )
            result = self.scanner.scan(tmpdir, allowed_paths=["/data/docs", "/tmp"])

        policy_findings = [
            f for f in result.findings if "outside allowed policy" in f.title.lower()
        ]
        self.assertEqual(len(policy_findings), 0)

    def test_path_outside_policy_flagged(self):
        """Path outside allowed policy should be flagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "  approval_required: true\n"
                    "tools:\n"
                    "  - name: file_read\n"
                    "    allowed_paths:\n"
                    "      - /data/docs\n"
                    "      - /var/log\n"
                )
            result = self.scanner.scan(tmpdir, allowed_paths=["/data/docs"])

        policy_findings = [
            f for f in result.findings if "outside allowed policy" in f.title.lower()
        ]
        self.assertTrue(len(policy_findings) > 0)
        self.assertIn("/var/log", policy_findings[0].title)

    def test_multiple_paths_mixed_policy(self):
        """Mix of compliant and non-compliant paths."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "  approval_required: true\n"
                    "tools:\n"
                    "  - name: file_read\n"
                    "    allowed_paths:\n"
                    "      - /data/docs\n"
                    "      - /home/user/secrets\n"
                    "      - /tmp/workspace/output\n"
                )
            result = self.scanner.scan(tmpdir, allowed_paths=["/data/docs", "/tmp/workspace"])

        policy_findings = [
            f for f in result.findings if "outside allowed policy" in f.title.lower()
        ]
        # Only /home/user/secrets should be flagged
        self.assertEqual(len(policy_findings), 1)
        self.assertIn("/home/user/secrets", policy_findings[0].title)

    def test_no_allowed_paths_no_policy_findings(self):
        """Without --allowed-paths, no policy findings should appear."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "  approval_required: true\n"
                    "tools:\n"
                    "  - name: file_read\n"
                    "    allowed_paths:\n"
                    "      - /anywhere/at/all\n"
                )
            result = self.scanner.scan(tmpdir)

        policy_findings = [
            f for f in result.findings if "outside allowed policy" in f.title.lower()
        ]
        self.assertEqual(len(policy_findings), 0)

    def test_subdirectory_within_policy(self):
        """Subdirectory of an allowed path should pass policy check."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "  approval_required: true\n"
                    "tools:\n"
                    "  - name: file_read\n"
                    "    allowed_paths:\n"
                    "      - /data/docs/reports/2026\n"
                )
            result = self.scanner.scan(tmpdir, allowed_paths=["/data/docs"])

        policy_findings = [
            f for f in result.findings if "outside allowed policy" in f.title.lower()
        ]
        self.assertEqual(len(policy_findings), 0)

    # =========================================================================
    # Combined: sensitive + policy
    # =========================================================================

    def test_sensitive_and_policy_both_fire(self):
        """Both sensitive path and policy violation can fire together."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "  approval_required: true\n"
                    "tools:\n"
                    "  - name: file_read\n"
                    "    allowed_paths:\n"
                    "      - ~/.ssh\n"
                )
            result = self.scanner.scan(tmpdir, allowed_paths=["/data/docs"])

        sensitive_findings = [f for f in result.findings if "sensitive path" in f.title.lower()]
        policy_findings = [
            f for f in result.findings if "outside allowed policy" in f.title.lower()
        ]
        self.assertTrue(len(sensitive_findings) > 0)
        self.assertTrue(len(policy_findings) > 0)


if __name__ == "__main__":
    unittest.main()
