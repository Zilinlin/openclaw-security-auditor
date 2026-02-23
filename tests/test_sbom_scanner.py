"""Tests for the SBOM supply chain scanner.

Tests use temporary directories with YAML/JSON config files to verify
detection of supply chain risks in AI agent dependencies.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from auditor.scanners.base import Severity
from auditor.scanners.sbom_scanner import SBOMScanner


class TestSBOMScanner(unittest.TestCase):
    """Tests for SBOMScanner."""

    def setUp(self):
        self.scanner = SBOMScanner()

    def test_scanner_metadata(self):
        """Test scanner name and description."""
        self.assertEqual(self.scanner.name, "sbom")
        self.assertIn("supply chain", self.scanner.description.lower())

    # =========================================================================
    # MCP Server checks
    # =========================================================================

    def test_detect_unpinned_mcp_version(self):
        """Detect MCP server without version pin."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "mcp_servers:\n"
                    "  - name: filesystem\n"
                    "    command: npx\n"
                    "    args:\n"
                    "      - '@modelcontextprotocol/server-filesystem'\n"
                )
            result = self.scanner.scan(tmpdir)

        version_findings = [f for f in result.findings if "version not pinned" in f.title.lower()]
        self.assertTrue(len(version_findings) > 0)
        self.assertEqual(version_findings[0].severity, Severity.HIGH)

    def test_pinned_mcp_version_no_finding(self):
        """Pinned MCP server version should not be flagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "mcp_servers:\n"
                    "  - name: filesystem\n"
                    "    command: npx\n"
                    "    args:\n"
                    "      - '@modelcontextprotocol/server-filesystem@1.2.3'\n"
                )
            result = self.scanner.scan(tmpdir)

        version_findings = [
            f
            for f in result.findings
            if "version not pinned" in f.title.lower() and "filesystem" in f.title
        ]
        self.assertEqual(len(version_findings), 0)

    def test_detect_unverified_mcp_source(self):
        """Detect MCP server from untrusted source."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "mcp_servers:\n"
                    "  - name: custom-tool\n"
                    "    command: npx\n"
                    "    args:\n"
                    "      - '@evil-scope/malicious-server@1.0.0'\n"
                )
            result = self.scanner.scan(tmpdir)

        source_findings = [f for f in result.findings if "unverified source" in f.title.lower()]
        self.assertTrue(len(source_findings) > 0)

    def test_trusted_npm_scope_no_source_finding(self):
        """Trusted npm scope should not trigger source finding."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "mcp_servers:\n"
                    "  - name: filesystem\n"
                    "    command: npx\n"
                    "    args:\n"
                    "      - '@modelcontextprotocol/server-filesystem@1.0.0'\n"
                )
            result = self.scanner.scan(tmpdir)

        source_findings = [f for f in result.findings if "unverified source" in f.title.lower()]
        self.assertEqual(len(source_findings), 0)

    def test_detect_mcp_no_integrity(self):
        """Detect MCP server without integrity check."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "mcp_servers:\n"
                    "  - name: filesystem\n"
                    "    command: npx\n"
                    "    args: ['@modelcontextprotocol/server-filesystem@1.0.0']\n"
                )
            result = self.scanner.scan(tmpdir)

        integrity_findings = [f for f in result.findings if "integrity" in f.title.lower()]
        self.assertTrue(len(integrity_findings) > 0)
        self.assertEqual(integrity_findings[0].severity, Severity.MEDIUM)

    def test_mcp_with_integrity_no_finding(self):
        """MCP server with integrity hash should not trigger integrity finding."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "mcp_servers:\n"
                    "  - name: filesystem\n"
                    "    command: npx\n"
                    "    args: ['@modelcontextprotocol/server-filesystem@1.0.0']\n"
                    "    sha256: abc123def456\n"
                )
            result = self.scanner.scan(tmpdir)

        integrity_findings = [
            f for f in result.findings if "integrity" in f.title.lower() and "filesystem" in f.title
        ]
        self.assertEqual(len(integrity_findings), 0)

    # =========================================================================
    # MCP JSON config
    # =========================================================================

    def test_scan_mcp_json(self):
        """Test scanning .mcp.json format files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/.mcp.json"
            with open(config, "w") as f:
                json.dump(
                    {
                        "mcpServers": {
                            "filesystem": {
                                "command": "npx",
                                "args": ["@modelcontextprotocol/server-filesystem"],
                            }
                        }
                    },
                    f,
                )
            result = self.scanner.scan(tmpdir)

        self.assertTrue(result.scanned_items > 0)
        version_findings = [f for f in result.findings if "version not pinned" in f.title.lower()]
        self.assertTrue(len(version_findings) > 0)

    def test_scan_mcp_json_dict_format(self):
        """Test scanning MCP JSON with dict-style server config."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/.mcp.json"
            with open(config, "w") as f:
                json.dump(
                    {
                        "mcpServers": {
                            "custom": {
                                "command": "https://evil.com/server",
                                "args": [],
                            }
                        }
                    },
                    f,
                )
            result = self.scanner.scan(tmpdir)

        source_findings = [f for f in result.findings if "unverified source" in f.title.lower()]
        self.assertTrue(len(source_findings) > 0)

    # =========================================================================
    # Skill/plugin checks
    # =========================================================================

    def test_detect_unpinned_skill(self):
        """Detect skill with unpinned version."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "skills:\n"
                    "  - name: web-search\n"
                    "    version: '*'\n"
                )
            result = self.scanner.scan(tmpdir)

        skill_findings = [
            f
            for f in result.findings
            if "skill" in f.title.lower() and "version" in f.title.lower()
        ]
        self.assertTrue(len(skill_findings) > 0)

    def test_detect_skill_latest_version(self):
        """Detect skill with version 'latest'."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "skills:\n"
                    "  - name: data-analysis\n"
                    "    version: latest\n"
                )
            result = self.scanner.scan(tmpdir)

        skill_findings = [
            f
            for f in result.findings
            if "skill" in f.title.lower() and "version" in f.title.lower()
        ]
        self.assertTrue(len(skill_findings) > 0)

    def test_detect_skill_unverified_source(self):
        """Detect skill from unverified URL source."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "skills:\n"
                    "  - name: malicious-skill\n"
                    "    version: '1.0.0'\n"
                    "    source: https://random-domain.com/skill.tar.gz\n"
                )
            result = self.scanner.scan(tmpdir)

        source_findings = [f for f in result.findings if "unverified source" in f.title.lower()]
        self.assertTrue(len(source_findings) > 0)

    def test_detect_skill_no_signature(self):
        """Detect skill without signature."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "skills:\n"
                    "  - name: web-search\n"
                    "    version: '1.0.0'\n"
                )
            result = self.scanner.scan(tmpdir)

        sig_findings = [f for f in result.findings if "signature" in f.title.lower()]
        self.assertTrue(len(sig_findings) > 0)

    def test_skill_with_signature_no_finding(self):
        """Skill with signature should not trigger signature finding."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "skills:\n"
                    "  - name: web-search\n"
                    "    version: '1.0.0'\n"
                    "    verified: true\n"
                )
            result = self.scanner.scan(tmpdir)

        sig_findings = [
            f for f in result.findings if "signature" in f.title.lower() and "web-search" in f.title
        ]
        self.assertEqual(len(sig_findings), 0)

    # =========================================================================
    # Model config checks
    # =========================================================================

    def test_detect_unpinned_model(self):
        """Detect unpinned model version."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "models:\n"
                    "  model: gpt-4\n"
                    "  provider: openai\n"
                )
            result = self.scanner.scan(tmpdir)

        model_findings = [
            f
            for f in result.findings
            if "model" in f.title.lower() and "version" in f.title.lower()
        ]
        self.assertTrue(len(model_findings) > 0)
        self.assertEqual(model_findings[0].severity, Severity.LOW)

    def test_pinned_model_no_finding(self):
        """Pinned model version should not be flagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "models:\n"
                    "  model: gpt-4-0613\n"
                    "  provider: openai\n"
                )
            result = self.scanner.scan(tmpdir)

        model_findings = [
            f
            for f in result.findings
            if "model" in f.title.lower() and "version" in f.title.lower()
        ]
        self.assertEqual(len(model_findings), 0)

    def test_pinned_claude_model_no_finding(self):
        """Claude model with date should not be flagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "models:\n"
                    "  model: claude-sonnet-4-5-20250929\n"
                )
            result = self.scanner.scan(tmpdir)

        model_findings = [
            f
            for f in result.findings
            if "model" in f.title.lower() and "version" in f.title.lower()
        ]
        self.assertEqual(len(model_findings), 0)

    # =========================================================================
    # Edge cases
    # =========================================================================

    def test_nonexistent_path(self):
        """Nonexistent path should return error."""
        result = self.scanner.scan("/nonexistent/path/12345")
        self.assertTrue(len(result.errors) > 0)

    def test_empty_directory(self):
        """Empty directory should return no findings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.scanner.scan(tmpdir)
        self.assertEqual(len(result.findings), 0)
        self.assertEqual(result.scanned_items, 0)

    def test_mcp_servers_as_dict_in_yaml(self):
        """MCP servers as dict format in YAML should work."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = tmpdir + "/config.yaml"
            with open(config, "w") as f:
                f.write(
                    "agent:\n"
                    "  name: TestAgent\n"
                    "mcpServers:\n"
                    "  filesystem:\n"
                    "    command: npx\n"
                    "    args: ['@modelcontextprotocol/server-filesystem']\n"
                )
            result = self.scanner.scan(tmpdir)

        version_findings = [f for f in result.findings if "version not pinned" in f.title.lower()]
        self.assertTrue(len(version_findings) > 0)

    def test_version_pin_patterns(self):
        """Test various version pin detection patterns."""
        scanner = SBOMScanner()
        self.assertTrue(scanner._has_version_pin("npx @scope/pkg@1.2.3"))
        self.assertTrue(scanner._has_version_pin("package==1.0.0"))
        self.assertTrue(scanner._has_version_pin("https://github.com/org/repo/releases/tag/v1.0.0"))
        self.assertFalse(scanner._has_version_pin("npx @scope/pkg"))
        self.assertFalse(scanner._has_version_pin("some-command"))

    def test_source_trust_patterns(self):
        """Test source trust detection."""
        scanner = SBOMScanner()
        self.assertTrue(scanner._check_source_trust("npx @modelcontextprotocol/server@1.0")[0])
        self.assertTrue(scanner._check_source_trust("python script.py")[0])
        self.assertFalse(scanner._check_source_trust("https://evil.com/server")[0])
        self.assertFalse(scanner._check_source_trust("npx @evil-scope/pkg@1.0")[0])

    def test_model_version_pinned(self):
        """Test model version pin detection."""
        scanner = SBOMScanner()
        self.assertTrue(scanner._is_model_version_pinned("gpt-4-0613"))
        self.assertTrue(scanner._is_model_version_pinned("claude-sonnet-4-5-20250929"))
        self.assertTrue(scanner._is_model_version_pinned("llama-3.1-70b"))
        self.assertFalse(scanner._is_model_version_pinned("gpt-4"))
        self.assertFalse(scanner._is_model_version_pinned("claude-opus"))


if __name__ == "__main__":
    unittest.main()
