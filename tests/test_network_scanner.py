"""Tests for the network exposure scanner.

Tests use mocked socket operations to avoid requiring actual network connections.
"""

import os
import socket
import ssl
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from auditor.scanners.base import Severity
from auditor.scanners.network_scanner import NetworkScanner


class TestNetworkScanner(unittest.TestCase):
    """Tests for NetworkScanner."""

    def setUp(self):
        self.scanner = NetworkScanner()

    def test_scanner_metadata(self):
        """Test scanner name and description."""
        self.assertEqual(self.scanner.name, "network")
        self.assertEqual(self.scanner.DEFAULT_PORT, 18789)

    # =========================================================================
    # _is_openclaw
    # =========================================================================

    def test_is_openclaw_none_banner(self):
        """None banner should default to True (assume OpenClaw on matching port)."""
        self.assertTrue(self.scanner._is_openclaw(None))

    def test_is_openclaw_empty_banner(self):
        """Empty banner should return True (same as None — assume OpenClaw)."""
        self.assertTrue(self.scanner._is_openclaw(""))

    def test_is_openclaw_matching_banner(self):
        """Banner containing openclaw indicators should return True."""
        self.assertTrue(self.scanner._is_openclaw("HTTP/1.1 200 OK\r\nServer: OpenClaw/2026.2.12"))
        self.assertTrue(self.scanner._is_openclaw("X-OpenClaw-Version: 1.0"))
        self.assertTrue(self.scanner._is_openclaw("powered by moltbot"))
        self.assertTrue(self.scanner._is_openclaw("clawdbot agent v1"))

    def test_is_openclaw_non_matching_banner(self):
        """Banner without openclaw indicators should return False."""
        self.assertFalse(self.scanner._is_openclaw("HTTP/1.1 200 OK\r\nServer: nginx"))
        self.assertFalse(self.scanner._is_openclaw("Apache/2.4"))

    def test_is_openclaw_case_insensitive(self):
        """Banner matching should be case-insensitive."""
        self.assertTrue(self.scanner._is_openclaw("OPENCLAW"))
        self.assertTrue(self.scanner._is_openclaw("MoltBot"))

    # =========================================================================
    # _is_public_ip
    # =========================================================================

    def test_is_public_ip_localhost(self):
        """localhost should not be public."""
        with patch("socket.gethostbyname", return_value="127.0.0.1"):
            self.assertFalse(self.scanner._is_public_ip("localhost"))

    def test_is_public_ip_private_10(self):
        """10.x.x.x should not be public."""
        with patch("socket.gethostbyname", return_value="10.0.0.1"):
            self.assertFalse(self.scanner._is_public_ip("internal.local"))

    def test_is_public_ip_private_192(self):
        """192.168.x.x should not be public."""
        with patch("socket.gethostbyname", return_value="192.168.1.100"):
            self.assertFalse(self.scanner._is_public_ip("router.local"))

    def test_is_public_ip_private_172(self):
        """172.16-31.x.x should not be public."""
        with patch("socket.gethostbyname", return_value="172.16.0.1"):
            self.assertFalse(self.scanner._is_public_ip("k8s-node"))
        with patch("socket.gethostbyname", return_value="172.31.255.255"):
            self.assertFalse(self.scanner._is_public_ip("k8s-node"))

    def test_is_public_ip_link_local(self):
        """169.254.x.x should not be public."""
        with patch("socket.gethostbyname", return_value="169.254.1.1"):
            self.assertFalse(self.scanner._is_public_ip("link-local"))

    def test_is_public_ip_true(self):
        """Public IPs should be detected."""
        with patch("socket.gethostbyname", return_value="8.8.8.8"):
            self.assertTrue(self.scanner._is_public_ip("dns.google"))
        with patch("socket.gethostbyname", return_value="203.0.113.1"):
            self.assertTrue(self.scanner._is_public_ip("example.com"))

    def test_is_public_ip_dns_failure(self):
        """DNS resolution failure should return False."""
        with patch("socket.gethostbyname", side_effect=socket.gaierror("DNS failed")):
            self.assertFalse(self.scanner._is_public_ip("nonexistent.invalid"))

    # =========================================================================
    # _check_port
    # =========================================================================

    def test_check_port_open(self):
        """Open port should return True with banner."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\nServer: OpenClaw"

        with patch("socket.socket", return_value=mock_sock):
            is_open, banner = self.scanner._check_port("localhost", 18789)

        self.assertTrue(is_open)
        self.assertIn("OpenClaw", banner)
        mock_sock.settimeout.assert_called_with(self.scanner.TIMEOUT)

    def test_check_port_open_no_banner(self):
        """Open port with recv exception should return True with None banner."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock.recv.side_effect = socket.timeout("recv timeout")

        with patch("socket.socket", return_value=mock_sock):
            is_open, banner = self.scanner._check_port("localhost", 18789)

        self.assertTrue(is_open)
        self.assertIsNone(banner)

    def test_check_port_closed(self):
        """Closed port should return False."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 111  # Connection refused

        with patch("socket.socket", return_value=mock_sock):
            is_open, banner = self.scanner._check_port("localhost", 18789)

        self.assertFalse(is_open)
        self.assertIsNone(banner)

    def test_check_port_dns_error(self):
        """DNS resolution failure should return False."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = socket.gaierror("Name not resolved")

        with patch("socket.socket", return_value=mock_sock):
            is_open, banner = self.scanner._check_port("bad-host.invalid", 18789)

        self.assertFalse(is_open)
        self.assertIsNone(banner)

    def test_check_port_generic_error(self):
        """Generic socket error should return False."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = OSError("Network unreachable")

        with patch("socket.socket", return_value=mock_sock):
            is_open, banner = self.scanner._check_port("localhost", 18789)

        self.assertFalse(is_open)
        self.assertIsNone(banner)

    # =========================================================================
    # _check_ssl
    # =========================================================================

    def test_check_ssl_enabled(self):
        """SSL-enabled host should produce INFO finding."""
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = {"subject": "test"}
        mock_ssock.__enter__ = MagicMock(return_value=mock_ssock)
        mock_ssock.__exit__ = MagicMock(return_value=False)

        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssock

        with (
            patch("ssl.create_default_context", return_value=mock_ctx),
            patch("socket.create_connection", return_value=mock_sock),
        ):
            findings = self.scanner._check_ssl("localhost", 18789)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "SSL/TLS enabled")
        self.assertEqual(findings[0].severity, Severity.INFO)

    def test_check_ssl_certificate_error(self):
        """SSL certificate error should produce MEDIUM finding."""
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.side_effect = ssl.SSLError("certificate verify failed")

        with (
            patch("ssl.create_default_context", return_value=mock_ctx),
            patch("socket.create_connection", return_value=mock_sock),
        ):
            findings = self.scanner._check_ssl("localhost", 18789)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "SSL certificate issue")
        self.assertEqual(findings[0].severity, Severity.MEDIUM)

    def test_check_ssl_not_enabled(self):
        """No SSL should produce HIGH finding."""
        with patch(
            "socket.create_connection",
            side_effect=ConnectionRefusedError("Connection refused"),
        ):
            findings = self.scanner._check_ssl("localhost", 18789)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "No SSL/TLS encryption")
        self.assertEqual(findings[0].severity, Severity.HIGH)

    # =========================================================================
    # _check_auth
    # =========================================================================

    def test_check_auth_no_auth_required(self):
        """Unauthenticated API access should produce HIGH finding."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
            b'{"status": "running", "version": "2026.2.12"}'
        )

        with patch("socket.socket", return_value=mock_sock):
            findings = self.scanner._check_auth("localhost", 18789)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "API accessible without authentication")
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_check_auth_401_required(self):
        """401 response should produce INFO finding (auth enforced)."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = (
            b"HTTP/1.1 401 Unauthorized\r\n\r\n" b'{"error": "authentication required"}'
        )

        with patch("socket.socket", return_value=mock_sock):
            findings = self.scanner._check_auth("localhost", 18789)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "Authentication required")
        self.assertEqual(findings[0].severity, Severity.INFO)

    def test_check_auth_403_forbidden(self):
        """403 response should produce INFO finding (auth enforced)."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"HTTP/1.1 403 Forbidden\r\n\r\n"

        with patch("socket.socket", return_value=mock_sock):
            findings = self.scanner._check_auth("localhost", 18789)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "Authentication required")
        self.assertEqual(findings[0].severity, Severity.INFO)

    def test_check_auth_connection_error(self):
        """Connection error during auth check should produce no findings."""
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = ConnectionRefusedError()

        with patch("socket.socket", return_value=mock_sock):
            findings = self.scanner._check_auth("localhost", 18789)

        self.assertEqual(len(findings), 0)

    def test_check_auth_200_without_sensitive_data(self):
        """200 without sensitive keywords should produce no findings."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\n\r\nOK"

        with patch("socket.socket", return_value=mock_sock):
            findings = self.scanner._check_auth("localhost", 18789)

        self.assertEqual(len(findings), 0)

    # =========================================================================
    # scan() - integration
    # =========================================================================

    def test_scan_port_closed(self):
        """Scan with closed port should report not accessible."""
        with patch.object(self.scanner, "_check_port", return_value=(False, None)):
            result = self.scanner.scan("localhost")

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].title, "OpenClaw port not accessible")
        self.assertEqual(result.findings[0].severity, Severity.INFO)

    def test_scan_port_open_not_openclaw(self):
        """Scan with open port but non-OpenClaw banner should report accordingly."""
        with patch.object(
            self.scanner, "_check_port", return_value=(True, "HTTP/1.1 200 OK\r\nServer: nginx")
        ):
            result = self.scanner.scan("localhost")

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].title, "Port open but not OpenClaw")

    def test_scan_openclaw_private_ip(self):
        """Scan with OpenClaw on private IP should not flag public exposure."""
        with (
            patch.object(
                self.scanner,
                "_check_port",
                return_value=(True, "Server: OpenClaw"),
            ),
            patch.object(self.scanner, "_is_public_ip", return_value=False),
            patch.object(self.scanner, "_check_ssl", return_value=[]),
            patch.object(self.scanner, "_check_auth", return_value=[]),
        ):
            result = self.scanner.scan("localhost")

        titles = [f.title for f in result.findings]
        self.assertIn("OpenClaw instance accessible", titles)
        self.assertNotIn("OpenClaw exposed to public internet", titles)

    def test_scan_openclaw_public_ip(self):
        """Scan with OpenClaw on public IP should flag critical exposure."""
        with (
            patch.object(
                self.scanner,
                "_check_port",
                return_value=(True, "Server: OpenClaw"),
            ),
            patch.object(self.scanner, "_is_public_ip", return_value=True),
            patch.object(self.scanner, "_check_ssl", return_value=[]),
            patch.object(self.scanner, "_check_auth", return_value=[]),
        ):
            result = self.scanner.scan("example.com")

        titles = [f.title for f in result.findings]
        self.assertIn("OpenClaw instance accessible", titles)
        self.assertIn("OpenClaw exposed to public internet", titles)

        exposure = [f for f in result.findings if f.title == "OpenClaw exposed to public internet"]
        self.assertEqual(exposure[0].severity, Severity.CRITICAL)

    def test_scan_url_target(self):
        """Scan should parse URLs and extract host/port."""
        with (patch.object(self.scanner, "_check_port", return_value=(False, None)) as mock_check,):
            self.scanner.scan("http://myhost:9999/path")

        mock_check.assert_called_once_with("myhost", 9999)

    def test_scan_host_parameter_overrides_target(self):
        """Explicit host parameter should override target."""
        with (patch.object(self.scanner, "_check_port", return_value=(False, None)) as mock_check,):
            self.scanner.scan("ignored", host="real-host", port=12345)

        mock_check.assert_called_once_with("real-host", 12345)

    def test_scan_scanned_items_count(self):
        """Scan should set scanned_items to 1."""
        with patch.object(self.scanner, "_check_port", return_value=(False, None)):
            result = self.scanner.scan("localhost")

        self.assertEqual(result.scanned_items, 1)


if __name__ == "__main__":
    unittest.main()
