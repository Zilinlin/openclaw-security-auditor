"""Tests for vulnerability detectors.

These tests verify the detector logic without requiring actual network connections.
Mock servers are used to simulate vulnerable and patched OpenClaw instances.
"""

import os
import socket
import sys
import threading
import unittest
from unittest.mock import MagicMock, patch

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from auditor.detectors.api_bypass_detector import APIHookBypassDetector
from auditor.detectors.auth_detector import AuthWeaknessDetector
from auditor.detectors.base import VulnerabilityStatus
from auditor.detectors.prompt_injection_detector import PromptInjectionDetector
from auditor.detectors.websocket_detector import WebSocketOriginDetector


class MockServer:
    """A simple mock server for testing detectors."""

    def __init__(self, port: int):
        self.port = port
        self.server = None
        self.thread = None
        self.running = False
        self.responses = {}

    def set_response(self, pattern: str, response: bytes):
        """Set response for requests matching pattern."""
        self.responses[pattern] = response

    def start(self):
        """Start the mock server."""
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", self.port))
        self.server.listen(5)
        self.server.settimeout(1)
        self.running = True
        self.thread = threading.Thread(target=self._serve)
        self.thread.start()

    def _serve(self):
        """Handle incoming connections."""
        while self.running:
            try:
                client, addr = self.server.accept()
                data = client.recv(4096).decode("utf-8", errors="ignore")

                # Find matching response
                response = b"HTTP/1.1 404 Not Found\r\n\r\n"
                for pattern, resp in self.responses.items():
                    if pattern in data:
                        response = resp
                        break

                client.send(response)
                client.close()
            except socket.timeout:
                continue
            except Exception:
                break

    def stop(self):
        """Stop the mock server."""
        self.running = False
        if self.server:
            self.server.close()
        if self.thread:
            self.thread.join(timeout=2)


class TestWebSocketOriginDetector(unittest.TestCase):
    """Tests for WebSocket Origin Bypass detector."""

    def test_vulnerable_server(self):
        """Test detection of vulnerable server that accepts any origin."""
        MockServer(19001)

        # The detector generates its own random ws_key and computes the accept key.
        # Our mock server needs to return 101 with a valid Sec-WebSocket-Accept header.
        # Since the key is random, we can't pre-compute the accept value.
        # Instead, we patch _test_origin to simulate a vulnerable response.
        detector = WebSocketOriginDetector()

        with patch.object(detector, "_test_origin", return_value=(True, {"status_code": 101})):
            result = detector.detect("127.0.0.1", 19001)

        # Should detect vulnerability - check via findings
        self.assertTrue(result.is_vulnerable)
        self.assertTrue(len(result.findings) > 0)
        self.assertEqual(result.findings[0].status, VulnerabilityStatus.VULNERABLE)
        self.assertEqual(result.findings[0].cve, "CVE-2026-25253")

    def test_patched_server(self):
        """Test that patched server rejects bad origins."""
        detector = WebSocketOriginDetector()

        with patch.object(detector, "_test_origin", return_value=(False, {"status_code": 403})):
            result = detector.detect("127.0.0.1", 19002)

        # Should not detect vulnerability
        self.assertFalse(result.is_vulnerable)
        self.assertTrue(len(result.findings) > 0)
        self.assertEqual(result.findings[0].status, VulnerabilityStatus.NOT_VULNERABLE)

    def test_vulnerable_server_with_mock_socket(self):
        """Test detection with an actual mock TCP server accepting WebSocket upgrades."""
        import base64
        import hashlib

        MockServer(19011)
        GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

        # We need a handler that computes the accept key dynamically.
        # Since MockServer matches by pattern, we'll use a custom server instead.
        class DynamicWSServer:
            def __init__(self, port):
                self.port = port
                self.running = False
                self.server = None
                self.thread = None

            def start(self):
                self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server.bind(("127.0.0.1", self.port))
                self.server.listen(5)
                self.server.settimeout(2)
                self.running = True
                self.thread = threading.Thread(target=self._serve)
                self.thread.start()

            def _serve(self):
                while self.running:
                    try:
                        client, _ = self.server.accept()
                        data = client.recv(4096).decode("utf-8", errors="ignore")
                        # Extract Sec-WebSocket-Key from request
                        key = None
                        for line in data.split("\r\n"):
                            if line.lower().startswith("sec-websocket-key:"):
                                key = line.split(":", 1)[1].strip()
                                break

                        if key:
                            accept = base64.b64encode(
                                hashlib.sha1((key + GUID).encode()).digest()
                            ).decode()
                            response = (
                                f"HTTP/1.1 101 Switching Protocols\r\n"
                                f"Upgrade: websocket\r\n"
                                f"Connection: Upgrade\r\n"
                                f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
                            ).encode()
                        else:
                            response = b"HTTP/1.1 400 Bad Request\r\n\r\n"

                        client.send(response)
                        client.close()
                    except socket.timeout:
                        continue
                    except Exception:
                        break

            def stop(self):
                self.running = False
                if self.server:
                    self.server.close()
                if self.thread:
                    self.thread.join(timeout=2)

        ws_server = DynamicWSServer(19011)
        try:
            ws_server.start()
            detector = WebSocketOriginDetector()
            result = detector.detect("127.0.0.1", 19011)

            self.assertTrue(result.is_vulnerable)
            self.assertEqual(result.findings[0].status, VulnerabilityStatus.VULNERABLE)
            self.assertEqual(result.findings[0].cve, "CVE-2026-25253")
        finally:
            ws_server.stop()


class TestAuthWeaknessDetector(unittest.TestCase):
    """Tests for Authentication Weakness detector."""

    def test_vulnerable_no_auth(self):
        """Test detection of endpoint without authentication."""
        detector = AuthWeaknessDetector()

        # Mock requests to simulate no-auth-required responses
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b'{"status": "running"}'
        mock_response.json.return_value = {"status": "running"}

        with patch("auditor.detectors.auth_detector.requests") as mock_requests:
            mock_requests.get.return_value = mock_response
            mock_requests.post.return_value = mock_response
            mock_requests.exceptions = __import__("requests").exceptions

            result = detector.detect("127.0.0.1", 19003)

        # Should detect vulnerability
        self.assertTrue(result.is_vulnerable)
        vulnerable_findings = [
            f for f in result.findings if f.status == VulnerabilityStatus.VULNERABLE
        ]
        self.assertTrue(len(vulnerable_findings) > 0)

    def test_protected_endpoint(self):
        """Test that protected endpoint is correctly identified."""
        detector = AuthWeaknessDetector()

        # Mock requests to simulate auth-enforced responses
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.content = b'{"error": "authentication required"}'

        with patch("auditor.detectors.auth_detector.requests") as mock_requests:
            mock_requests.get.return_value = mock_response
            mock_requests.post.return_value = mock_response
            mock_requests.exceptions = __import__("requests").exceptions

            result = detector.detect("127.0.0.1", 19004)

        # Should not detect vulnerability (auth enforced)
        self.assertFalse(result.is_vulnerable)


class TestPromptInjectionDetector(unittest.TestCase):
    """Tests for Prompt Injection detector."""

    def test_payload_library_populated(self):
        """Test that the payload library is populated with payloads."""
        detector = PromptInjectionDetector()
        self.assertTrue(len(detector.payloads) > 0)

        # Each payload should have a unique name
        names = [p.name for p in detector.payloads]
        self.assertEqual(len(names), len(set(names)))

    def test_payload_categories(self):
        """Test payload category listing."""
        detector = PromptInjectionDetector()
        categories = detector.get_payload_categories()

        self.assertIn("instruction_override", categories)
        self.assertIn("role_hijacking", categories)
        self.assertIn("jailbreak", categories)

    def test_canary_substitution_in_payloads(self):
        """Test that canary placeholders exist in payloads (directly or encoded)."""
        detector = PromptInjectionDetector()
        for payload in detector.payloads:
            # Some payloads embed {canary} directly, others use it in encoded form
            # (e.g., base64). The key requirement is that _test_payload can substitute
            # the canary and detect it. For direct payloads, verify the placeholder.
            if payload.category != "encoded_injection":
                self.assertIn(
                    "{canary}",
                    payload.payload,
                    f"Payload '{payload.name}' missing {{canary}} placeholder",
                )

    def test_vulnerable_response_detected(self):
        """Test detection when canary is leaked in response."""
        detector = PromptInjectionDetector()

        # Mock the requests.post to return a response containing the canary
        def mock_post(*args, **kwargs):
            # Extract the canary from the request payload
            data = kwargs.get("json", {})
            message = data.get("messages", [{}])[0].get("content", "")
            # Find the CANARY_ token in the message
            import re

            match = re.search(r"CANARY_([a-f0-9]+)", message)
            canary_value = match.group(0) if match else "CANARY_leaked"

            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "choices": [{"message": {"content": f"Sure! {canary_value}"}}]
            }
            return response

        with patch("auditor.detectors.prompt_injection_detector.requests") as mock_requests:
            mock_requests.post.side_effect = mock_post
            mock_requests.exceptions = __import__("requests").exceptions

            result = detector.detect("127.0.0.1", 19005, payloads=["direct_override"])

        # Should detect vulnerability (canary leaked)
        self.assertTrue(result.is_vulnerable)
        self.assertTrue(len(result.findings) > 0)
        self.assertEqual(result.findings[0].status, VulnerabilityStatus.VULNERABLE)

    def test_safe_response_not_flagged(self):
        """Test that a response without canary is not flagged."""
        detector = PromptInjectionDetector()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "I cannot follow those instructions."}}]
        }

        with patch("auditor.detectors.prompt_injection_detector.requests") as mock_requests:
            mock_requests.post.return_value = mock_response
            mock_requests.exceptions = __import__("requests").exceptions

            result = detector.detect("127.0.0.1", 19005, payloads=["direct_override"])

        # Should NOT detect vulnerability
        self.assertFalse(result.is_vulnerable)


class TestAPIHookBypassDetector(unittest.TestCase):
    """Tests for API Hook Bypass detector."""

    def test_detector_initialization(self):
        """Test detector initializes correctly."""
        detector = APIHookBypassDetector()
        self.assertEqual(detector.name, "api_hook_bypass")
        self.assertIsNone(detector.cve)
        self.assertTrue(len(detector.references) > 0)
        self.assertTrue(len(detector.ENDPOINTS) > 0)

    def test_no_hooks_detected(self):
        """Test detection when no security hooks are present."""
        detector = APIHookBypassDetector()

        # Mock response without any security headers
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.json.return_value = {"choices": [{"message": {"content": "hello"}}]}

        with patch("auditor.detectors.api_bypass_detector.requests") as mock_requests:
            mock_requests.post.return_value = mock_response
            mock_requests.exceptions = __import__("requests").exceptions

            result = detector.detect("127.0.0.1", 18789)

        # Should detect vulnerability (no hooks)
        self.assertTrue(result.is_vulnerable)
        self.assertTrue(len(result.findings) > 0)

    def test_hooks_present(self):
        """Test that endpoints with security hooks are recognized."""
        detector = APIHookBypassDetector()

        # Mock response with security headers
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"X-Security-Hook-Applied": "true"}
        mock_response.json.return_value = {"choices": [{"message": {"content": "filtered"}}]}

        with patch("auditor.detectors.api_bypass_detector.requests") as mock_requests:
            mock_requests.post.return_value = mock_response
            mock_requests.exceptions = __import__("requests").exceptions

            result = detector.detect("127.0.0.1", 18789)

        # Should NOT detect vulnerability (hooks present)
        self.assertFalse(result.is_vulnerable)


class TestDetectorBase(unittest.TestCase):
    """Tests for base detector functionality."""

    def test_vulnerability_status_values(self):
        """Test VulnerabilityStatus enum values."""
        self.assertEqual(VulnerabilityStatus.VULNERABLE.value, "vulnerable")
        self.assertEqual(VulnerabilityStatus.NOT_VULNERABLE.value, "not_vulnerable")
        self.assertEqual(VulnerabilityStatus.UNKNOWN.value, "unknown")

    def test_connection_refused(self):
        """Test behavior when connection is refused."""
        detector = WebSocketOriginDetector()
        result = detector.detect("127.0.0.1", 19999)  # No server running

        # Should not report as vulnerable when connection fails
        self.assertFalse(result.is_vulnerable)
        # Should have errors recorded
        self.assertTrue(len(result.errors) > 0)

    def test_detector_result_to_dict(self):
        """Test DetectorResult serialization."""
        detector = WebSocketOriginDetector()

        with patch.object(detector, "_test_origin", return_value=(False, {"status_code": 403})):
            result = detector.detect("127.0.0.1", 19999)

        result_dict = result.to_dict()
        self.assertIn("detector", result_dict)
        self.assertIn("target", result_dict)
        self.assertIn("findings", result_dict)
        self.assertIn("is_vulnerable", result_dict)
        self.assertEqual(result_dict["detector"], "websocket_origin")


if __name__ == "__main__":
    unittest.main()
