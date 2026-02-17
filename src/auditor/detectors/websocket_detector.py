"""WebSocket Origin Bypass Detector.

Detects CVE-2026-25253: Cross-Site WebSocket Hijacking (CSWSH) vulnerability
in OpenClaw's WebSocket server.

SAFETY NOTE:
- This detector only tests if the WebSocket server validates Origin headers
- It does NOT attempt to steal authentication tokens
- It does NOT execute any commands on the target

Reference:
- CVE: https://nvd.nist.gov/vuln/detail/CVE-2026-25253
- Research: https://depthfirst.com/post/1-click-rce-to-steal-your-moltbot-data-and-keys
- Advisory: https://socradar.io/blog/cve-2026-25253-rce-openclaw-auth-token/
"""

import base64
import hashlib
import os
import socket
import ssl

from .base import (
    BaseDetector,
    DetectorFinding,
    DetectorResult,
    DetectorSeverity,
    VulnerabilityStatus,
)


class WebSocketOriginDetector(BaseDetector):
    """Detect WebSocket Origin validation bypass (CVE-2026-25253).

    This vulnerability allows attackers to perform Cross-Site WebSocket
    Hijacking (CSWSH) because the OpenClaw WebSocket server does not
    validate the Origin header.

    Detection Method:
    1. Send WebSocket upgrade request with spoofed Origin header
    2. If server accepts (101 Switching Protocols) → Vulnerable
    3. If server rejects (403 or connection refused) → Not vulnerable

    What this detector does NOT do:
    - Does NOT exfiltrate authentication tokens
    - Does NOT execute any commands
    - Does NOT modify any server state
    """

    name = "websocket_origin"
    description = "Detect WebSocket Origin validation bypass (CVE-2026-25253)"
    cve = "CVE-2026-25253"
    references = [
        "https://nvd.nist.gov/vuln/detail/CVE-2026-25253",
        "https://depthfirst.com/post/1-click-rce-to-steal-your-moltbot-data-and-keys",
        "https://socradar.io/blog/cve-2026-25253-rce-openclaw-auth-token/",
    ]

    # Spoofed origins to test
    # These are clearly fake domains to avoid any accidental legitimate requests
    TEST_ORIGINS = [
        "https://attacker-test.invalid",
        "https://malicious-origin.invalid",
        "null",  # Some implementations may accept null origin
    ]

    TIMEOUT = 5

    def detect(
        self, host: str, port: int = 18789, use_ssl: bool = False, **kwargs
    ) -> DetectorResult:
        """
        Test if WebSocket server validates Origin header.

        Args:
            host: Target hostname or IP
            port: Target port (default: 18789)
            use_ssl: Whether to use WSS (WebSocket Secure)

        Returns:
            DetectorResult indicating if vulnerable to CSWSH
        """
        result = self._create_result(host, port)

        # Test each spoofed origin
        for origin in self.TEST_ORIGINS:
            try:
                is_vulnerable, response_info = self._test_origin(host, port, origin, use_ssl)

                if is_vulnerable:
                    result.findings.append(
                        DetectorFinding(
                            title="WebSocket Origin Validation Bypass",
                            status=VulnerabilityStatus.VULNERABLE,
                            severity=DetectorSeverity.CRITICAL,
                            cve=self.cve,
                            description=(
                                f"The WebSocket server accepted a connection with "
                                f"spoofed Origin header '{origin}'. This enables "
                                f"Cross-Site WebSocket Hijacking (CSWSH) attacks, "
                                f"allowing attackers to steal authentication tokens "
                                f"via malicious web pages."
                            ),
                            evidence=f"Server accepted WebSocket upgrade with Origin: {origin}",
                            remediation=(
                                "Upgrade to OpenClaw v2026.1.29 or later. "
                                "The fix adds a gateway URL confirmation modal "
                                "preventing auto-connect behavior. "
                                "Additionally, configure allowed origins in settings."
                            ),
                            references=self.references,
                        )
                    )
                    # Found vulnerability, no need to test more origins
                    return result

            except socket.timeout:
                result.errors.append(f"Connection timeout testing origin: {origin}")
            except ConnectionRefusedError:
                result.errors.append(f"Connection refused on {host}:{port}")
                break  # No point testing more origins
            except Exception as e:
                result.errors.append(f"Error testing origin {origin}: {str(e)}")

        # If we get here, no vulnerability was found
        if not result.findings and not result.errors:
            result.findings.append(
                DetectorFinding(
                    title="WebSocket Origin Validation",
                    status=VulnerabilityStatus.NOT_VULNERABLE,
                    description=(
                        "The WebSocket server properly rejects connections with "
                        "unauthorized Origin headers. CSWSH attacks are mitigated."
                    ),
                    references=self.references,
                )
            )

        return result

    def _test_origin(self, host: str, port: int, origin: str, use_ssl: bool) -> tuple[bool, dict]:
        """
        Test if server accepts WebSocket connection with given Origin.

        Returns:
            Tuple of (is_vulnerable, response_info)
        """
        # Generate WebSocket key
        ws_key = base64.b64encode(os.urandom(16)).decode("utf-8")

        # Build WebSocket upgrade request
        # Reference: RFC 6455 - The WebSocket Protocol
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Origin: {origin}\r\n"
            f"\r\n"
        )

        # Create socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.TIMEOUT)

        try:
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)

            sock.connect((host, port))
            sock.send(request.encode("utf-8"))

            # Receive response
            response = sock.recv(4096).decode("utf-8", errors="ignore")

            # Parse response
            response_info = self._parse_http_response(response)

            # Check if WebSocket upgrade was accepted
            # 101 Switching Protocols indicates successful upgrade
            is_vulnerable = response_info.get("status_code") == 101

            # Also check for the expected Sec-WebSocket-Accept header
            if is_vulnerable:
                expected_accept = self._compute_accept_key(ws_key)
                actual_accept = response_info.get("headers", {}).get("sec-websocket-accept", "")
                # Verify it's a real WebSocket response
                is_vulnerable = actual_accept == expected_accept

            return is_vulnerable, response_info

        finally:
            sock.close()

    def _parse_http_response(self, response: str) -> dict:  # type: ignore[type-arg]
        """Parse HTTP response into status code and headers."""
        result: dict = {
            "status_code": None,
            "status_text": "",
            "headers": {},
        }

        lines = response.split("\r\n")
        if not lines:
            return result

        # Parse status line
        status_line = lines[0]
        parts = status_line.split(" ", 2)
        if len(parts) >= 2:
            try:
                result["status_code"] = int(parts[1])
                result["status_text"] = parts[2] if len(parts) > 2 else ""
            except ValueError:
                pass

        # Parse headers
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                result["headers"][key.strip().lower()] = value.strip()

        return result

    def _compute_accept_key(self, ws_key: str) -> str:
        """Compute expected Sec-WebSocket-Accept value.

        Reference: RFC 6455 Section 1.3
        """
        GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        accept = ws_key + GUID
        sha1 = hashlib.sha1(accept.encode("utf-8")).digest()
        return base64.b64encode(sha1).decode("utf-8")
