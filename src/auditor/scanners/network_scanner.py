"""Network exposure scanner for OpenClaw instances."""

import socket
import ssl
from typing import Optional
from urllib.parse import urlparse

from .base import BaseScanner, Finding, ScanResult, Severity


class NetworkScanner(BaseScanner):
    """Scans for network exposure and connectivity issues."""

    name = "network"
    description = "Check for network exposure and insecure connectivity"

    DEFAULT_PORT = 18789
    TIMEOUT = 5

    def scan(
        self, target: str, host: Optional[str] = None, port: Optional[int] = None, **kwargs
    ) -> ScanResult:
        """
        Check network exposure of an OpenClaw instance.

        Args:
            target: Host to check (can also be passed via 'host' parameter)
            host: Host to check
            port: Port to check (default: 18789)

        Returns:
            ScanResult with network exposure findings
        """
        result = ScanResult(scanner_name=self.name)

        check_host = host or target
        check_port = port or self.DEFAULT_PORT

        # Parse host if it's a URL
        if "://" in check_host:
            parsed = urlparse(check_host)
            check_host = parsed.hostname or check_host
            check_port = parsed.port or check_port

        result.scanned_items = 1

        # Check if port is open
        port_open, banner = self._check_port(check_host, check_port)

        if port_open:
            # Check if it's actually OpenClaw
            if self._is_openclaw(banner):
                result.findings.append(
                    Finding(
                        title="OpenClaw instance accessible",
                        severity=Severity.INFO,
                        description=f"OpenClaw instance found at {check_host}:{check_port}",
                        location=f"{check_host}:{check_port}",
                    )
                )

                # Check for public exposure
                if self._is_public_ip(check_host):
                    result.findings.append(
                        Finding(
                            title="OpenClaw exposed to public internet",
                            severity=Severity.CRITICAL,
                            description=f"The OpenClaw instance at {check_host}:{check_port} is "
                            "accessible from the public internet. This exposes the "
                            "instance to remote attacks.",
                            location=f"{check_host}:{check_port}",
                            remediation="Bind to 127.0.0.1 for local-only access, or use a firewall "
                            "to restrict access to trusted IP addresses.",
                            references=[
                                "https://github.com/openclaw/openclaw/blob/main/docs/security.md",
                            ],
                        )
                    )

                # Check SSL/TLS
                ssl_findings = self._check_ssl(check_host, check_port)
                result.findings.extend(ssl_findings)

                # Check for authentication
                auth_findings = self._check_auth(check_host, check_port)
                result.findings.extend(auth_findings)
            else:
                result.findings.append(
                    Finding(
                        title="Port open but not OpenClaw",
                        severity=Severity.INFO,
                        description=f"Port {check_port} is open at {check_host} but does not "
                        "appear to be an OpenClaw instance.",
                        location=f"{check_host}:{check_port}",
                    )
                )
        else:
            result.findings.append(
                Finding(
                    title="OpenClaw port not accessible",
                    severity=Severity.INFO,
                    description=f"Could not connect to {check_host}:{check_port}. "
                    "The instance may be properly firewalled or not running.",
                    location=f"{check_host}:{check_port}",
                )
            )

        return result

    def _check_port(self, host: str, port: int) -> tuple[bool, Optional[str]]:
        """Check if a port is open and get banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.TIMEOUT)
            result = sock.connect_ex((host, port))

            if result == 0:
                # Try to get banner
                try:
                    sock.send(b"GET / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024).decode("utf-8", errors="ignore")
                except Exception:
                    banner = None

                sock.close()
                return True, banner
            else:
                sock.close()
                return False, None
        except socket.gaierror:
            return False, None
        except Exception:
            return False, None

    def _is_openclaw(self, banner: Optional[str]) -> bool:
        """Check if banner indicates OpenClaw."""
        if not banner:
            return True  # Assume it might be OpenClaw if port matches

        openclaw_indicators = [
            "openclaw",
            "moltbot",
            "clawdbot",
            "x-openclaw",
        ]

        banner_lower = banner.lower()
        return any(indicator in banner_lower for indicator in openclaw_indicators)

    def _is_public_ip(self, host: str) -> bool:
        """Check if host is a public IP or resolves to one."""
        try:
            # Resolve hostname to IP
            ip = socket.gethostbyname(host)

            # Check for private/local IP ranges
            private_ranges = [
                "127.",
                "10.",
                "192.168.",
                "172.16.",
                "172.17.",
                "172.18.",
                "172.19.",
                "172.20.",
                "172.21.",
                "172.22.",
                "172.23.",
                "172.24.",
                "172.25.",
                "172.26.",
                "172.27.",
                "172.28.",
                "172.29.",
                "172.30.",
                "172.31.",
                "169.254.",
                "::1",
                "fe80:",
            ]

            for prefix in private_ranges:
                if ip.startswith(prefix):
                    return False

            return True
        except socket.gaierror:
            return False

    def _check_ssl(self, host: str, port: int) -> list[Finding]:
        """Check SSL/TLS configuration."""
        findings = []

        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    ssock.getpeercert()
                    # SSL is working
                    findings.append(
                        Finding(
                            title="SSL/TLS enabled",
                            severity=Severity.INFO,
                            description="The connection is secured with SSL/TLS.",
                            location=f"{host}:{port}",
                        )
                    )
        except ssl.SSLError as e:
            if "certificate" in str(e).lower():
                findings.append(
                    Finding(
                        title="SSL certificate issue",
                        severity=Severity.MEDIUM,
                        description=f"SSL certificate validation failed: {e}",
                        location=f"{host}:{port}",
                        remediation="Install a valid SSL certificate from a trusted CA.",
                    )
                )
        except Exception:
            findings.append(
                Finding(
                    title="No SSL/TLS encryption",
                    severity=Severity.HIGH,
                    description="The connection is not encrypted with SSL/TLS.",
                    location=f"{host}:{port}",
                    remediation="Enable SSL/TLS to encrypt communications.",
                )
            )

        return findings

    def _check_auth(self, host: str, port: int) -> list[Finding]:
        """Check if authentication is required."""
        findings = []

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.TIMEOUT)
            sock.connect((host, port))

            # Try to access API without auth
            request = (
                "GET /api/v1/status HTTP/1.1\r\n" f"Host: {host}\r\n" "Connection: close\r\n" "\r\n"
            )
            sock.send(request.encode())
            response = sock.recv(4096).decode("utf-8", errors="ignore")
            sock.close()

            if "200 OK" in response or "200 ok" in response.lower():
                # Check if response contains sensitive data
                if any(word in response.lower() for word in ["version", "config", "status"]):
                    findings.append(
                        Finding(
                            title="API accessible without authentication",
                            severity=Severity.HIGH,
                            description="The OpenClaw API is accessible without authentication. "
                            "This may allow unauthorized access to sensitive functions.",
                            location=f"{host}:{port}/api/v1/status",
                            remediation="Enable authentication for all API endpoints.",
                        )
                    )
            elif "401" in response or "403" in response:
                findings.append(
                    Finding(
                        title="Authentication required",
                        severity=Severity.INFO,
                        description="The API properly requires authentication.",
                        location=f"{host}:{port}",
                    )
                )
        except Exception:
            pass

        return findings
