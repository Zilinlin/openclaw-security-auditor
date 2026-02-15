"""Authentication Weakness Detector.

Tests OpenClaw authentication enforcement on API endpoints.

SAFETY NOTE:
- This detector only tests if authentication is enforced
- It does NOT attempt brute force attacks
- It does NOT attempt to steal or use valid credentials

Reference:
- Research: https://www.infosecurity-magazine.com/news/researchers-40000-exposed-openclaw/
- SecurityWeek: https://www.securityweek.com/vulnerability-allows-hackers-to-hijack-openclaw-ai-assistant/
"""

import secrets
from typing import Dict, List, Optional, Tuple

import requests

from .base import (
    BaseDetector,
    DetectorFinding,
    DetectorResult,
    DetectorSeverity,
    VulnerabilityStatus,
)


class AuthWeaknessDetector(BaseDetector):
    """Detect authentication weaknesses in OpenClaw deployments.

    Security research found that 93.4% of exposed OpenClaw instances
    were vulnerable to authentication bypass attacks.

    Detection Method:
    1. Test endpoints without any authentication
    2. Test endpoints with invalid/malformed tokens
    3. Check for overly permissive token scopes
    4. Test for default credentials

    What this detector does NOT do:
    - Does NOT attempt brute force attacks
    - Does NOT attempt credential stuffing
    - Does NOT store or exfiltrate valid credentials

    Reference: https://www.infosecurity-magazine.com/news/researchers-40000-exposed-openclaw/
    """

    name = "auth_weakness"
    description = "Detect authentication weaknesses"
    cve = "CVE-2026-25157"
    references = [
        "https://www.infosecurity-magazine.com/news/researchers-40000-exposed-openclaw/",
        "https://www.securityweek.com/vulnerability-allows-hackers-to-hijack-openclaw-ai-assistant/",
        "https://docs.openclaw.ai/gateway/security",
    ]

    # Endpoints to test authentication on
    PROTECTED_ENDPOINTS = [
        {"path": "/api/v1/status", "method": "GET", "description": "System status"},
        {"path": "/api/v1/config", "method": "GET", "description": "Configuration"},
        {"path": "/v1/chat/completions", "method": "POST", "description": "Chat API"},
        {"path": "/tools/invoke", "method": "POST", "description": "Tool invocation"},
        {"path": "/api/v1/agents", "method": "GET", "description": "Agent list"},
        {"path": "/api/v1/skills", "method": "GET", "description": "Skills list"},
    ]

    # Invalid tokens to test
    # These should ALL be rejected by a properly configured system
    INVALID_TOKENS = [
        "",  # Empty token
        "invalid",  # Obviously invalid
        "Bearer ",  # Empty bearer
        "null",  # Null string
        "undefined",  # Undefined string
        "admin",  # Common weak token
        "test",  # Test token
    ]

    TIMEOUT = 10

    def detect(
        self,
        host: str,
        port: int = 18789,
        **kwargs
    ) -> DetectorResult:
        """
        Test authentication enforcement on API endpoints.

        Args:
            host: Target hostname or IP
            port: Target port (default: 18789)

        Returns:
            DetectorResult with authentication findings
        """
        result = self._create_result(host, port)
        base_url = f"http://{host}:{port}"

        # Track findings by category
        no_auth_endpoints = []
        weak_auth_endpoints = []
        protected_endpoints = []

        for endpoint in self.PROTECTED_ENDPOINTS:
            try:
                auth_status = self._test_endpoint_auth(base_url, endpoint)

                if auth_status["no_auth_required"]:
                    no_auth_endpoints.append(endpoint["path"])
                    result.findings.append(DetectorFinding(
                        title=f"No Authentication Required: {endpoint['path']}",
                        status=VulnerabilityStatus.VULNERABLE,
                        severity=DetectorSeverity.CRITICAL,
                        cve=self.cve,
                        description=(
                            f"The endpoint {endpoint['path']} ({endpoint['description']}) "
                            f"is accessible without any authentication. "
                            f"This allows unauthorized access to potentially sensitive "
                            f"functionality."
                        ),
                        evidence=auth_status["evidence"],
                        remediation=(
                            "Enable authentication for all API endpoints. "
                            "Configure strong, unique API tokens. "
                            "Consider implementing rate limiting and IP allowlisting."
                        ),
                        references=self.references,
                    ))

                elif auth_status["accepts_invalid_token"]:
                    weak_auth_endpoints.append(endpoint["path"])
                    result.findings.append(DetectorFinding(
                        title=f"Weak Token Validation: {endpoint['path']}",
                        status=VulnerabilityStatus.VULNERABLE,
                        severity=DetectorSeverity.HIGH,
                        description=(
                            f"The endpoint {endpoint['path']} accepts invalid or "
                            f"malformed authentication tokens. "
                            f"Token validation may be improperly implemented."
                        ),
                        evidence=auth_status["evidence"],
                        remediation=(
                            "Implement proper token validation. "
                            "Reject empty, null, and malformed tokens. "
                            "Use constant-time comparison for token validation."
                        ),
                        references=self.references,
                    ))

                else:
                    protected_endpoints.append(endpoint["path"])

            except requests.exceptions.ConnectionError:
                result.errors.append(f"Connection failed to {base_url}")
                break
            except requests.exceptions.Timeout:
                result.errors.append(f"Timeout testing: {endpoint['path']}")
            except Exception as e:
                result.errors.append(f"Error testing {endpoint['path']}: {str(e)}")

        # Test for default credentials if we found open endpoints
        if no_auth_endpoints:
            default_creds_result = self._test_default_credentials(base_url)
            if default_creds_result["found"]:
                result.findings.append(DetectorFinding(
                    title="Default Credentials Detected",
                    status=VulnerabilityStatus.VULNERABLE,
                    severity=DetectorSeverity.CRITICAL,
                    description=(
                        "The system appears to be using default or commonly known "
                        "credentials. This allows trivial unauthorized access."
                    ),
                    evidence=default_creds_result["evidence"],
                    remediation=(
                        "Change all default credentials immediately. "
                        "Use strong, randomly generated passwords. "
                        "Implement password complexity requirements."
                    ),
                    references=self.references,
                ))

        # Summary metadata
        result.metadata["endpoints_tested"] = len(self.PROTECTED_ENDPOINTS)
        result.metadata["no_auth_required"] = no_auth_endpoints
        result.metadata["weak_auth"] = weak_auth_endpoints
        result.metadata["properly_protected"] = protected_endpoints

        # Add positive finding if all endpoints are protected
        if not no_auth_endpoints and not weak_auth_endpoints and protected_endpoints:
            result.findings.append(DetectorFinding(
                title="Authentication Properly Enforced",
                status=VulnerabilityStatus.NOT_VULNERABLE,
                description=(
                    f"All {len(protected_endpoints)} tested endpoints properly "
                    f"require and validate authentication tokens."
                ),
                references=self.references,
            ))

        return result

    def _test_endpoint_auth(
        self,
        base_url: str,
        endpoint: Dict
    ) -> Dict:
        """
        Test authentication requirements for a single endpoint.

        Returns:
            Dict with auth status and evidence
        """
        result = {
            "no_auth_required": False,
            "accepts_invalid_token": False,
            "evidence": "",
        }

        url = f"{base_url}{endpoint['path']}"
        method = endpoint["method"].upper()

        # Test 1: Request without any authentication
        try:
            if method == "GET":
                response = requests.get(url, timeout=self.TIMEOUT)
            else:
                response = requests.post(
                    url,
                    json={"test": "auth_check"},
                    timeout=self.TIMEOUT
                )

            if response.status_code in (200, 201):
                result["no_auth_required"] = True
                result["evidence"] = (
                    f"Endpoint returned {response.status_code} without authentication. "
                    f"Response length: {len(response.content)} bytes."
                )
                return result
            elif response.status_code not in (401, 403):
                # Unexpected status code - might indicate misconfiguration
                result["evidence"] = (
                    f"Unexpected status {response.status_code} without auth. "
                    f"Expected 401 or 403."
                )

        except Exception as e:
            result["evidence"] = f"Error testing no-auth: {str(e)}"

        # Test 2: Request with invalid tokens
        for invalid_token in self.INVALID_TOKENS:
            try:
                headers = {"Authorization": f"Bearer {invalid_token}"}

                if method == "GET":
                    response = requests.get(url, headers=headers, timeout=self.TIMEOUT)
                else:
                    response = requests.post(
                        url,
                        headers=headers,
                        json={"test": "auth_check"},
                        timeout=self.TIMEOUT
                    )

                if response.status_code in (200, 201):
                    result["accepts_invalid_token"] = True
                    result["evidence"] = (
                        f"Endpoint accepted invalid token: '{invalid_token}'. "
                        f"Status: {response.status_code}."
                    )
                    return result

            except Exception:
                pass

        # If we get here, authentication seems properly enforced
        result["evidence"] = "Authentication properly enforced (401/403 returned)"
        return result

    def _test_default_credentials(self, base_url: str) -> Dict:
        """
        Test for common default credentials.

        NOTE: This only tests a small set of extremely common defaults.
        It does NOT perform brute force attacks.

        Returns:
            Dict with findings
        """
        result = {
            "found": False,
            "evidence": "",
        }

        # Common default credentials to check
        # These are publicly documented defaults that should be changed
        DEFAULT_CREDS = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "openclaw"),
            ("root", "root"),
            ("user", "user"),
        ]

        # Check if there's a login endpoint
        login_endpoints = [
            "/api/v1/auth/login",
            "/api/auth/login",
            "/login",
        ]

        for login_endpoint in login_endpoints:
            for username, password in DEFAULT_CREDS:
                try:
                    response = requests.post(
                        f"{base_url}{login_endpoint}",
                        json={"username": username, "password": password},
                        timeout=self.TIMEOUT,
                    )

                    if response.status_code in (200, 201):
                        # Check if response indicates successful login
                        try:
                            data = response.json()
                            if "token" in data or "access_token" in data:
                                result["found"] = True
                                result["evidence"] = (
                                    f"Default credentials accepted: {username}:*** "
                                    f"at {login_endpoint}"
                                )
                                return result
                        except Exception:
                            pass

                except Exception:
                    pass

        return result

    def test_token_scope(
        self,
        host: str,
        port: int,
        token: str
    ) -> Dict:
        """
        Test if a token has overly permissive scopes.

        Reference: CVE-2026-25253 notes that tokens may have
        operator.admin and operator.approvals scopes.

        Args:
            host: Target hostname
            port: Target port
            token: Token to test

        Returns:
            Dict with scope analysis
        """
        result = {
            "overly_permissive": False,
            "scopes_detected": [],
            "evidence": "",
        }

        base_url = f"http://{host}:{port}"
        headers = {"Authorization": f"Bearer {token}"}

        # Test endpoints that require elevated privileges
        privileged_endpoints = [
            ("/api/v1/admin/config", "admin"),
            ("/api/v1/system/restart", "admin"),
            ("/exec.approvals.set", "operator.approvals"),
            ("/api/v1/gateway/settings", "operator.admin"),
        ]

        for endpoint, required_scope in privileged_endpoints:
            try:
                response = requests.get(
                    f"{base_url}{endpoint}",
                    headers=headers,
                    timeout=self.TIMEOUT,
                )

                if response.status_code in (200, 201):
                    result["scopes_detected"].append(required_scope)

            except Exception:
                pass

        if result["scopes_detected"]:
            result["overly_permissive"] = True
            result["evidence"] = (
                f"Token has access to privileged endpoints requiring: "
                f"{', '.join(result['scopes_detected'])}"
            )

        return result
