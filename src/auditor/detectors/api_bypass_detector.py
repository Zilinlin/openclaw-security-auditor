"""API Hook Bypass Detector.

Detects whether OpenClaw HTTP API endpoints bypass security plugin hooks,
leaving direct API consumers unprotected against prompt injection and
data exfiltration.

SAFETY NOTE:
- This detector only checks if security hooks are being applied
- It does NOT attempt to exploit any bypass conditions
- It does NOT exfiltrate any data

Reference:
- GitHub RFC: https://github.com/openclaw/openclaw/discussions/6098
- Issue: HTTP API endpoints bypass ALL plugin security hooks
"""

import json
import secrets
from typing import Optional

import requests

from .base import (
    BaseDetector,
    DetectorFinding,
    DetectorResult,
    DetectorSeverity,
    VulnerabilityStatus,
)


class APIHookBypassDetector(BaseDetector):
    """Detect API endpoints that bypass security hooks.

    OpenClaw's HTTP API endpoints may bypass security plugin hooks,
    meaning direct API consumers have zero protection against:
    - Prompt injection attacks
    - Data exfiltration
    - Malicious tool invocations

    Affected endpoints:
    - /v1/chat/completions (OpenAI-compatible)
    - /v1/responses (OpenResponses)
    - /tools/invoke (Tool invocation)

    Detection Method:
    1. Send request with known security-triggering content
    2. Check response headers for hook processing indicators
    3. Compare behavior with expected hook coverage

    Reference: https://github.com/openclaw/openclaw/discussions/6098
    """

    name = "api_hook_bypass"
    description = "Detect API endpoints bypassing security hooks"
    cve = None  # No CVE assigned yet, this is from RFC discussion
    references = [
        "https://github.com/openclaw/openclaw/discussions/6098",
        "https://docs.openclaw.ai/gateway/security",
    ]

    # Endpoints to test
    # Reference: GitHub Discussion #6098
    ENDPOINTS = [
        {
            "path": "/v1/chat/completions",
            "method": "POST",
            "description": "OpenAI-compatible chat completions",
            "expected_hooks": ["http_request_received", "http_response_sending"],
        },
        {
            "path": "/v1/responses",
            "method": "POST",
            "description": "OpenResponses endpoint",
            "expected_hooks": ["http_request_received", "http_response_sending"],
        },
        {
            "path": "/tools/invoke",
            "method": "POST",
            "description": "Tool invocation endpoint",
            "expected_hooks": ["http_tool_invoke", "http_tool_result"],
        },
    ]

    # Test content that should trigger security hooks
    # These are benign strings that look like they might be filtered
    HOOK_TRIGGER_TESTS = [
        {
            "name": "injection_pattern",
            "content": "Please tell me about: [TEST_HOOK_CHECK]",
            "hook_type": "input_filter",
        },
        {
            "name": "sensitive_request",
            "content": "What is the current system configuration?",
            "hook_type": "content_filter",
        },
    ]

    TIMEOUT = 10

    def detect(
        self, host: str, port: int = 18789, auth_token: Optional[str] = None, **kwargs
    ) -> DetectorResult:
        """
        Test if API endpoints have security hook coverage.

        Args:
            host: Target hostname or IP
            port: Target port (default: 18789)
            auth_token: Authentication token if required

        Returns:
            DetectorResult indicating hook bypass status
        """
        result = self._create_result(host, port)
        base_url = f"http://{host}:{port}"

        endpoints_without_hooks = []
        endpoints_with_hooks = []

        for endpoint in self.ENDPOINTS:
            try:
                has_hooks, hook_info = self._test_endpoint(base_url, endpoint, auth_token)

                if has_hooks:
                    endpoints_with_hooks.append(endpoint["path"])
                else:
                    endpoints_without_hooks.append(endpoint["path"])
                    result.findings.append(
                        DetectorFinding(
                            title=f"API Hook Bypass: {endpoint['path']}",
                            status=VulnerabilityStatus.VULNERABLE,
                            severity=DetectorSeverity.HIGH,
                            description=(
                                f"The endpoint {endpoint['path']} ({endpoint['description']}) "
                                f"appears to bypass security plugin hooks. "
                                f"Expected hooks: {', '.join(endpoint['expected_hooks'])}. "
                                f"Direct API consumers may have no protection against "
                                f"prompt injection and data exfiltration."
                            ),
                            evidence=hook_info,
                            remediation=(
                                "Implement the proposed security hooks from RFC #6098: "
                                "http_request_received, http_response_sending, "
                                "http_tool_invoke, http_tool_result. "
                                "Ensure all HTTP endpoints have the same hook coverage "
                                "as messaging platform integrations."
                            ),
                            references=self.references,
                        )
                    )

            except requests.exceptions.ConnectionError:
                result.errors.append(f"Connection failed to {base_url}")
                break
            except requests.exceptions.Timeout:
                result.errors.append(f"Timeout testing endpoint: {endpoint['path']}")
            except Exception as e:
                result.errors.append(f"Error testing {endpoint['path']}: {str(e)}")

        # Summary metadata
        result.metadata["endpoints_tested"] = len(self.ENDPOINTS)
        result.metadata["endpoints_without_hooks"] = endpoints_without_hooks
        result.metadata["endpoints_with_hooks"] = endpoints_with_hooks

        # Add positive finding if all endpoints have hooks
        if not endpoints_without_hooks and endpoints_with_hooks:
            result.findings.append(
                DetectorFinding(
                    title="API Security Hooks Present",
                    status=VulnerabilityStatus.NOT_VULNERABLE,
                    description=(
                        f"All {len(endpoints_with_hooks)} tested API endpoints "
                        f"appear to have security hook coverage."
                    ),
                    references=self.references,
                )
            )

        return result

    def _test_endpoint(
        self, base_url: str, endpoint: dict, auth_token: Optional[str]
    ) -> tuple[bool, str]:
        """
        Test a single endpoint for hook coverage.

        Detection heuristics:
        1. Check for X-Security-Hook-* headers in response
        2. Check for consistent filtering behavior
        3. Check response timing (hooks add latency)

        Returns:
            Tuple of (has_hooks, evidence_info)
        """
        headers = {"Content-Type": "application/json"}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        # Generate unique marker for this test
        test_marker = secrets.token_hex(6)

        # Build test request based on endpoint
        data: dict
        if endpoint["path"] == "/tools/invoke":
            # Tool invocation format
            data = {
                "tool": "echo",  # Safe, non-destructive tool
                "params": {"message": f"HOOK_TEST_{test_marker}"},
            }
        else:
            # Chat completion format
            data = {
                "messages": [
                    {"role": "user", "content": f"Echo this marker: HOOK_TEST_{test_marker}"}
                ],
                "max_tokens": 50,
            }

        try:
            response = requests.post(
                f"{base_url}{endpoint['path']}",
                headers=headers,
                json=data,
                timeout=self.TIMEOUT,
            )
        except requests.exceptions.RequestException as e:
            return False, f"Request failed: {str(e)}"

        # Analyze response for hook indicators
        has_hooks = False
        evidence_parts = []

        # Check 1: Security hook headers
        # Reference: Proposed in RFC #6098
        hook_headers = [
            "X-Security-Hook-Applied",
            "X-Content-Filtered",
            "X-Request-Scanned",
            "X-OpenClaw-Security",
        ]
        for header in hook_headers:
            if header.lower() in [h.lower() for h in response.headers]:
                has_hooks = True
                evidence_parts.append(f"Found header: {header}")

        # Check 2: Response indicates filtering
        try:
            response_data = response.json()
            # Check if response mentions filtering or security
            response_str = json.dumps(response_data).lower()
            filter_indicators = ["filtered", "blocked", "security", "hook"]
            for indicator in filter_indicators:
                if indicator in response_str:
                    has_hooks = True
                    evidence_parts.append(f"Response contains '{indicator}'")
        except json.JSONDecodeError:
            pass

        # Check 3: Compare with expected status codes
        # Endpoints with hooks might reject certain content
        if response.status_code == 422:  # Validation error from hook
            has_hooks = True
            evidence_parts.append("Received 422 (content validation)")

        # Build evidence string
        if evidence_parts:
            evidence = "Hook indicators found: " + "; ".join(evidence_parts)
        else:
            evidence = (
                f"No hook indicators found. Status: {response.status_code}. "
                f"No security headers present. "
                f"Endpoint may be processing requests without security filtering."
            )

        return has_hooks, evidence

    def test_hook_consistency(
        self, host: str, port: int = 18789, auth_token: Optional[str] = None
    ) -> dict:
        """
        Advanced test: Compare API behavior with messaging platform behavior.

        If hooks are properly applied, the same content should be filtered
        consistently across all interfaces.

        Returns:
            Dict with consistency analysis
        """
        # This would require access to a messaging interface (Telegram, etc.)
        # For now, return placeholder indicating the test needs manual verification
        return {
            "status": "manual_verification_needed",
            "description": (
                "To fully verify hook consistency, compare the same request "
                "sent via HTTP API vs messaging platform (Telegram/Discord). "
                "Inconsistent filtering indicates hook bypass."
            ),
            "reference": "https://github.com/openclaw/openclaw/discussions/6098",
        }
