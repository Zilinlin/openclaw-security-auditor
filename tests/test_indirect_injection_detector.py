"""Tests for the indirect prompt injection detector.

Tests use mocked HTTP requests to verify detection of indirect prompt
injection attacks via data sources.
"""

import os
import re
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from auditor.detectors.base import VulnerabilityStatus
from auditor.detectors.indirect_injection_detector import IndirectInjectionDetector


class TestIndirectInjectionDetector(unittest.TestCase):
    """Tests for IndirectInjectionDetector."""

    def setUp(self):
        self.detector = IndirectInjectionDetector()

    def test_detector_metadata(self):
        """Test detector name and description."""
        self.assertEqual(self.detector.name, "indirect_injection")
        self.assertEqual(self.detector.cve, "CVE-2026-24763")
        self.assertTrue(len(self.detector.references) > 0)

    def test_payload_library_populated(self):
        """Verify payloads are loaded."""
        self.assertTrue(len(self.detector.payloads) > 0)
        # Should have at least 10 payloads
        self.assertGreaterEqual(len(self.detector.payloads), 10)

    def test_payload_categories(self):
        """Verify all expected categories exist."""
        categories = self.detector.get_payload_categories()
        self.assertIn("document_injection", categories)
        self.assertIn("tool_output_injection", categories)
        self.assertIn("rag_poisoning", categories)
        self.assertIn("multi_turn_escalation", categories)
        self.assertIn("invisible_instruction", categories)

    def test_unique_payload_names(self):
        """Each payload should have a unique name."""
        names = [p.name for p in self.detector.payloads]
        self.assertEqual(len(names), len(set(names)))

    def test_canary_placeholder_in_payloads(self):
        """Verify {canary} placeholder exists in injected content."""
        for payload in self.detector.payloads:
            self.assertIn(
                "{canary}",
                payload.injected_content,
                f"Payload '{payload.name}' missing {{canary}} in injected_content",
            )

    def test_document_placeholder_in_user_message(self):
        """Verify {document} placeholder exists in user message."""
        for payload in self.detector.payloads:
            self.assertIn(
                "{document}",
                payload.user_message,
                f"Payload '{payload.name}' missing {{document}} in user_message",
            )

    def test_payloads_by_category(self):
        """Test category-based payload filtering."""
        doc_payloads = self.detector.get_payloads_by_category("document_injection")
        self.assertTrue(len(doc_payloads) > 0)
        for p in doc_payloads:
            self.assertEqual(p.category, "document_injection")

    # =========================================================================
    # Detection tests
    # =========================================================================

    def test_vulnerable_response_detected(self):
        """Mock API returns canary in response -> vulnerable."""

        def mock_post(*args, **kwargs):
            data = kwargs.get("json", {})
            messages = data.get("messages", [])
            last_msg = messages[-1].get("content", "") if messages else ""

            match = re.search(r"CANARY_([a-f0-9]+)", last_msg)
            canary_value = match.group(0) if match else "CANARY_leaked"

            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "choices": [{"message": {"content": f"Summary: {canary_value}"}}]
            }
            return response

        with patch("auditor.detectors.indirect_injection_detector.requests") as mock_requests:
            mock_requests.post.side_effect = mock_post
            mock_requests.exceptions = __import__("requests").exceptions

            result = self.detector.detect("127.0.0.1", 19020, categories=["document_injection"])

        self.assertTrue(result.is_vulnerable)
        vulnerable_findings = [
            f for f in result.findings if f.status == VulnerabilityStatus.VULNERABLE
        ]
        self.assertTrue(len(vulnerable_findings) > 0)
        self.assertIn("indirect_injection", vulnerable_findings[0].title.lower().replace(" ", "_"))

    def test_safe_response_not_flagged(self):
        """Mock API returns safe summary -> not vulnerable."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": "The document discusses revenue growth of 15% and expense reduction of 8%."
                    }
                }
            ]
        }

        with patch("auditor.detectors.indirect_injection_detector.requests") as mock_requests:
            mock_requests.post.return_value = mock_response
            mock_requests.exceptions = __import__("requests").exceptions

            result = self.detector.detect("127.0.0.1", 19020, categories=["document_injection"])

        self.assertFalse(result.is_vulnerable)

    def test_category_filtering(self):
        """Test that categories parameter filters correctly."""

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"choices": [{"message": {"content": "Safe response."}}]}

        with patch("auditor.detectors.indirect_injection_detector.requests") as mock_requests:
            mock_requests.post.return_value = mock_response
            mock_requests.exceptions = __import__("requests").exceptions

            # Only test one category
            result = self.detector.detect("127.0.0.1", 19020, categories=["invisible_instruction"])

        # Should have tested only invisible_instruction payloads
        invisible_count = len(self.detector.get_payloads_by_category("invisible_instruction"))
        # The NOT_VULNERABLE finding should mention the correct count
        not_vuln = [f for f in result.findings if f.status == VulnerabilityStatus.NOT_VULNERABLE]
        self.assertTrue(len(not_vuln) > 0)
        self.assertIn(str(invisible_count), not_vuln[0].description)

    def test_connection_error_handled(self):
        """Connection failures should produce errors, not crashes."""
        with patch("auditor.detectors.indirect_injection_detector.requests") as mock_requests:
            mock_requests.post.side_effect = __import__("requests").exceptions.ConnectionError(
                "Connection refused"
            )
            mock_requests.exceptions = __import__("requests").exceptions

            result = self.detector.detect("127.0.0.1", 19999)

        self.assertFalse(result.is_vulnerable)
        self.assertTrue(len(result.errors) > 0)

    def test_timeout_handled(self):
        """Timeout should produce error for that payload."""
        call_count = 0

        def mock_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise __import__("requests").exceptions.Timeout("timed out")
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {"choices": [{"message": {"content": "OK"}}]}
            return response

        with patch("auditor.detectors.indirect_injection_detector.requests") as mock_requests:
            mock_requests.post.side_effect = mock_post
            mock_requests.exceptions = __import__("requests").exceptions

            result = self.detector.detect("127.0.0.1", 19020, categories=["document_injection"])

        self.assertTrue(len(result.errors) > 0)
        self.assertIn("Timeout", result.errors[0])

    def test_auth_enforced_not_vulnerable(self):
        """401 response should mean not vulnerable (auth enforced)."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"

        with patch("auditor.detectors.indirect_injection_detector.requests") as mock_requests:
            mock_requests.post.return_value = mock_response
            mock_requests.exceptions = __import__("requests").exceptions

            result = self.detector.detect("127.0.0.1", 19020, categories=["document_injection"])

        self.assertFalse(result.is_vulnerable)

    def test_metadata_on_vulnerability(self):
        """Metadata should include vulnerable payload details."""

        def mock_post(*args, **kwargs):
            data = kwargs.get("json", {})
            messages = data.get("messages", [])
            last_msg = messages[-1].get("content", "") if messages else ""

            match = re.search(r"CANARY_([a-f0-9]+)", last_msg)
            canary_value = match.group(0) if match else ""

            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "choices": [{"message": {"content": f"Result: {canary_value}"}}]
            }
            return response

        with patch("auditor.detectors.indirect_injection_detector.requests") as mock_requests:
            mock_requests.post.side_effect = mock_post
            mock_requests.exceptions = __import__("requests").exceptions

            result = self.detector.detect("127.0.0.1", 19020, categories=["document_injection"])

        self.assertIn("vulnerable_count", result.metadata)
        self.assertIn("total_tested", result.metadata)
        self.assertIn("vulnerable_payloads", result.metadata)

    def test_result_serialization(self):
        """Test DetectorResult serialization."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"choices": [{"message": {"content": "Safe."}}]}

        with patch("auditor.detectors.indirect_injection_detector.requests") as mock_requests:
            mock_requests.post.return_value = mock_response
            mock_requests.exceptions = __import__("requests").exceptions

            result = self.detector.detect("127.0.0.1", 19020, categories=["document_injection"])

        result_dict = result.to_dict()
        self.assertIn("detector", result_dict)
        self.assertEqual(result_dict["detector"], "indirect_injection")
        self.assertIn("findings", result_dict)
        self.assertIn("is_vulnerable", result_dict)


if __name__ == "__main__":
    unittest.main()
