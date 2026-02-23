"""Tests for the output safety detector.

Tests use mocked HTTP requests to verify detection of unsafe patterns
in agent-generated code outputs.
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from auditor.detectors.base import VulnerabilityStatus
from auditor.detectors.output_safety_detector import OutputSafetyDetector


class TestOutputSafetyDetector(unittest.TestCase):
    """Tests for OutputSafetyDetector."""

    def setUp(self):
        self.detector = OutputSafetyDetector()

    def test_detector_metadata(self):
        """Test detector name and description."""
        self.assertEqual(self.detector.name, "output_safety")
        self.assertIsNone(self.detector.cve)
        self.assertTrue(len(self.detector.references) > 0)

    def test_test_cases_populated(self):
        """Verify test cases are loaded."""
        self.assertTrue(len(self.detector.test_cases) > 0)
        self.assertGreaterEqual(len(self.detector.test_cases), 8)

    def test_test_categories(self):
        """Verify all expected categories exist."""
        categories = self.detector.get_test_categories()
        self.assertIn("xss_output", categories)
        self.assertIn("sqli_output", categories)
        self.assertIn("cmdi_output", categories)
        self.assertIn("ssrf_output", categories)
        self.assertIn("path_traversal_output", categories)

    # =========================================================================
    # XSS detection
    # =========================================================================

    def test_xss_innerhtml_detected(self):
        """Mock response with innerHTML -> detected as unsafe."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": (
                            "```javascript\n"
                            "const name = new URLSearchParams(window.location.search).get('name');\n"
                            "document.getElementById('greeting').innerHTML = 'Hello, ' + name;\n"
                            "```"
                        )
                    }
                }
            ]
        }

        with patch("auditor.detectors.output_safety_detector.requests") as mock_requests:
            mock_requests.post.return_value = mock_response
            mock_requests.exceptions = __import__("requests").exceptions

            result = self.detector.detect("127.0.0.1", 19030, categories=["xss_output"])

        self.assertTrue(result.is_vulnerable)
        vulnerable = [f for f in result.findings if f.status == VulnerabilityStatus.VULNERABLE]
        self.assertTrue(len(vulnerable) > 0)

    def test_xss_safe_text_content(self):
        """Mock response with textContent -> not flagged."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": (
                            "```javascript\n"
                            "const name = new URLSearchParams(window.location.search).get('name');\n"
                            "document.getElementById('greeting').textContent = 'Hello, ' + name;\n"
                            "```"
                        )
                    }
                }
            ]
        }

        with patch("auditor.detectors.output_safety_detector.requests") as mock_requests:
            mock_requests.post.return_value = mock_response
            mock_requests.exceptions = __import__("requests").exceptions

            result = self.detector.detect("127.0.0.1", 19030, categories=["xss_output"])

        self.assertFalse(result.is_vulnerable)

    # =========================================================================
    # SQL injection detection
    # =========================================================================

    def test_sqli_fstring_detected(self):
        """Mock response with f-string SQL -> detected."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": (
                            "```python\n"
                            "def find_user(name):\n"
                            "    cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n"
                            "```"
                        )
                    }
                }
            ]
        }

        with patch("auditor.detectors.output_safety_detector.requests") as mock_requests:
            mock_requests.post.return_value = mock_response
            mock_requests.exceptions = __import__("requests").exceptions

            result = self.detector.detect("127.0.0.1", 19030, categories=["sqli_output"])

        self.assertTrue(result.is_vulnerable)

    def test_sqli_parameterized_safe(self):
        """Mock response with parameterized query -> not flagged."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": (
                            "```python\n"
                            "def find_user(name):\n"
                            '    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))\n'
                            "```"
                        )
                    }
                }
            ]
        }

        with patch("auditor.detectors.output_safety_detector.requests") as mock_requests:
            mock_requests.post.return_value = mock_response
            mock_requests.exceptions = __import__("requests").exceptions

            result = self.detector.detect("127.0.0.1", 19030, categories=["sqli_output"])

        self.assertFalse(result.is_vulnerable)

    # =========================================================================
    # Command injection detection
    # =========================================================================

    def test_cmdi_os_system_detected(self):
        """Mock response with os.system -> detected."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": (
                            "```python\n"
                            "def check_file(filename):\n"
                            "    os.system(f'file {filename}')\n"
                            "```"
                        )
                    }
                }
            ]
        }

        with patch("auditor.detectors.output_safety_detector.requests") as mock_requests:
            mock_requests.post.return_value = mock_response
            mock_requests.exceptions = __import__("requests").exceptions

            result = self.detector.detect("127.0.0.1", 19030, categories=["cmdi_output"])

        self.assertTrue(result.is_vulnerable)

    def test_cmdi_subprocess_list_safe(self):
        """Mock response with subprocess list form -> not flagged."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": (
                            "```python\n"
                            "import subprocess\n"
                            "def check_file(filename):\n"
                            "    result = subprocess.run(['file', filename], capture_output=True)\n"
                            "    return result.stdout.decode()\n"
                            "```"
                        )
                    }
                }
            ]
        }

        with patch("auditor.detectors.output_safety_detector.requests") as mock_requests:
            mock_requests.post.return_value = mock_response
            mock_requests.exceptions = __import__("requests").exceptions

            result = self.detector.detect("127.0.0.1", 19030, categories=["cmdi_output"])

        self.assertFalse(result.is_vulnerable)

    # =========================================================================
    # Mixed output (dangerous + safe patterns)
    # =========================================================================

    def test_mixed_output_not_vulnerable(self):
        """Response with both dangerous and safe patterns -> not vulnerable."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": (
                            "```python\n"
                            "# BAD: Don't do this\n"
                            "# query = f\"SELECT * FROM users WHERE name = '{name}'\"\n"
                            "# GOOD: Use parameterized queries\n"
                            'cursor.execute("SELECT * FROM users WHERE name = ?", (name,))\n'
                            "```"
                        )
                    }
                }
            ]
        }

        with patch("auditor.detectors.output_safety_detector.requests") as mock_requests:
            mock_requests.post.return_value = mock_response
            mock_requests.exceptions = __import__("requests").exceptions

            result = self.detector.detect("127.0.0.1", 19030, categories=["sqli_output"])

        self.assertFalse(result.is_vulnerable)

    # =========================================================================
    # Connection handling
    # =========================================================================

    def test_connection_error_handled(self):
        """Connection failures should produce errors."""
        with patch("auditor.detectors.output_safety_detector.requests") as mock_requests:
            mock_requests.post.side_effect = __import__("requests").exceptions.ConnectionError(
                "Connection refused"
            )
            mock_requests.exceptions = __import__("requests").exceptions

            result = self.detector.detect("127.0.0.1", 19999)

        self.assertFalse(result.is_vulnerable)
        self.assertTrue(len(result.errors) > 0)

    def test_auth_enforced_not_vulnerable(self):
        """401 response should mean safe (auth enforced)."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"

        with patch("auditor.detectors.output_safety_detector.requests") as mock_requests:
            mock_requests.post.return_value = mock_response
            mock_requests.exceptions = __import__("requests").exceptions

            result = self.detector.detect("127.0.0.1", 19030, categories=["xss_output"])

        self.assertFalse(result.is_vulnerable)

    # =========================================================================
    # Category filtering and metadata
    # =========================================================================

    def test_category_filtering(self):
        """Test that categories parameter filters correctly."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"choices": [{"message": {"content": "Safe code."}}]}

        with patch("auditor.detectors.output_safety_detector.requests") as mock_requests:
            mock_requests.post.return_value = mock_response
            mock_requests.exceptions = __import__("requests").exceptions

            result = self.detector.detect("127.0.0.1", 19030, categories=["ssrf_output"])

        ssrf_count = len([t for t in self.detector.test_cases if t.category == "ssrf_output"])
        self.assertEqual(result.metadata["total_tested"], ssrf_count)

    def test_metadata_populated(self):
        """Test metadata is populated after detection."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"choices": [{"message": {"content": "Clean code."}}]}

        with patch("auditor.detectors.output_safety_detector.requests") as mock_requests:
            mock_requests.post.return_value = mock_response
            mock_requests.exceptions = __import__("requests").exceptions

            result = self.detector.detect("127.0.0.1", 19030, categories=["xss_output"])

        self.assertIn("total_tested", result.metadata)
        self.assertIn("unsafe_count", result.metadata)
        self.assertIn("safe_count", result.metadata)

    def test_result_serialization(self):
        """Test DetectorResult serialization."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"choices": [{"message": {"content": "Safe."}}]}

        with patch("auditor.detectors.output_safety_detector.requests") as mock_requests:
            mock_requests.post.return_value = mock_response
            mock_requests.exceptions = __import__("requests").exceptions

            result = self.detector.detect("127.0.0.1", 19030, categories=["xss_output"])

        result_dict = result.to_dict()
        self.assertIn("detector", result_dict)
        self.assertEqual(result_dict["detector"], "output_safety")
        self.assertIn("findings", result_dict)


if __name__ == "__main__":
    unittest.main()
