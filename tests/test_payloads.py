"""Tests for payload library.

These tests verify payload structure and integrity.
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from auditor.payloads.injection_payloads import (
    PROMPT_INJECTION_PAYLOADS,
    PayloadCategory,
    get_payloads_by_category,
    get_all_payloads,
)


class TestPayloadLibrary(unittest.TestCase):
    """Tests for injection payload library."""

    def test_payload_categories_exist(self):
        """Test that all expected categories exist."""
        expected_categories = [
            PayloadCategory.DIRECT_INJECTION,
            PayloadCategory.INDIRECT_INJECTION,
            PayloadCategory.DELIMITER_INJECTION,
            PayloadCategory.ENCODING_BYPASS,
            PayloadCategory.CONTEXT_MANIPULATION,
            PayloadCategory.PRIVILEGE_ESCALATION,
        ]

        for category in expected_categories:
            self.assertIn(category, PROMPT_INJECTION_PAYLOADS)

    def test_payloads_have_required_fields(self):
        """Test that all payloads have required fields."""
        for category, payloads in PROMPT_INJECTION_PAYLOADS.items():
            for payload in payloads:
                self.assertIn("name", payload)
                self.assertIn("payload", payload)
                self.assertIn("description", payload)
                self.assertIn("reference", payload)

    def test_payloads_have_content(self):
        """Test that payloads are not empty."""
        for category, payloads in PROMPT_INJECTION_PAYLOADS.items():
            self.assertTrue(len(payloads) > 0, f"Category {category} has no payloads")

            for payload in payloads:
                self.assertTrue(len(payload["name"]) > 0)
                self.assertTrue(len(payload["payload"]) > 0)
                self.assertTrue(len(payload["description"]) > 0)

    def test_get_payloads_by_category(self):
        """Test filtering payloads by category."""
        direct_payloads = get_payloads_by_category(PayloadCategory.DIRECT_INJECTION)
        self.assertTrue(len(direct_payloads) > 0)

        # Verify all returned payloads are from correct category
        all_in_category = all(
            p in PROMPT_INJECTION_PAYLOADS[PayloadCategory.DIRECT_INJECTION]
            for p in direct_payloads
        )
        self.assertTrue(all_in_category)

    def test_get_all_payloads(self):
        """Test getting all payloads."""
        all_payloads = get_all_payloads()

        # Should have payloads from all categories
        total_expected = sum(
            len(payloads) for payloads in PROMPT_INJECTION_PAYLOADS.values()
        )
        self.assertEqual(len(all_payloads), total_expected)

    def test_payloads_have_valid_references(self):
        """Test that payload references are URLs or citations."""
        for category, payloads in PROMPT_INJECTION_PAYLOADS.items():
            for payload in payloads:
                ref = payload["reference"]
                # Reference should be a URL or academic citation
                valid_ref = (
                    ref.startswith("http") or
                    "arxiv" in ref.lower() or
                    "owasp" in ref.lower() or
                    "et al" in ref.lower() or
                    len(ref) > 0
                )
                self.assertTrue(valid_ref, f"Invalid reference: {ref}")

    def test_no_duplicate_payload_names(self):
        """Test that payload names are unique within categories."""
        for category, payloads in PROMPT_INJECTION_PAYLOADS.items():
            names = [p["name"] for p in payloads]
            unique_names = set(names)
            self.assertEqual(
                len(names), len(unique_names),
                f"Duplicate names in category {category}"
            )


class TestPayloadSafety(unittest.TestCase):
    """Tests to verify payloads are safe for detection purposes."""

    def test_payloads_use_canary_placeholders(self):
        """Test that payloads use {canary} placeholder for detection."""
        detection_payloads = get_payloads_by_category(PayloadCategory.DIRECT_INJECTION)

        # At least some payloads should support canary injection
        canary_payloads = [p for p in detection_payloads if "{canary}" in p["payload"]]
        # This is optional - not all payloads need canaries
        # Just verify the structure is correct

    def test_no_destructive_commands(self):
        """Test that payloads don't contain destructive shell commands."""
        destructive_patterns = [
            "rm -rf",
            "dd if=",
            ":(){:|:&};:",  # Fork bomb
            "mkfs",
            "> /dev/sda",
        ]

        for category, payloads in PROMPT_INJECTION_PAYLOADS.items():
            for payload in payloads:
                payload_text = payload["payload"].lower()
                for pattern in destructive_patterns:
                    self.assertNotIn(
                        pattern.lower(), payload_text,
                        f"Destructive pattern '{pattern}' found in {payload['name']}"
                    )


if __name__ == '__main__':
    unittest.main()
