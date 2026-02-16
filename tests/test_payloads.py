"""Tests for payload library.

These tests verify payload structure and integrity.
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from auditor.payloads.injection_payloads import (
    ALL_PAYLOADS,
    INSTRUCTION_OVERRIDE_PAYLOADS,
    ROLE_HIJACK_PAYLOADS,
    CONTEXT_MANIPULATION_PAYLOADS,
    ENCODED_INJECTION_PAYLOADS,
    JAILBREAK_PAYLOADS,
    Payload,
    get_payload_categories,
    get_payloads_by_category,
    get_payloads_by_severity,
    get_payload_by_id,
)


class TestPayloadLibrary(unittest.TestCase):
    """Tests for injection payload library."""

    def test_payload_categories_exist(self):
        """Test that all expected categories exist."""
        categories = get_payload_categories()

        expected = [
            "instruction_override",
            "role_hijacking",
            "context_manipulation",
            "encoded_injection",
            "jailbreak",
        ]
        for cat in expected:
            self.assertIn(cat, categories)

    def test_payloads_have_required_fields(self):
        """Test that all payloads have required fields."""
        for payload in ALL_PAYLOADS:
            self.assertIsInstance(payload, Payload)
            self.assertTrue(len(payload.id) > 0)
            self.assertTrue(len(payload.name) > 0)
            self.assertTrue(len(payload.template) > 0)
            self.assertTrue(len(payload.description) > 0)
            self.assertTrue(len(payload.reference) > 0)

    def test_payloads_have_content(self):
        """Test that each category list is non-empty."""
        self.assertTrue(len(INSTRUCTION_OVERRIDE_PAYLOADS) > 0)
        self.assertTrue(len(ROLE_HIJACK_PAYLOADS) > 0)
        self.assertTrue(len(CONTEXT_MANIPULATION_PAYLOADS) > 0)
        self.assertTrue(len(ENCODED_INJECTION_PAYLOADS) > 0)
        self.assertTrue(len(JAILBREAK_PAYLOADS) > 0)

    def test_get_payloads_by_category(self):
        """Test filtering payloads by category."""
        direct = get_payloads_by_category("instruction_override")
        self.assertTrue(len(direct) > 0)

        for p in direct:
            self.assertEqual(p.category, "instruction_override")

    def test_get_payloads_by_severity(self):
        """Test filtering payloads by severity."""
        high = get_payloads_by_severity("high")
        self.assertTrue(len(high) > 0)

        for p in high:
            self.assertEqual(p.severity, "high")

    def test_get_payload_by_id(self):
        """Test getting a specific payload by ID."""
        payload = get_payload_by_id("io_001")
        self.assertEqual(payload.id, "io_001")
        self.assertEqual(payload.category, "instruction_override")

    def test_get_payload_by_id_not_found(self):
        """Test that missing payload raises ValueError."""
        with self.assertRaises(ValueError):
            get_payload_by_id("nonexistent_id")

    def test_get_all_payloads(self):
        """Test getting all payloads."""
        total_expected = (
            len(INSTRUCTION_OVERRIDE_PAYLOADS) +
            len(ROLE_HIJACK_PAYLOADS) +
            len(CONTEXT_MANIPULATION_PAYLOADS) +
            len(ENCODED_INJECTION_PAYLOADS) +
            len(JAILBREAK_PAYLOADS)
        )
        self.assertEqual(len(ALL_PAYLOADS), total_expected)

    def test_payloads_have_valid_references(self):
        """Test that payload references are non-empty strings."""
        for payload in ALL_PAYLOADS:
            self.assertTrue(
                len(payload.reference) > 0,
                f"Payload '{payload.name}' has empty reference"
            )

    def test_no_duplicate_payload_ids(self):
        """Test that payload IDs are globally unique."""
        ids = [p.id for p in ALL_PAYLOADS]
        self.assertEqual(len(ids), len(set(ids)), "Duplicate payload IDs found")


class TestPayloadSafety(unittest.TestCase):
    """Tests to verify payloads are safe for detection purposes."""

    def test_no_destructive_commands(self):
        """Test that payloads don't contain destructive shell commands."""
        destructive_patterns = [
            "rm -rf",
            "dd if=",
            ":(){:|:&};:",
            "mkfs",
            "> /dev/sda",
        ]

        for payload in ALL_PAYLOADS:
            payload_text = payload.template.lower()
            for pattern in destructive_patterns:
                self.assertNotIn(
                    pattern.lower(), payload_text,
                    f"Destructive pattern '{pattern}' found in {payload.name}"
                )


if __name__ == '__main__':
    unittest.main()
