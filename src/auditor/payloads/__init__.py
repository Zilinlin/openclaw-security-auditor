"""Prompt injection payload library.

All payloads in this module are:
1. Sourced from public security research
2. Designed for detection only (not exploitation)
3. Safe to use in authorized testing

References:
- Snyk ToxicSkills: https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/
- OWASP LLM Top 10: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- Penligent Research: https://www.penligent.ai/hackinglabs/the-openclaw-prompt-injection-problem-persistence-tool-hijack-and-the-security-boundary-that-doesnt-exist/
"""

from .injection_payloads import (
    INSTRUCTION_OVERRIDE_PAYLOADS,
    ROLE_HIJACK_PAYLOADS,
    CONTEXT_MANIPULATION_PAYLOADS,
    ENCODED_INJECTION_PAYLOADS,
    JAILBREAK_PAYLOADS,
    ALL_PAYLOADS,
    get_payloads_by_category,
    get_payload_categories,
)

__all__ = [
    "INSTRUCTION_OVERRIDE_PAYLOADS",
    "ROLE_HIJACK_PAYLOADS",
    "CONTEXT_MANIPULATION_PAYLOADS",
    "ENCODED_INJECTION_PAYLOADS",
    "JAILBREAK_PAYLOADS",
    "ALL_PAYLOADS",
    "get_payloads_by_category",
    "get_payload_categories",
]
