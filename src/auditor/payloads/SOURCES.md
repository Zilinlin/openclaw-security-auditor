# Payload Sources

This document lists the sources for all prompt injection payloads used in this toolkit.

## Source Attribution

All payloads in this library are derived from public security research and are used for **defensive testing purposes only**.

### Primary Sources

| Source | Type | URL |
|--------|------|-----|
| OWASP LLM Top 10 | Security Standard | https://owasp.org/www-project-top-10-for-large-language-model-applications/ |
| Snyk ToxicSkills | Research Paper | https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/ |
| Penligent Labs | Research Paper | https://www.penligent.ai/hackinglabs/the-openclaw-prompt-injection-problem-persistence-tool-hijack-and-the-security-boundary-that-doesnt-exist/ |

### Payload Categories

#### Instruction Override (io_*)
- **Source**: OWASP LLM01:2025 Prompt Injection
- **Description**: Techniques that attempt to override the agent's original instructions
- **Reference**: https://genai.owasp.org/llmrisk/llm01-prompt-injection/

#### Role Hijacking (rh_*)
- **Source**: Snyk ToxicSkills Research
- **Description**: Techniques that attempt to change the agent's role or persona
- **Reference**: https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/

#### Context Manipulation (cm_*)
- **Source**: Penligent Prompt Injection Research
- **Description**: Techniques that exploit context boundaries and delimiters
- **Reference**: https://www.penligent.ai/hackinglabs/the-openclaw-prompt-injection-problem-persistence-tool-hijack-and-the-security-boundary-that-doesnt-exist/

#### Encoded Injection (ei_*)
- **Source**: Snyk ToxicSkills - Obfuscation Techniques
- **Description**: Techniques that hide malicious instructions through encoding
- **Reference**: https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/

#### Jailbreak (jb_*)
- **Source**: OWASP LLM01:2025, Community Research
- **Description**: Techniques that attempt to bypass safety restrictions
- **Reference**: https://owasp.org/www-project-top-10-for-large-language-model-applications/

## Safety Design

All payloads are designed with safety in mind:

1. **Canary-Based Detection**: Each payload requests output of a unique canary string, not harmful actions
2. **No Exploitation**: Payloads detect vulnerability, they don't exploit it
3. **No Data Exfiltration**: No payload attempts to steal real data
4. **No System Modification**: No payload attempts to modify files or settings
5. **No External Communication**: No payload attempts to contact external servers

## Usage Guidelines

1. Only use these payloads on systems you have authorization to test
2. Replace `{canary}` with a unique identifier before sending
3. Check if canary appears in response to detect vulnerability
4. Report findings to system owners for remediation

## Contributing New Payloads

When adding new payloads:

1. Source must be public security research
2. Payload must be detection-only (canary-based)
3. Include reference to source
4. Assign appropriate severity level
5. Document in this file

## Disclaimer

These payloads are provided for **authorized security testing only**. Unauthorized use against systems you do not own or have permission to test may violate laws and regulations.
