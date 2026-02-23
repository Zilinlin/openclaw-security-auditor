<p align="center">
  <img src="docs/assets/banner-v2.png" alt="OpenClaw Security Auditor" width="100%">
</p>

<h3 align="center">Security auditing toolkit for OpenClaw deployments</h3>

<p align="center">
  Detect misconfigurations, known CVEs, exposed secrets, privilege escalation, supply chain risks, and runtime threats — before attackers do.
</p>

<p align="center">
  <a href="https://github.com/Zilinlin/openclaw-security-auditor/actions/workflows/ci.yml"><img src="https://github.com/Zilinlin/openclaw-security-auditor/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.9%20|%203.10%20|%203.11%20|%203.12-blue" alt="Python"></a>
  <img src="https://img.shields.io/badge/CVEs%20Detected-5-critical" alt="CVEs Detected">
  <img src="https://img.shields.io/badge/Scanners-6%20Static%20|%206%20Dynamic-green" alt="Scanners">
</p>

---

## Why This Exists

Recent security research has exposed critical risks in OpenClaw deployments at scale:

- **135,000+** instances exposed to the public internet [[1]](#references)
- **63%** of deployments vulnerable to known exploits [[1]](#references)
- **12,812** instances exploitable via Remote Code Execution [[2]](#references)
- **93.4%** vulnerable to authentication bypass attacks [[3]](#references)

This tool provides a comprehensive security audit pipeline — from static config analysis to live vulnerability detection to runtime monitoring.

## What It Does

### Discover — Static Analysis

- **Config Scanner** — Detects missing auth, exposed prompts, plaintext tokens, default ports in OpenClaw YAML configs
- **CVE Scanner** — Checks your OpenClaw version against 5 known CVEs with severity scoring
- **Secret Scanner** — Finds exposed API keys, Slack tokens (`xapp-*`, `xoxb-*`, `xoxp-*`), AWS keys, private keys
- **Network Scanner** — Detects public-facing exposure (`0.0.0.0` binds, open ports, missing TLS)
- **Privilege Scanner** — Analyzes agent configs for excessive permissions, missing approval gates, unrestricted tools, disabled sandboxes ([OWASP ASI02/ASI06](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/))
- **SBOM Scanner** — Supply chain analysis for MCP servers, skills/plugins, and model configs — detects unpinned versions, unverified sources, missing integrity checks ([OWASP ASI03](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/))

### Detect — Dynamic Probing

- **WebSocket Origin Bypass** — Tests for Cross-Site WebSocket Hijacking ([CVE-2026-25253](https://nvd.nist.gov/vuln/detail/CVE-2026-25253))
- **Auth Weakness Probe** — Tests authentication enforcement, default credentials, token scope
- **API Hook Bypass** — Verifies security hooks are active on HTTP endpoints
- **Prompt Injection Probe** — Tests agent resilience with 15+ categorized direct injection payloads
- **Indirect Injection Probe** — Tests agent resilience against injections hidden in data sources: documents, tool outputs, RAG context, invisible instructions ([OWASP ASI01/LLM01](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), [CVE-2026-24763](https://nvd.nist.gov/vuln/detail/CVE-2026-24763))
- **Output Safety Probe** — Checks if LLM outputs contain unsafe code patterns (XSS, SQLi, command injection, SSRF, path traversal) that could harm downstream systems ([OWASP LLM05](https://owasp.org/www-project-top-10-for-large-language-model-applications/))

### Defend — Runtime Monitoring

- **File Integrity Monitor** — SHA256 verification of critical files (SOUL.md, IDENTITY.md)
- **Canary Token Injection** — Plants fake secrets to detect data exfiltration
- **Anomaly Detection** — Monitors egress, rate limits, and suspicious patterns
- **CVE Feed Integration** — Real-time notifications when new vulnerabilities are disclosed

## Quick Start

### Installation

```bash
pip install openclaw-security-auditor
```

Or from source:

```bash
git clone https://github.com/Zilinlin/openclaw-security-auditor.git
cd openclaw-security-auditor
pip install -e .
```

### Run Your First Scan

```bash
# Full security audit
openclaw-audit scan /path/to/openclaw

# Check a specific version for known CVEs
openclaw-audit cve --version 2026.1.0

# Scan configs for misconfigurations
openclaw-audit config /path/to/openclaw

# Hunt for exposed secrets
openclaw-audit secrets /path/to/project

# Test network exposure
openclaw-audit network --host localhost --port 18789

# Analyze agent privilege boundaries
openclaw-audit privilege /path/to/project

# Generate supply chain SBOM
openclaw-audit sbom /path/to/project

# Test for indirect prompt injection
openclaw-audit detect-indirect-injection --host localhost --port 19020

# Test output safety
openclaw-audit detect-output-safety --host localhost --port 19030
```

### Example Output

<details>
<summary><b>CVE Scan — Vulnerable Version Detected</b></summary>

```
$ openclaw-audit cve --version 2026.1.0

╔═══════════════════════════════════════════════════════════╗
║        OpenClaw Security Auditor v0.1.1                   ║
╚═══════════════════════════════════════════════════════════╝

1. [CRITICAL] Remote Code Execution via Malicious Skill
   CVE: CVE-2026-25253
   A vulnerability in the Skills marketplace allows attackers to execute
   arbitrary code on the host system through specially crafted skill packages.
   Remediation: Upgrade to OpenClaw 2026.2.12 or later.

2. [HIGH] Authentication Bypass in Gateway API
   CVE: CVE-2026-25157
   The Gateway component fails to properly validate authentication tokens,
   allowing unauthenticated access to protected API endpoints.
   Remediation: Upgrade to OpenClaw 2026.2.10 or later.

3. [HIGH] Privilege Escalation via Prompt Injection
   CVE: CVE-2026-24763
   Attackers can inject malicious instructions through external content
   that the agent processes, leading to unauthorized actions.
   Remediation: Upgrade to OpenClaw 2026.2.12 or later.

4. [MEDIUM] SSRF via URL Input Processing
   CVE: CVE-2026-23891

5. [MEDIUM] Information Disclosure in Error Messages
   CVE: CVE-2026-22456

============================================================
SCAN SUMMARY: 5 findings (1 Critical, 2 High, 2 Medium)
============================================================
```

</details>

<details>
<summary><b>Config Scan — Insecure OpenClaw Config</b></summary>

```
$ openclaw-audit config /path/to/openclaw

╔═══════════════════════════════════════════════════════════╗
║        OpenClaw Security Auditor v0.1.1                   ║
╚═══════════════════════════════════════════════════════════╝

1. [CRITICAL] No authentication configured
   CVE: CVE-2026-25157
   The OpenClaw configuration has no 'auth' or 'security' section.
   Remediation: Add an auth section with API key or JWT authentication.

2. [HIGH] Slack tokens stored in plaintext config
   Slack appToken and/or botToken are stored directly in the config file.
   Remediation: Move tokens to environment variables or a secrets manager.

3. [HIGH] No WebSocket origin validation configured
   CVE: CVE-2026-25253
   No 'cors' or 'allowedOrigins' is configured for the gateway.
   Remediation: Configure allowedOrigins to restrict WebSocket connections.

4. [MEDIUM] System prompt exposed in config file
   The agent system prompt is stored directly in the config file.
   Remediation: Store the system prompt in a separate file (e.g., SOUL.md).

5. [LOW] Default gateway port in use

============================================================
SCAN SUMMARY: 5 findings (1 Critical, 2 High, 1 Medium, 1 Low)
============================================================
```

</details>

<details>
<summary><b>JSON Output — CI/CD Integration</b></summary>

```bash
$ openclaw-audit --json cve --version 2026.1.0
```

```json
{
  "scanner": "cve",
  "findings": [
    {
      "title": "Remote Code Execution via Malicious Skill",
      "severity": "critical",
      "cve": "CVE-2026-25253",
      "remediation": "Upgrade to OpenClaw 2026.2.12 or later."
    }
  ],
  "summary": {
    "total": 5,
    "critical": 1,
    "high": 2,
    "medium": 2
  }
}
```

</details>

## CI/CD Integration

Use the `--fail-on` flag to fail builds when vulnerabilities meet a severity threshold:

```bash
# Fail only on critical findings
openclaw-audit --fail-on critical cve --version $(openclaw --version)

# Fail on high and above
openclaw-audit --fail-on high config /path/to/openclaw

# Fail on any finding (strictest)
openclaw-audit --fail-on info secrets /path/to/project
```

Exit codes: `0` = pass, `1` = findings at or above threshold, `2` = error.

### SARIF Output (GitHub Code Scanning)

Generate [SARIF](https://sarifweb.azurewebsites.net/) reports for integration with GitHub Code Scanning:

```bash
# Write SARIF report to file
openclaw-audit --sarif report.sarif cve --version 2026.1.0

# Combine with other flags
openclaw-audit --sarif report.sarif --fail-on high scan /path/to/openclaw
```

Upload to GitHub Code Scanning in your CI workflow:

```yaml
- name: Run security audit
  run: openclaw-audit --sarif results.sarif scan .

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### GitHub Action

Add security scanning to your CI pipeline with one step:

```yaml
# .github/workflows/security.yml
name: Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Zilinlin/openclaw-security-auditor@main
        with:
          target: "."
          version: "2026.2.5"
          fail-on: "high"
```

### Docker

Run scans without installing Python:

```bash
# Build the image
docker build -t openclaw-audit .

# Scan a local directory
docker run --rm -v $(pwd):/target openclaw-audit scan /target

# Check a specific version for CVEs
docker run --rm openclaw-audit cve --version 2026.1.0
```

### Pre-commit Hook

Add automatic secret scanning to your git workflow:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Zilinlin/openclaw-security-auditor
    rev: v0.1.1
    hooks:
      - id: openclaw-audit-secrets
```

## Known Vulnerabilities Detected

| CVE | CVSS | Description | Fixed In |
|-----|------|-------------|----------|
| [CVE-2026-25253](https://nvd.nist.gov/vuln/detail/CVE-2026-25253) | 8.8 Critical | 1-Click RCE via WebSocket Hijack | v2026.1.29 |
| [CVE-2026-25157](https://nvd.nist.gov/vuln/detail/CVE-2026-25157) | High | Authentication Bypass in Gateway API | v2026.2.10 |
| [CVE-2026-24763](https://nvd.nist.gov/vuln/detail/CVE-2026-24763) | High | Privilege Escalation via Prompt Injection | v2026.2.12 |
| [CVE-2026-23891](https://nvd.nist.gov/vuln/detail/CVE-2026-23891) | Medium | SSRF via URL Input Processing | v2026.2.8 |
| [CVE-2026-22456](https://nvd.nist.gov/vuln/detail/CVE-2026-22456) | Medium | Information Disclosure in Error Messages | v2026.2.6 |

## Project Structure

```
openclaw-security-auditor/
├── src/auditor/
│   ├── scanners/           # Static analysis (config, CVE, secrets, network, privilege, SBOM)
│   ├── detectors/          # Dynamic probing (WebSocket, auth, API, injection, output safety)
│   └── payloads/           # Categorized prompt injection payloads
├── skill/                  # OpenClaw runtime monitoring skill
│   └── monitor/            # Integrity, canary, anomaly, CVE feed modules
├── pocs/                   # PoCs for disclosed CVEs (patched only)
├── tests/                  # 315 tests, 73% coverage
└── docs/                   # Security research & disclosure policy
```

## Documentation

- [Security Research & References](docs/SECURITY_RESEARCH.md) — Detailed vulnerability analysis
- [Detection Techniques](docs/DETECTION_TECHNIQUES.md) — How each detector works
- [Disclosure Policy](docs/DISCLOSURE_POLICY.md) — Responsible disclosure guidelines
- [Changelog](CHANGELOG.md) — Version history
- [Security Policy](SECURITY.md) — Report vulnerabilities in this tool

## Contributing

Contributions are welcome! To add a new scanner:

1. Create a scanner in `src/auditor/scanners/` implementing `BaseScanner`
2. Register it in `src/auditor/scanners/__init__.py`
3. Add tests in `tests/`
4. Document the detection technique with references

## References

| # | Source | URL |
|---|--------|-----|
| 1 | SecurityScorecard — Exposed OpenClaw Instances | https://www.infosecurity-magazine.com/news/researchers-40000-exposed-openclaw/ |
| 2 | The Register — OpenClaw Security Analysis | https://www.theregister.com/2026/02/09/openclaw_instances_exposed_vibe_code |
| 3 | SecurityWeek — OpenClaw Hijack Vulnerability | https://www.securityweek.com/vulnerability-allows-hackers-to-hijack-openclaw-ai-assistant/ |
| 4 | OpenClaw Official Security Docs | https://docs.openclaw.ai/gateway/security |
| 5 | CyberSecurityNews — OpenClaw 2026.2.12 Release | https://cybersecuritynews.com/openclaw-2026-2-12-released/ |
| 6 | Snyk — ToxicSkills Research | https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/ |
| 7 | DepthFirst — CVE-2026-25253 Analysis | https://depthfirst.com/post/1-click-rce-to-steal-your-moltbot-data-and-keys |
| 8 | Penligent — Prompt Injection Problem | https://www.penligent.ai/hackinglabs/the-openclaw-prompt-injection-problem-persistence-tool-hijack-and-the-security-boundary-that-doesnt-exist/ |
| 9 | GitHub — API Security Hooks RFC | https://github.com/openclaw/openclaw/discussions/6098 |
| 10 | GitHub — ClawSec Security Suite | https://github.com/prompt-security/clawsec |
| 11 | GitHub — Runtime Prompt Injection Defenses | https://github.com/openclaw/openclaw/issues/4840 |
| 12 | GBHackers — OpenClaw Security Update | https://gbhackers.com/openclaw-2026-2-12-released/ |
| 13 | OWASP — Top 10 for Agentic Applications (2026) | https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ |
| 14 | OWASP — Top 10 for LLM Applications | https://owasp.org/www-project-top-10-for-large-language-model-applications/ |
| 15 | CrowdStrike — Indirect Prompt Injection Research | https://www.crowdstrike.com/blog/indirect-prompt-injection-attacks/ |

## Acknowledgments

Built on security research from [DepthFirst](https://depthfirst.com), [Snyk](https://snyk.io), [SecurityScorecard STRIKE Team](https://securityscorecard.com), [Prompt Security](https://prompt.security), and [Penligent Labs](https://penligent.ai).

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <b>This tool is for authorized security testing only.</b><br>
  Always obtain proper authorization before scanning systems you do not own.<br>
  See <a href="docs/DISCLOSURE_POLICY.md">Disclosure Policy</a> for responsible disclosure guidelines.
</p>
