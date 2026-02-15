# OpenClaw Security Auditor

A comprehensive security auditing toolkit for [OpenClaw](https://github.com/openclaw/openclaw) deployments. Perform static analysis, dynamic vulnerability detection, and runtime monitoring.

## Background

Recent security research has revealed critical vulnerabilities in OpenClaw deployments:

- **135,000+** instances exposed to the public internet [[1]](#references)
- **63%** of deployments vulnerable to known exploits [[1]](#references)
- **12,812** instances exploitable via Remote Code Execution [[2]](#references)
- **93.4%** vulnerable to authentication bypass attacks [[3]](#references)

This tool helps security teams and developers audit their OpenClaw deployments before attackers do.

## Features

### Static Analysis (Implemented)

| Scanner | Description | Reference |
|---------|-------------|-----------|
| **Config Scanner** | Detect insecure defaults (e.g., `bind: 0.0.0.0`) | [[4]](#references) |
| **CVE Detector** | Check for known vulnerabilities | [[5]](#references) |
| **Secret Scanner** | Find exposed API keys and credentials | [[6]](#references) |
| **Network Scanner** | Detect public network exposure | [[1]](#references) |

### Dynamic Detection (Coming Soon)

| Detector | Description | Reference |
|----------|-------------|-----------|
| **WebSocket Origin Bypass** | Test for CSWSH vulnerability (CVE-2026-25253) | [[7]](#references) |
| **Prompt Injection Probe** | Test agent resilience against injection | [[8]](#references) |
| **API Hook Bypass Check** | Verify security hooks on HTTP endpoints | [[9]](#references) |
| **Auth Weakness Probe** | Test authentication enforcement | [[3]](#references) |

### Runtime Monitor Skill (Coming Soon)

| Feature | Description | Reference |
|---------|-------------|-----------|
| **File Integrity Monitor** | SHA256 verification of SOUL.md, IDENTITY.md | [[10]](#references) |
| **Canary Token Injection** | Detect data exfiltration via fake secrets | [[11]](#references) |
| **Anomaly Detection** | Monitor for suspicious behavior patterns | [[8]](#references) |
| **CVE Feed Integration** | Real-time vulnerability notifications | [[10]](#references) |

## Known Vulnerabilities Detected

| CVE | Severity | Description | Fixed Version | Reference |
|-----|----------|-------------|---------------|-----------|
| CVE-2026-25253 | Critical (8.8) | 1-Click RCE via WebSocket Hijack | v2026.1.29 | [[7]](#references) |
| CVE-2026-25157 | High | Authentication Bypass in Gateway API | v2026.2.10 | [[2]](#references) |
| CVE-2026-24763 | High | Privilege Escalation via Prompt Injection | v2026.2.12 | [[12]](#references) |
| CVE-2026-23891 | Medium | SSRF via URL Input Processing | v2026.2.8 | [[5]](#references) |
| CVE-2026-22456 | Medium | Information Disclosure in Error Messages | v2026.2.6 | [[5]](#references) |

## Installation

```bash
pip install openclaw-security-auditor
```

Or install from source:

```bash
git clone https://github.com/Zilinlin/openclaw-security-auditor.git
cd openclaw-security-auditor
pip install -e .
```

## Quick Start

```bash
# Full security scan
openclaw-audit scan /path/to/openclaw

# Scan with specific checks
openclaw-audit scan /path/to/openclaw --checks config,cve,secrets

# CVE vulnerability check for specific version
openclaw-audit cve --version 2026.2.6

# Check network exposure
openclaw-audit network --host localhost --port 18789

# Output as JSON
openclaw-audit scan /path/to/openclaw --json
```

## Usage

### Full Audit

```bash
openclaw-audit scan /path/to/openclaw --all
```

### Individual Scanners

```bash
# Configuration audit
openclaw-audit config /path/to/openclaw

# CVE vulnerability check
openclaw-audit cve --version 2026.2.6

# Secret scanning
openclaw-audit secrets /path/to/openclaw

# Network exposure test
openclaw-audit network --host your-server.com --port 18789
```

### Output Formats

```bash
# Human-readable (default)
openclaw-audit scan /path/to/openclaw

# JSON output for CI/CD integration
openclaw-audit scan /path/to/openclaw --json

# Save report to file
openclaw-audit scan /path/to/openclaw --output report.json
```

## Configuration

Create `.openclaw-audit.yaml` in your project root:

```yaml
# Scanners to enable
scanners:
  - config
  - cve
  - secrets
  - network

# Paths to ignore
ignore:
  - node_modules/
  - .git/
  - "*.log"

# Secret patterns to detect
secret_patterns:
  - "OPENAI_API_KEY"
  - "ANTHROPIC_API_KEY"
  - "sk-[a-zA-Z0-9]{48}"
```

## Documentation

- [Security Research & References](docs/SECURITY_RESEARCH.md) - Detailed vulnerability analysis
- [Detection Techniques](docs/DETECTION_TECHNIQUES.md) - How each detector works
- [Disclosure Policy](docs/DISCLOSURE_POLICY.md) - Responsible disclosure guidelines
- [Contributing](CONTRIBUTING.md) - How to contribute

## Project Structure

```
openclaw-security-auditor/
├── src/auditor/
│   ├── scanners/           # Static analysis scanners
│   ├── detectors/          # Dynamic vulnerability detectors
│   └── payloads/           # Public payload references
├── skill/                  # OpenClaw runtime monitor skill
├── pocs/                   # PoC for disclosed CVEs
└── docs/                   # Documentation
```

## References

| # | Source | URL |
|---|--------|-----|
| 1 | SecurityScorecard - Exposed OpenClaw Instances | https://www.infosecurity-magazine.com/news/researchers-40000-exposed-openclaw/ |
| 2 | The Register - OpenClaw Security Analysis | https://www.theregister.com/2026/02/09/openclaw_instances_exposed_vibe_code |
| 3 | SecurityWeek - OpenClaw Hijack Vulnerability | https://www.securityweek.com/vulnerability-allows-hackers-to-hijack-openclaw-ai-assistant/ |
| 4 | OpenClaw Official Security Docs | https://docs.openclaw.ai/gateway/security |
| 5 | CyberSecurityNews - OpenClaw 2026.2.12 Release | https://cybersecuritynews.com/openclaw-2026-2-12-released/ |
| 6 | Snyk - ToxicSkills Research | https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/ |
| 7 | DepthFirst - CVE-2026-25253 Analysis | https://depthfirst.com/post/1-click-rce-to-steal-your-moltbot-data-and-keys |
| 8 | Penligent - Prompt Injection Problem | https://www.penligent.ai/hackinglabs/the-openclaw-prompt-injection-problem-persistence-tool-hijack-and-the-security-boundary-that-doesnt-exist/ |
| 9 | GitHub - API Security Hooks RFC | https://github.com/openclaw/openclaw/discussions/6098 |
| 10 | GitHub - ClawSec Security Suite | https://github.com/prompt-security/clawsec |
| 11 | GitHub - Runtime Prompt Injection Defenses | https://github.com/openclaw/openclaw/issues/4840 |
| 12 | GBHackers - OpenClaw Security Update | https://gbhackers.com/openclaw-2026-2-12-released/ |

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Adding New Scanners

1. Create a new scanner in `src/auditor/scanners/`
2. Implement the `BaseScanner` interface
3. Register in `src/auditor/scanners/__init__.py`
4. Add tests in `tests/`
5. Document the detection technique with references

## License

MIT License - see [LICENSE](LICENSE) for details.

## Disclaimer

This tool is for **authorized security testing only**. Always obtain proper authorization before scanning systems you do not own. See [DISCLOSURE_POLICY.md](docs/DISCLOSURE_POLICY.md) for responsible disclosure guidelines.

## Acknowledgments

This project builds upon security research from:
- [DepthFirst Security](https://depthfirst.com)
- [Snyk Security Research](https://snyk.io)
- [SecurityScorecard STRIKE Team](https://securityscorecard.com)
- [Prompt Security](https://prompt.security)
- [Penligent Labs](https://penligent.ai)
