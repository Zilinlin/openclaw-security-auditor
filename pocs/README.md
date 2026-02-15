# Proof of Concept Collection

This directory contains proof-of-concept code for **disclosed and patched** OpenClaw vulnerabilities. These PoCs are provided for **educational and authorized security testing purposes only**.

## Disclaimer

**IMPORTANT**: These PoCs are for:
- Educational purposes
- Authorized security testing
- Verifying that patches are properly applied
- Security research in controlled environments

**DO NOT** use these against systems you do not own or have explicit authorization to test.

## Available PoCs

| CVE | Vulnerability | Severity | Fixed Version | PoC |
|-----|--------------|----------|---------------|-----|
| CVE-2026-25253 | WebSocket Origin Bypass / 1-Click RCE | Critical (8.8) | v2026.1.29 | [websocket_hijack.py](CVE-2026-25253/detector.py) |
| CVE-2026-25157 | Authentication Bypass | High | v2026.2.10 | [auth_bypass.py](CVE-2026-25157/detector.py) |
| CVE-2026-24763 | Privilege Escalation via Prompt Injection | High | v2026.2.12 | [prompt_injection.py](CVE-2026-24763/detector.py) |

## Responsible Disclosure

All vulnerabilities in this collection have been:

1. **Reported** to the OpenClaw security team
2. **Patched** in public releases
3. **Disclosed** following standard 90-day timelines

See [DISCLOSURE_POLICY.md](../docs/DISCLOSURE_POLICY.md) for our full disclosure policy.

## Usage

Each PoC directory contains:

```
CVE-YYYY-XXXXX/
├── README.md       # Vulnerability description
├── detector.py     # Detection-focused PoC
├── TIMELINE.md     # Disclosure timeline
└── references.txt  # Source links
```

### Running a PoC

```bash
# Detection only - checks if target is vulnerable
python pocs/CVE-2026-25253/detector.py --host localhost --port 18789

# With JSON output
python pocs/CVE-2026-25253/detector.py --host localhost --port 18789 --json
```

## References

- [NVD CVE Database](https://nvd.nist.gov/)
- [OpenClaw Security Advisories](https://github.com/openclaw/openclaw/security/advisories)
- [DepthFirst Research](https://depthfirst.com)

## Legal

These PoCs are provided under the MIT License. Users are responsible for ensuring their use complies with all applicable laws and regulations.
