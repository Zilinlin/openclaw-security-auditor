# Responsible Disclosure Policy

This document outlines our commitment to responsible security research and coordinated vulnerability disclosure.

## Table of Contents

- [Our Commitment](#our-commitment)
- [Scope](#scope)
- [Disclosure Timeline](#disclosure-timeline)
- [PoC Guidelines](#poc-guidelines)
- [Reporting Vulnerabilities](#reporting-vulnerabilities)
- [Legal Safe Harbor](#legal-safe-harbor)
- [References](#references)

---

## Our Commitment

OpenClaw Security Auditor is developed for **defensive security purposes only**. We are committed to:

1. **Responsible Disclosure**: We only publish PoC code for vulnerabilities that have been:
   - Reported to the vendor
   - Patched in a public release
   - Past the disclosure timeline

2. **Minimal Harm**: Our detection tools are designed to:
   - Identify vulnerabilities without exploiting them
   - Never exfiltrate real data
   - Never cause denial of service

3. **Transparency**: All detection techniques are:
   - Documented with references
   - Based on public security research
   - Open source for community review

---

## Scope

### In Scope

This project covers security testing for:

- OpenClaw (formerly Clawdbot/Moltbot) deployments
- OpenClaw Skills and integrations
- OpenClaw API endpoints
- Configuration and deployment security

### Out of Scope

We do NOT provide tools for:

- Attacking systems without authorization
- Mass scanning of internet-facing systems
- Exploiting vulnerabilities for malicious purposes
- Bypassing security controls for unauthorized access

---

## Disclosure Timeline

We follow a **90-day coordinated disclosure** policy aligned with industry standards [[1]](#references).

### Standard Timeline

| Day | Action |
|-----|--------|
| 0 | Vulnerability discovered and documented |
| 1-3 | Initial report sent to vendor security team |
| 7 | Acknowledgment expected from vendor |
| 14 | Technical details shared if requested |
| 30 | Progress check with vendor |
| 60 | Draft advisory prepared |
| 90 | Public disclosure (with or without patch) |

### Accelerated Timeline (Critical Vulnerabilities)

For actively exploited or critical vulnerabilities:

| Day | Action |
|-----|--------|
| 0-1 | Immediate report to vendor |
| 7 | Public disclosure if no response |
| 14 | Full disclosure if no patch available |

### Extended Timeline

We may extend the timeline if:

- Vendor is actively working on a complex fix
- Patch requires coordinated release with dependencies
- Extended timeline is requested in good faith

---

## PoC Guidelines

### What We Publish

Our PoC collection (`/pocs`) contains:

1. **Patched Vulnerabilities Only**: Code for CVEs that have been fixed in public releases
2. **Educational Focus**: Detailed comments explaining the vulnerability
3. **Detection Emphasis**: Focus on identifying, not exploiting

### PoC Structure

Each PoC includes:

```
pocs/
└── CVE-YYYY-XXXXX/
    ├── README.md           # Vulnerability description
    ├── detector.py         # Detection-only code
    ├── TIMELINE.md         # Disclosure timeline
    └── references.txt      # Source links
```

### README.md Template

```markdown
# CVE-YYYY-XXXXX: [Vulnerability Title]

## Overview
- **CVE ID**: CVE-YYYY-XXXXX
- **CVSS Score**: X.X
- **Affected Versions**: < vX.X.X
- **Fixed Version**: vX.X.X
- **Disclosure Date**: YYYY-MM-DD

## Description
[Technical description of the vulnerability]

## Impact
[What an attacker could achieve]

## Detection
[How to detect if you're vulnerable]

## Remediation
[Steps to fix the vulnerability]

## References
- [NVD Entry](https://nvd.nist.gov/vuln/detail/CVE-YYYY-XXXXX)
- [Vendor Advisory](https://...)
- [Original Research](https://...)

## Disclaimer
This PoC is for educational and authorized security testing only.
```

---

## Reporting Vulnerabilities

### If You Find a Vulnerability Using Our Tool

1. **Do NOT** publicly disclose before reporting to vendor
2. Report to the OpenClaw security team:
   - Email: security@openclaw.ai
   - GitHub Security Advisory: https://github.com/openclaw/openclaw/security/advisories
3. Optionally CC us: zilinlin@proton.me

### If You Find a Vulnerability in Our Tool

1. **Do NOT** open a public GitHub issue
2. Email: zilinlin@proton.me
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### CVE Assignment

For vulnerabilities you discover:

1. Report to vendor first
2. Request CVE from:
   - GitHub CNA (for GitHub-hosted projects)
   - MITRE (https://cveform.mitre.org/)
3. Wait for vendor patch before public disclosure

---

## Legal Safe Harbor

### For Users of This Tool

This tool is intended for:

- **Authorized security testing** of your own systems
- **Security research** in controlled environments
- **Educational purposes** in academic settings
- **Professional penetration testing** with proper authorization

**You are responsible for**:
- Obtaining proper authorization before testing
- Complying with all applicable laws
- Not using this tool for malicious purposes

### Our Legal Position

We provide this tool in good faith for legitimate security purposes. We:

- Do NOT encourage unauthorized access to systems
- Do NOT provide support for malicious use
- Reserve the right to report abuse to authorities

---

## References

| # | Source | URL |
|---|--------|-----|
| 1 | Google Project Zero Disclosure Policy | https://googleprojectzero.blogspot.com/p/vulnerability-disclosure-policy.html |
| 2 | CERT/CC Vulnerability Disclosure Policy | https://vuls.cert.org/confluence/display/CVD |
| 3 | ISO/IEC 29147:2018 Vulnerability Disclosure | https://www.iso.org/standard/72311.html |

---

## Contact

- **Security Issues**: zilinlin@proton.me
- **General Questions**: Open a GitHub issue
- **Contributions**: See [CONTRIBUTING.md](../CONTRIBUTING.md)

---

*Last Updated: February 2026*
