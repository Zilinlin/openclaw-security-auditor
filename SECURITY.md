# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in openclaw-security-auditor itself, please report it responsibly.

### Contact

- **Email**: shenzilin27@gmail.com
- **Subject line**: `[SECURITY] openclaw-security-auditor: <brief description>`

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response timeline

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 7 days
- **Fix or mitigation**: within 30 days for critical issues

### Scope

This policy covers vulnerabilities in:

- The `openclaw-security-auditor` tool itself
- Its dependencies as used in this project
- The runtime monitoring skill (`skill/`)

This policy does **not** cover:

- Vulnerabilities in OpenClaw itself (report those to the OpenClaw project)
- Issues found *by* this tool in your deployments (those are expected findings)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes      |

## Security Design Principles

This tool is designed with security in mind:

1. **Detection only** - Scanners and detectors identify vulnerabilities without exploiting them
2. **No data exfiltration** - No secrets, credentials, or sensitive data leave your machine
3. **Minimal dependencies** - Reduces supply chain attack surface
4. **Safe defaults** - All operations are read-only unless explicitly configured otherwise
