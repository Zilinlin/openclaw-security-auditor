# OpenClaw Security Monitor

A runtime security monitoring skill for OpenClaw agents. Provides file integrity monitoring, canary token detection, and anomaly alerts.

## Features

- **File Integrity Monitor**: SHA256 verification of critical agent files (SOUL.md, IDENTITY.md)
- **Canary Token Injection**: Detect data exfiltration via fake secrets
- **Anomaly Detection**: Monitor for suspicious behavior patterns
- **CVE Feed Integration**: Real-time vulnerability notifications

## Installation

Install this skill in your OpenClaw agent:

```
/skill install https://github.com/Zilinlin/openclaw-security-auditor/skill
```

Or manually add to your agent's skills directory.

## Usage

Once installed, the security monitor runs automatically. You can interact with it via commands:

```
@security status          # Show security status
@security check           # Run integrity check
@security alerts          # Show recent alerts
@security canary inject   # Inject canary tokens
@security canary check    # Check for canary leaks
```

## Configuration

Create `security-config.yaml` in your agent's config directory:

```yaml
# File integrity monitoring
integrity:
  enabled: true
  files:
    - SOUL.md
    - IDENTITY.md
    - AGENTS.md
    - config.yaml
  check_interval: 300  # seconds
  auto_restore: false  # Restore from backup on change

# Canary token injection
canary:
  enabled: true
  format: "CANARY-{id}"
  inject_count: 3

# Anomaly detection
anomaly:
  enabled: true
  rate_limits:
    email: 5/hour
    exec: 100/hour
    external_api: 50/hour
  egress_whitelist:
    - api.openai.com
    - api.anthropic.com

# CVE feed
cve_feed:
  enabled: true
  check_interval: 3600  # seconds
  sources:
    - https://clawsec.prompt.security/advisories/feed.json
```

## Alerts

The skill generates alerts for:

| Alert Type | Severity | Description |
|------------|----------|-------------|
| `integrity_violation` | Critical | Critical file modified |
| `canary_leak` | Critical | Canary token found in output |
| `rate_limit_exceeded` | High | Action rate limit exceeded |
| `egress_anomaly` | High | Connection to unknown domain |
| `new_integration` | Medium | Integration added without approval |
| `cve_advisory` | Varies | New CVE affecting current version |

## References

- File Integrity: https://github.com/prompt-security/clawsec
- Canary Tokens: https://github.com/openclaw/openclaw/issues/4840
- Anomaly Detection: https://www.penligent.ai/hackinglabs/the-openclaw-prompt-injection-problem-persistence-tool-hijack-and-the-security-boundary-that-doesnt-exist/

## License

MIT License
