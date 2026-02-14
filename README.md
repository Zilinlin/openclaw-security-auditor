# OpenClaw Security Auditor

A security auditing tool for [OpenClaw](https://github.com/openclaw/openclaw) deployments. Detect misconfigurations, known CVEs, exposed secrets, and network exposure issues.

[中文文档](#中文文档)

## Why This Tool?

Recent security research revealed **135,000+ OpenClaw instances exposed to the internet**, with 63% vulnerable to known exploits. This tool helps you audit your deployment before attackers do.

### Known Vulnerabilities Detected

| CVE | Severity | Description |
|-----|----------|-------------|
| CVE-2026-25253 | High | Remote Code Execution |
| CVE-2026-25157 | High | Authentication Bypass |
| CVE-2026-24763 | High | Privilege Escalation |

## Features

- **Config Scanner** - Detect insecure default configurations (e.g., binding to `0.0.0.0`)
- **CVE Detector** - Check for known high-severity vulnerabilities
- **Secret Scanner** - Find exposed API keys and credentials
- **Network Exposure Check** - Detect if your instance is publicly accessible
- **Prompt Injection Tester** - Test agent resilience against injection attacks

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
# Scan local OpenClaw installation
openclaw-audit scan /path/to/openclaw

# Scan with specific checks
openclaw-audit scan /path/to/openclaw --checks config,cve,secrets

# Output as JSON
openclaw-audit scan /path/to/openclaw --json

# Check network exposure
openclaw-audit network --host localhost --port 18789
```

## Usage

### Full Audit

```bash
openclaw-audit scan /path/to/openclaw --all
```

### Individual Scanners

```bash
# Configuration audit
openclaw-audit config /path/to/openclaw/config.yaml

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

# JSON output
openclaw-audit scan /path/to/openclaw --json

# Save report
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

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Adding New Scanners

1. Create a new scanner in `src/auditor/scanners/`
2. Implement the `BaseScanner` interface
3. Register in `src/auditor/scanners/__init__.py`
4. Add tests in `tests/`

## License

MIT License - see [LICENSE](LICENSE) for details.

## Disclaimer

This tool is for **authorized security testing only**. Always obtain proper authorization before scanning systems you do not own.

---

# 中文文档

OpenClaw 安全审计工具，用于检测 OpenClaw 部署中的配置错误、已知 CVE 漏洞、敏感信息泄露和网络暴露问题。

## 为什么需要这个工具？

最新安全研究发现超过 **13.5 万个 OpenClaw 实例暴露在公网**，其中 63% 存在已知漏洞。在攻击者发现之前，先用这个工具审计你的部署。

## 功能特性

- **配置扫描** - 检测不安全的默认配置（如绑定 `0.0.0.0`）
- **CVE 检测** - 检查已知高危漏洞
- **密钥扫描** - 发现暴露的 API Key 和凭据
- **网络暴露检测** - 检测实例是否意外暴露到公网
- **Prompt 注入测试** - 测试代理对注入攻击的防御能力

## 快速开始

```bash
# 安装
pip install openclaw-security-auditor

# 扫描本地 OpenClaw 安装
openclaw-audit scan /path/to/openclaw

# JSON 格式输出
openclaw-audit scan /path/to/openclaw --json
```

## 免责声明

本工具仅用于**授权的安全测试**。在扫描不属于你的系统之前，请务必获得适当授权。
