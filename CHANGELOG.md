# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- GitHub Actions CI pipeline with testing, linting, and security checks
- SECURITY.md for vulnerability reporting
- CHANGELOG.md for version tracking
- **Privilege Scanner**: Sensitive path detection — alerts when agent configs grant access to sensitive directories (`~/.ssh`, `~/.aws`, `~/.gnupg`, `/etc/shadow`, etc.) with 20+ built-in sensitive paths
- **Privilege Scanner**: Allowed path whitelist policy — users can specify `--allowed-paths` to enforce that all configured agent paths fall within approved directories
- **Privilege Scanner**: Custom sensitive path injection via `--sensitive-paths` for organization-specific sensitive locations
- 13 new tests for sensitive path and allowed path policy features (328 total)

## [0.1.1] - 2026-02-16

### Added
- CVE feed integration for runtime monitoring skill
- OpenClaw YAML-aware config scanner (detects missing auth, exposed prompts, plaintext tokens, missing CORS)
- Slack token detection patterns (xapp-*, xoxb-*, xoxp-*) in secret scanner
- 14 new tests for config and secret scanner improvements

### Fixed
- Config scanner now parses OpenClaw's nested YAML structure instead of only matching flat key=value patterns
- Missing `DetectorSeverity` and `VulnerabilityStatus` exports in detectors module

## [0.1.0] - 2026-02-15

### Added
- Initial release
- **Static analysis scanners**: config, CVE, secrets, network
- **Dynamic detectors**: WebSocket origin bypass (CVE-2026-25253), prompt injection, API hook bypass, auth weakness
- **Runtime monitoring skill**: file integrity, canary tokens, anomaly detection
- **PoC collection**: CVE-2026-25253, CVE-2026-25157, CVE-2026-24763
- **Payload library**: 15+ prompt injection payloads with references
- CLI tool with JSON output support
- Comprehensive documentation and security research references
