# Contributing to OpenClaw Security Auditor

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Adding New Scanners](#adding-new-scanners)
- [Adding New Detectors](#adding-new-detectors)
- [Documentation Requirements](#documentation-requirements)
- [Pull Request Process](#pull-request-process)
- [Security Considerations](#security-considerations)

---

## Code of Conduct

This project is intended for **defensive security purposes only**. Contributors must:

1. **Not** submit code designed for malicious purposes
2. **Not** include real exploits without proper disclosure
3. Follow responsible disclosure guidelines
4. Respect the security community and end users

---

## How to Contribute

### Types of Contributions

| Type | Description |
|------|-------------|
| Bug Fixes | Fix issues in existing scanners/detectors |
| New Scanners | Add static analysis capabilities |
| New Detectors | Add dynamic detection capabilities |
| Documentation | Improve docs, add references |
| Tests | Increase test coverage |
| CVE Updates | Add newly disclosed vulnerabilities |

### Getting Started

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Add tests for new functionality
5. Update documentation with references
6. Submit a pull request

---

## Development Setup

### Prerequisites

- Python 3.9+
- pip

### Installation

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/openclaw-security-auditor.git
cd openclaw-security-auditor

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest
```

### Code Style

We use:
- `black` for code formatting
- `ruff` for linting
- `mypy` for type checking

```bash
# Format code
black src/ tests/

# Lint
ruff check src/ tests/

# Type check
mypy src/
```

---

## Adding New Scanners

Static scanners analyze files and configurations without making network connections.

### Step 1: Create Scanner File

Create `src/auditor/scanners/my_scanner.py`:

```python
"""Description of what this scanner detects."""

from .base import BaseScanner, Finding, ScanResult, Severity


class MyScanner(BaseScanner):
    """Scanner description with reference."""

    name = "my_scanner"
    description = "What this scanner detects"

    # Document the source of each pattern
    # Reference: [URL to security research]
    PATTERNS = [
        {
            "pattern": r"...",
            "title": "Issue Title",
            "severity": Severity.HIGH,
            "description": "What this means",
            "reference": "https://...",  # REQUIRED
        }
    ]

    def scan(self, target: str, **kwargs) -> ScanResult:
        """Implement scanning logic."""
        result = ScanResult(scanner_name=self.name)
        # ... implementation
        return result
```

### Step 2: Register Scanner

Add to `src/auditor/scanners/__init__.py`:

```python
from .my_scanner import MyScanner

SCANNERS = {
    # ... existing scanners
    "my_scanner": MyScanner,
}
```

### Step 3: Add Tests

Create `tests/test_my_scanner.py`:

```python
"""Tests for MyScanner."""

import pytest
from auditor.scanners import MyScanner


class TestMyScanner:
    def test_detects_issue(self):
        # Test detection works
        pass

    def test_no_false_positives(self):
        # Test clean input doesn't trigger
        pass
```

### Step 4: Document

Add to `docs/DETECTION_TECHNIQUES.md`:

```markdown
### My Scanner

**Purpose**: What it detects

**Reference**: [[X]](#references)

| Pattern | Severity | Description | Reference |
|---------|----------|-------------|-----------|
| ... | ... | ... | [[X]](#references) |
```

---

## Adding New Detectors

Dynamic detectors interact with running OpenClaw instances.

### Safety Requirements

**All detectors MUST**:

1. **Not exploit vulnerabilities** - Only detect their presence
2. **Not exfiltrate data** - No real credentials should be captured
3. **Not cause denial of service** - Be gentle with target systems
4. **Be clearly documented** - Explain what network activity occurs

### Step 1: Create Detector File

Create `src/auditor/detectors/my_detector.py`:

```python
"""
Detector for [vulnerability name].

Reference: [URL to CVE or research]

Safety:
- This detector only checks if [condition]
- No actual exploitation is performed
- No sensitive data is transmitted
"""

from .base import BaseDetector, DetectorResult


class MyDetector(BaseDetector):
    """
    Detect [vulnerability].

    Reference: https://...
    """

    name = "my_detector"
    description = "What this detects"
    cve = "CVE-YYYY-XXXXX"  # If applicable

    def detect(self, host: str, port: int, **kwargs) -> DetectorResult:
        """
        Test for vulnerability.

        This method:
        - Does: [what it does]
        - Does NOT: [what it doesn't do]
        """
        result = DetectorResult(detector_name=self.name)
        # ... safe detection implementation
        return result
```

### Step 2: Safety Review Checklist

Before submitting a detector PR, verify:

- [ ] No actual exploitation code
- [ ] No credential harvesting
- [ ] No persistent changes to target
- [ ] No excessive requests (rate limiting)
- [ ] Clear documentation of network activity
- [ ] Reference to public security research

---

## Documentation Requirements

### Every New Feature Must Include

1. **Code Comments**: Explain the purpose and reference sources

```python
# Detect binding to all interfaces
# Reference: https://docs.openclaw.ai/gateway/security
# This is dangerous because: [explanation]
PATTERN = r"bind.*0\.0\.0\.0"
```

2. **Detection Techniques Doc**: Add to `docs/DETECTION_TECHNIQUES.md`

3. **References**: Link to authoritative sources

| Acceptable References | Not Acceptable |
|----------------------|----------------|
| CVE/NVD entries | Personal blogs without sources |
| Vendor security advisories | "Common knowledge" |
| Published security research | Stack Overflow answers |
| OWASP documentation | Wikipedia (use primary sources) |
| GitHub security advisories | Unverified claims |

---

## Pull Request Process

### PR Checklist

- [ ] Code follows project style (black, ruff)
- [ ] Tests pass (`pytest`)
- [ ] Type hints included (`mypy`)
- [ ] Documentation updated with references
- [ ] No secrets or credentials in code
- [ ] Follows security guidelines

### PR Template

```markdown
## Description
[What does this PR do?]

## Type
- [ ] Bug fix
- [ ] New scanner
- [ ] New detector
- [ ] Documentation
- [ ] Other: ___

## References
[Links to security research, CVEs, or documentation]

## Testing
[How was this tested?]

## Security Checklist
- [ ] No exploitation code
- [ ] No credential harvesting
- [ ] Detection-only functionality
- [ ] Documented network activity (if any)
```

---

## Security Considerations

### What NOT to Submit

1. **Working exploits** - Detection only, no weaponization
2. **Zero-day vulnerabilities** - Must be disclosed to vendor first
3. **Credential harvesting** - Even for "testing"
4. **DoS capabilities** - No stress testing features
5. **Obfuscated code** - All code must be readable

### Responsible Disclosure

If your contribution involves a new vulnerability:

1. **Report to vendor first** (see [DISCLOSURE_POLICY.md](docs/DISCLOSURE_POLICY.md))
2. Wait for patch to be released
3. Then submit PR with detection capability
4. Include disclosure timeline in PR

### Questions?

Open an issue or reach out to maintainers before submitting sensitive security contributions.

---

*Thank you for contributing to making OpenClaw deployments more secure!*
