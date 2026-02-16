"""OpenClaw Security Monitor Skill.

Runtime security monitoring for OpenClaw agents including:
- File integrity monitoring
- Canary token detection
- Anomaly detection
- CVE feed integration

Reference:
- https://github.com/prompt-security/clawsec
- https://github.com/openclaw/openclaw/issues/4840
"""

from .integrity import FileIntegrityMonitor
from .canary import CanaryTokenManager
from .anomaly import AnomalyDetector
from .cve_feed import CVEFeedManager
from .alerts import AlertManager, Alert, AlertSeverity

__all__ = [
    "FileIntegrityMonitor",
    "CanaryTokenManager",
    "AnomalyDetector",
    "CVEFeedManager",
    "AlertManager",
    "Alert",
    "AlertSeverity",
]

__version__ = "0.1.0"
