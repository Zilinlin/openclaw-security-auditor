"""Alert Management System.

Handles security alerts from all monitoring components.

Reference:
- https://github.com/prompt-security/clawsec
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Callable, Dict, List, Optional


class AlertSeverity(Enum):
    """Severity levels for security alerts."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Alert:
    """A security alert.

    Attributes:
        alert_type: Type of alert (e.g., "integrity_violation", "canary_leak")
        severity: Severity level
        title: Short title
        description: Detailed description
        metadata: Additional data
        reference: URL to relevant documentation
        created_at: When the alert was created
        acknowledged: Whether the alert has been acknowledged
    """
    alert_type: str
    severity: AlertSeverity
    title: str
    description: str
    metadata: Dict = field(default_factory=dict)
    reference: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    acknowledged: bool = False

    def to_dict(self) -> Dict:
        """Convert alert to dictionary."""
        return {
            "alert_type": self.alert_type,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "metadata": self.metadata,
            "reference": self.reference,
            "created_at": self.created_at.isoformat(),
            "acknowledged": self.acknowledged,
        }

    def to_json(self) -> str:
        """Convert alert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class AlertManager:
    """Manage security alerts.

    Handles alert creation, storage, and notification dispatch.

    Attributes:
        alerts: List of all alerts
        handlers: Registered alert handlers
        max_alerts: Maximum number of alerts to retain
    """

    def __init__(self, max_alerts: int = 1000):
        """Initialize the alert manager.

        Args:
            max_alerts: Maximum number of alerts to retain
        """
        self.alerts: List[Alert] = []
        self.handlers: List[Callable[[Alert], None]] = []
        self.max_alerts = max_alerts

    def register_handler(self, handler: Callable[[Alert], None]) -> None:
        """Register an alert handler.

        Handlers are called when new alerts are created.

        Args:
            handler: Callable that takes an Alert
        """
        self.handlers.append(handler)

    def send(self, alert: Alert) -> None:
        """Send a new alert.

        Args:
            alert: The alert to send
        """
        self.alerts.append(alert)

        # Trim if over limit
        if len(self.alerts) > self.max_alerts:
            self.alerts = self.alerts[-self.max_alerts:]

        # Dispatch to handlers
        for handler in self.handlers:
            try:
                handler(alert)
            except Exception:
                pass  # Don't let handler errors break alerting

    def get_alerts(
        self,
        severity: Optional[AlertSeverity] = None,
        alert_type: Optional[str] = None,
        unacknowledged_only: bool = False,
        limit: int = 100,
    ) -> List[Alert]:
        """Get alerts matching criteria.

        Args:
            severity: Filter by severity
            alert_type: Filter by alert type
            unacknowledged_only: Only return unacknowledged alerts
            limit: Maximum number of alerts to return

        Returns:
            List of matching alerts (newest first)
        """
        result = self.alerts

        if severity:
            result = [a for a in result if a.severity == severity]

        if alert_type:
            result = [a for a in result if a.alert_type == alert_type]

        if unacknowledged_only:
            result = [a for a in result if not a.acknowledged]

        # Return newest first
        return list(reversed(result[-limit:]))

    def acknowledge(self, index: int) -> bool:
        """Acknowledge an alert by index.

        Args:
            index: Index of alert to acknowledge

        Returns:
            True if successful
        """
        if 0 <= index < len(self.alerts):
            self.alerts[index].acknowledged = True
            return True
        return False

    def acknowledge_all(self) -> int:
        """Acknowledge all unacknowledged alerts.

        Returns:
            Number of alerts acknowledged
        """
        count = 0
        for alert in self.alerts:
            if not alert.acknowledged:
                alert.acknowledged = True
                count += 1
        return count

    def clear(self, acknowledged_only: bool = True) -> int:
        """Clear alerts.

        Args:
            acknowledged_only: Only clear acknowledged alerts

        Returns:
            Number of alerts cleared
        """
        if acknowledged_only:
            original_count = len(self.alerts)
            self.alerts = [a for a in self.alerts if not a.acknowledged]
            return original_count - len(self.alerts)
        else:
            count = len(self.alerts)
            self.alerts = []
            return count

    def get_summary(self) -> Dict:
        """Get alert summary statistics.

        Returns:
            Dict with summary statistics
        """
        summary = {
            "total": len(self.alerts),
            "unacknowledged": sum(1 for a in self.alerts if not a.acknowledged),
            "by_severity": {},
            "by_type": {},
        }

        for alert in self.alerts:
            # Count by severity
            sev = alert.severity.value
            summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1

            # Count by type
            summary["by_type"][alert.alert_type] = summary["by_type"].get(alert.alert_type, 0) + 1

        return summary


# Console alert handler for debugging
def console_alert_handler(alert: Alert) -> None:
    """Print alerts to console."""
    severity_colors = {
        AlertSeverity.CRITICAL: "\033[91m",  # Red
        AlertSeverity.HIGH: "\033[91m",       # Red
        AlertSeverity.MEDIUM: "\033[93m",     # Yellow
        AlertSeverity.LOW: "\033[96m",        # Cyan
        AlertSeverity.INFO: "\033[94m",       # Blue
    }
    reset = "\033[0m"

    color = severity_colors.get(alert.severity, "")
    print(f"{color}[{alert.severity.value.upper()}]{reset} {alert.title}")
    print(f"  {alert.description}")
    if alert.reference:
        print(f"  Reference: {alert.reference}")
