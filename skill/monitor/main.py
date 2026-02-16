"""OpenClaw Security Monitor - Main Entry Point.

This is the main skill entry point that integrates all monitoring components.

Usage:
    The skill can be installed in OpenClaw and responds to @security commands.

Reference:
- https://github.com/prompt-security/clawsec
- https://github.com/openclaw/openclaw/issues/4840
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

from .integrity import FileIntegrityMonitor
from .canary import CanaryTokenManager
from .anomaly import AnomalyDetector
from .cve_feed import CVEFeedManager
from .alerts import AlertManager, Alert, AlertSeverity, console_alert_handler


class SecurityMonitor:
    """Main security monitor that integrates all components.

    This class provides a unified interface to:
    - File integrity monitoring
    - Canary token detection
    - Anomaly detection
    - CVE feed integration
    - Alert management

    Reference:
    - ClawSec: https://github.com/prompt-security/clawsec
    - Runtime Defenses: https://github.com/openclaw/openclaw/issues/4840

    Usage:
        monitor = SecurityMonitor("/path/to/agent/config")
        monitor.initialize()

        # Check integrity
        violations = monitor.check_integrity()

        # Protect context with canaries
        protected = monitor.inject_canaries(context)

        # Check output for leaks
        leaks = monitor.check_output(agent_response)

        # Record actions for anomaly detection
        monitor.record_action("email", "user@example.com")
    """

    VERSION = "0.1.0"

    def __init__(
        self,
        config_dir: str,
        config: Optional[Dict] = None,
        enable_console_alerts: bool = True,
    ):
        """Initialize the security monitor.

        Args:
            config_dir: Path to agent configuration directory
            config: Optional configuration dict
            enable_console_alerts: Whether to print alerts to console
        """
        self.config_dir = Path(config_dir)
        self.config = config or {}

        # Initialize alert manager
        self.alert_manager = AlertManager()
        if enable_console_alerts:
            self.alert_manager.register_handler(console_alert_handler)

        # Initialize components
        self._init_components()

    def _init_components(self) -> None:
        """Initialize monitoring components based on config."""
        # File integrity monitor
        integrity_config = self.config.get("integrity", {})
        self.integrity_monitor = FileIntegrityMonitor(
            config_dir=str(self.config_dir),
            alert_manager=self.alert_manager,
            monitored_files=integrity_config.get("files"),
            auto_restore=integrity_config.get("auto_restore", False),
        )

        # Canary token manager
        canary_config = self.config.get("canary", {})
        self.canary_manager = CanaryTokenManager(
            alert_manager=self.alert_manager,
            token_format=canary_config.get("format"),
            include_fake_secrets=canary_config.get("include_fake_secrets", True),
        )

        # Anomaly detector
        anomaly_config = self.config.get("anomaly", {})
        self.anomaly_detector = AnomalyDetector(
            alert_manager=self.alert_manager,
            egress_whitelist=set(anomaly_config.get("egress_whitelist", [])) or None,
        )

        # CVE feed manager
        cve_feed_config = self.config.get("cve_feed", {})
        self.cve_feed_manager = CVEFeedManager(
            alert_manager=self.alert_manager,
            sources=cve_feed_config.get("sources", []),
            check_interval=cve_feed_config.get("check_interval", 3600),
            current_version=cve_feed_config.get("current_version"),
        )

    def initialize(self) -> Dict:
        """Initialize all monitoring components.

        This should be called once during agent startup to establish baselines.

        Returns:
            Dict with initialization status
        """
        status = {
            "version": self.VERSION,
            "initialized_at": datetime.now().isoformat(),
            "components": {},
        }

        # Initialize file integrity baseline
        if self.config.get("integrity", {}).get("enabled", True):
            checksums = self.integrity_monitor.initialize()
            status["components"]["integrity"] = {
                "enabled": True,
                "files_tracked": len(checksums),
            }
        else:
            status["components"]["integrity"] = {"enabled": False}

        # Initialize canary (just mark as ready)
        if self.config.get("canary", {}).get("enabled", True):
            status["components"]["canary"] = {"enabled": True}
        else:
            status["components"]["canary"] = {"enabled": False}

        # Initialize anomaly detection
        if self.config.get("anomaly", {}).get("enabled", True):
            status["components"]["anomaly"] = {
                "enabled": True,
                "rate_limits": list(self.anomaly_detector.rate_limits.keys()),
            }
        else:
            status["components"]["anomaly"] = {"enabled": False}

        # Initialize CVE feed
        if self.config.get("cve_feed", {}).get("enabled", True):
            advisories = self.cve_feed_manager.check()
            status["components"]["cve_feed"] = {
                "enabled": True,
                "relevant_advisories": len(advisories),
                "total_advisories": len(self.cve_feed_manager.advisories),
            }
        else:
            status["components"]["cve_feed"] = {"enabled": False}

        return status

    # =========================================================================
    # FILE INTEGRITY
    # =========================================================================

    def check_integrity(self) -> Dict:
        """Check file integrity.

        Returns:
            Dict with check results
        """
        violations = self.integrity_monitor.check()
        return {
            "checked_at": datetime.now().isoformat(),
            "violations_found": len(violations),
            "violations": [
                {
                    "file": v.path,
                    "type": v.violation_type,
                    "detected_at": v.detected_at.isoformat(),
                }
                for v in violations
            ],
        }

    def update_integrity_baseline(self, filename: str) -> Dict:
        """Update baseline for a file after legitimate modification.

        Args:
            filename: File to update

        Returns:
            Dict with new checksum info
        """
        checksum = self.integrity_monitor.update_baseline(filename)
        if checksum:
            return {
                "file": filename,
                "sha256": checksum.sha256,
                "updated_at": checksum.checked_at.isoformat(),
            }
        return {"error": f"File not found: {filename}"}

    # =========================================================================
    # CANARY TOKENS
    # =========================================================================

    def inject_canaries(self, context: str, count: int = 1) -> str:
        """Inject canary tokens into context.

        Args:
            context: Original context
            count: Number of canaries to inject

        Returns:
            Context with canaries injected
        """
        return self.canary_manager.inject(
            context,
            num_canaries=count,
            include_fake_secrets=self.config.get("canary", {}).get("include_fake_secrets", True),
        )

    def check_output(self, output: str) -> Dict:
        """Check output for canary token leaks.

        Args:
            output: Agent output to check

        Returns:
            Dict with check results
        """
        triggered = self.canary_manager.check_output(output)
        return {
            "checked_at": datetime.now().isoformat(),
            "leaks_found": len(triggered),
            "leaked_canaries": [
                {
                    "id": c.id,
                    "context": c.context,
                    "triggered_at": c.triggered_at.isoformat() if c.triggered_at else None,
                }
                for c in triggered
            ],
        }

    # =========================================================================
    # ANOMALY DETECTION
    # =========================================================================

    def record_action(
        self,
        action_type: str,
        target: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ) -> Optional[Dict]:
        """Record an action and check for anomalies.

        Args:
            action_type: Type of action
            target: Target of action
            metadata: Additional metadata

        Returns:
            Alert dict if anomaly detected, None otherwise
        """
        alert = self.anomaly_detector.record_action(action_type, target, metadata)
        if alert:
            return alert.to_dict()
        return None

    def record_ingestion(
        self,
        source_type: str,
        source: str,
        content_hash: Optional[str] = None,
    ) -> None:
        """Record content ingestion for egress correlation.

        Args:
            source_type: Type of source
            source: Source identifier
            content_hash: Optional content hash
        """
        self.anomaly_detector.record_ingestion(source_type, source, content_hash)

    # =========================================================================
    # ALERTS
    # =========================================================================

    def get_alerts(
        self,
        severity: Optional[str] = None,
        alert_type: Optional[str] = None,
        limit: int = 100,
    ) -> Dict:
        """Get security alerts.

        Args:
            severity: Filter by severity
            alert_type: Filter by type
            limit: Maximum alerts to return

        Returns:
            Dict with alerts
        """
        sev = AlertSeverity(severity) if severity else None
        alerts = self.alert_manager.get_alerts(
            severity=sev,
            alert_type=alert_type,
            limit=limit,
        )
        return {
            "count": len(alerts),
            "alerts": [a.to_dict() for a in alerts],
        }

    def get_alert_summary(self) -> Dict:
        """Get alert summary statistics.

        Returns:
            Dict with summary
        """
        return self.alert_manager.get_summary()

    def acknowledge_alert(self, index: int) -> bool:
        """Acknowledge an alert.

        Args:
            index: Alert index

        Returns:
            True if successful
        """
        return self.alert_manager.acknowledge(index)

    # =========================================================================
    # STATUS
    # =========================================================================

    def get_status(self) -> Dict:
        """Get overall security monitor status.

        Returns:
            Dict with full status
        """
        return {
            "version": self.VERSION,
            "config_dir": str(self.config_dir),
            "components": {
                "integrity": self.integrity_monitor.get_status(),
                "canary": self.canary_manager.get_status(),
                "anomaly": self.anomaly_detector.get_status(),
                "cve_feed": self.cve_feed_manager.get_status(),
            },
            "alerts": self.alert_manager.get_summary(),
        }


# =============================================================================
# SKILL COMMAND HANDLERS
# =============================================================================

def handle_command(monitor: SecurityMonitor, command: str, args: list) -> str:
    """Handle @security commands.

    Commands:
        @security status - Show status
        @security check - Run integrity check
        @security alerts - Show alerts
        @security alerts clear - Clear acknowledged alerts
        @security canary inject - Inject canaries
        @security canary check <text> - Check for canary leaks
        @security cve check - Check for relevant CVE advisories
        @security cve status - Show CVE feed status

    Args:
        monitor: SecurityMonitor instance
        command: Command name
        args: Command arguments

    Returns:
        Response string
    """
    if command == "status":
        return json.dumps(monitor.get_status(), indent=2)

    elif command == "check":
        result = monitor.check_integrity()
        if result["violations_found"] > 0:
            return f"ALERT: {result['violations_found']} integrity violations found!\n" + \
                   json.dumps(result, indent=2)
        return "OK: No integrity violations detected."

    elif command == "alerts":
        if args and args[0] == "clear":
            count = monitor.alert_manager.clear(acknowledged_only=True)
            return f"Cleared {count} acknowledged alerts."
        elif args and args[0] == "summary":
            return json.dumps(monitor.get_alert_summary(), indent=2)
        else:
            return json.dumps(monitor.get_alerts(), indent=2)

    elif command == "canary":
        if not args:
            return "Usage: @security canary [inject|check|status]"

        if args[0] == "inject":
            canary = monitor.canary_manager.create_canary("manual")
            return f"Canary created: {canary.id}"
        elif args[0] == "check" and len(args) > 1:
            text = " ".join(args[1:])
            result = monitor.check_output(text)
            if result["leaks_found"] > 0:
                return f"ALERT: Canary leak detected!\n{json.dumps(result, indent=2)}"
            return "OK: No canary leaks detected."
        elif args[0] == "status":
            return json.dumps(monitor.canary_manager.get_status(), indent=2)
        else:
            return "Usage: @security canary [inject|check <text>|status]"

    elif command == "cve":
        if not args:
            return "Usage: @security cve [check|status]"

        if args[0] == "check":
            advisories = monitor.cve_feed_manager.check()
            if advisories:
                lines = [f"ALERT: {len(advisories)} relevant CVE advisories found!"]
                for adv in advisories:
                    lines.append(f"  [{adv.severity.value.upper()}] {adv.cve_id}: {adv.title}")
                return "\n".join(lines)
            return "OK: No relevant CVE advisories for current version."
        elif args[0] == "status":
            return json.dumps(monitor.cve_feed_manager.get_status(), indent=2)
        else:
            return "Usage: @security cve [check|status]"

    else:
        return f"Unknown command: {command}\n" + \
               "Available: status, check, alerts, canary, cve"
