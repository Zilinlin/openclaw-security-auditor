"""Anomaly Detector.

Monitors agent behavior for suspicious patterns that may indicate
prompt injection or compromise.

SAFETY NOTE:
- This module only monitors and logs behavior
- It does NOT block any actions (advisory only)
- All detections are based on configurable thresholds

Reference:
- https://www.penligent.ai/hackinglabs/the-openclaw-prompt-injection-problem-persistence-tool-hijack-and-the-security-boundary-that-doesnt-exist/
- https://github.com/openclaw/openclaw/issues/4840
"""

import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set

from .alerts import Alert, AlertManager, AlertSeverity


@dataclass
class ActionRecord:
    """Record of an agent action for anomaly tracking."""
    action_type: str
    target: Optional[str]
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict = field(default_factory=dict)


@dataclass
class RateLimit:
    """Rate limit configuration for an action type."""
    action_type: str
    max_count: int
    period_seconds: int


class AnomalyDetector:
    """Detect anomalous agent behavior patterns.

    This detector monitors for behavioral patterns that may indicate
    a compromised agent, including:

    1. Rate limit violations (unusual action frequency)
    2. Egress anomalies (connections to unexpected domains)
    3. Integration mutations (new integrations added without approval)
    4. Memory drift (configuration changes outside admin channels)

    Reference:
    - Penligent Research: Detection signals for prompt injection
    - GitHub Issue #4840: Runtime prompt injection defenses

    Attributes:
        alert_manager: AlertManager for sending alerts
        rate_limits: Dict of action type to RateLimit
        egress_whitelist: Set of allowed external domains
        baseline_period: Period to establish behavioral baseline
    """

    # Default rate limits
    # Reference: https://github.com/openclaw/openclaw/issues/4840
    DEFAULT_RATE_LIMITS = {
        "email": RateLimit("email", max_count=5, period_seconds=3600),
        "exec": RateLimit("exec", max_count=100, period_seconds=3600),
        "external_api": RateLimit("external_api", max_count=50, period_seconds=3600),
        "file_write": RateLimit("file_write", max_count=20, period_seconds=3600),
        "skill_install": RateLimit("skill_install", max_count=3, period_seconds=86400),
    }

    # Default allowed egress domains
    DEFAULT_EGRESS_WHITELIST = {
        "api.openai.com",
        "api.anthropic.com",
        "api.github.com",
        "raw.githubusercontent.com",
    }

    def __init__(
        self,
        alert_manager: Optional[AlertManager] = None,
        rate_limits: Optional[Dict[str, RateLimit]] = None,
        egress_whitelist: Optional[Set[str]] = None,
    ):
        """Initialize the anomaly detector.

        Args:
            alert_manager: Optional AlertManager for sending alerts
            rate_limits: Custom rate limits (merged with defaults)
            egress_whitelist: Set of allowed external domains
        """
        self.alert_manager = alert_manager or AlertManager()

        # Merge rate limits with defaults
        self.rate_limits = dict(self.DEFAULT_RATE_LIMITS)
        if rate_limits:
            self.rate_limits.update(rate_limits)

        # Egress whitelist
        self.egress_whitelist = egress_whitelist or self.DEFAULT_EGRESS_WHITELIST.copy()

        # Action history for rate limiting
        self.action_history: Dict[str, List[ActionRecord]] = defaultdict(list)

        # Known integrations (baseline)
        self.known_integrations: Set[str] = set()

        # Recently ingested content (for egress correlation)
        self.recent_ingestion: List[Dict] = []

    def record_action(
        self,
        action_type: str,
        target: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ) -> Optional[Alert]:
        """Record an agent action and check for anomalies.

        Args:
            action_type: Type of action (e.g., "email", "exec", "external_api")
            target: Target of the action (e.g., URL, command)
            metadata: Additional action metadata

        Returns:
            Alert if anomaly detected, None otherwise
        """
        record = ActionRecord(
            action_type=action_type,
            target=target,
            metadata=metadata or {},
        )

        self.action_history[action_type].append(record)

        # Check rate limits
        alert = self._check_rate_limit(action_type)
        if alert:
            return alert

        # Check egress whitelist for external API calls
        if action_type == "external_api" and target:
            alert = self._check_egress(target)
            if alert:
                return alert

        return None

    def _check_rate_limit(self, action_type: str) -> Optional[Alert]:
        """Check if action rate limit is exceeded.

        Reference: Rate limiting proposed in GitHub Issue #4840
        """
        if action_type not in self.rate_limits:
            return None

        limit = self.rate_limits[action_type]
        cutoff = datetime.now() - timedelta(seconds=limit.period_seconds)

        # Count recent actions
        recent_actions = [
            a for a in self.action_history[action_type]
            if a.timestamp > cutoff
        ]

        if len(recent_actions) > limit.max_count:
            alert = Alert(
                alert_type="rate_limit_exceeded",
                severity=AlertSeverity.HIGH,
                title=f"Rate Limit Exceeded: {action_type}",
                description=(
                    f"Action '{action_type}' has been performed "
                    f"{len(recent_actions)} times in the last "
                    f"{limit.period_seconds} seconds, exceeding the limit of "
                    f"{limit.max_count}. This may indicate automated abuse "
                    f"or a compromised agent."
                ),
                metadata={
                    "action_type": action_type,
                    "count": len(recent_actions),
                    "limit": limit.max_count,
                    "period_seconds": limit.period_seconds,
                },
                reference="https://github.com/openclaw/openclaw/issues/4840",
            )
            self.alert_manager.send(alert)
            return alert

        return None

    def _check_egress(self, target: str) -> Optional[Alert]:
        """Check if egress target is in whitelist.

        Reference: Egress anomalies as detection signal (Penligent Research)
        """
        # Extract domain from URL
        domain = self._extract_domain(target)

        if domain and domain not in self.egress_whitelist:
            # Check if this is shortly after ingesting external content
            is_suspicious = self._check_ingestion_correlation()

            severity = AlertSeverity.HIGH if is_suspicious else AlertSeverity.MEDIUM

            alert = Alert(
                alert_type="egress_anomaly",
                severity=severity,
                title=f"Egress to Unknown Domain: {domain}",
                description=(
                    f"Agent attempted to connect to '{domain}' which is not "
                    f"in the egress whitelist. "
                    + ("This occurred shortly after ingesting external content, "
                       "which may indicate a prompt injection attack." if is_suspicious else "")
                ),
                metadata={
                    "domain": domain,
                    "full_url": target,
                    "post_ingestion": is_suspicious,
                },
                reference="https://www.penligent.ai/hackinglabs/the-openclaw-prompt-injection-problem-persistence-tool-hijack-and-the-security-boundary-that-doesnt-exist/",
            )
            self.alert_manager.send(alert)
            return alert

        return None

    def _extract_domain(self, url: str) -> Optional[str]:
        """Extract domain from URL."""
        match = re.search(r'https?://([^/]+)', url)
        if match:
            domain = match.group(1)
            # Remove port if present
            domain = domain.split(':')[0]
            return domain.lower()
        return None

    def _check_ingestion_correlation(self) -> bool:
        """Check if egress is correlated with recent content ingestion.

        Reference: Penligent Research - "Agent attempts to contact new domain
        shortly after ingesting external document"
        """
        cutoff = datetime.now() - timedelta(minutes=5)
        return any(
            datetime.fromisoformat(ing.get('timestamp', '2000-01-01')) > cutoff
            for ing in self.recent_ingestion
        )

    def record_ingestion(
        self,
        source_type: str,
        source: str,
        content_hash: Optional[str] = None,
    ) -> None:
        """Record content ingestion for egress correlation.

        Args:
            source_type: Type of source (e.g., "url", "file", "message")
            source: Source identifier (e.g., URL, filename)
            content_hash: Optional hash of content for tracking
        """
        self.recent_ingestion.append({
            "source_type": source_type,
            "source": source,
            "content_hash": content_hash,
            "timestamp": datetime.now().isoformat(),
        })

        # Keep only recent ingestions (last hour)
        cutoff = datetime.now() - timedelta(hours=1)
        self.recent_ingestion = [
            ing for ing in self.recent_ingestion
            if datetime.fromisoformat(ing['timestamp']) > cutoff
        ]

    def record_integration(self, integration_name: str) -> Optional[Alert]:
        """Record a new integration and check if it was expected.

        Reference: Penligent Research - "New integration added by agent
        without explicit approval"

        Args:
            integration_name: Name of the integration

        Returns:
            Alert if integration was not previously known
        """
        if integration_name not in self.known_integrations:
            alert = Alert(
                alert_type="integration_mutation",
                severity=AlertSeverity.MEDIUM,
                title=f"New Integration Added: {integration_name}",
                description=(
                    f"Integration '{integration_name}' was added without being "
                    f"in the known integrations list. This may indicate an "
                    f"agent autonomously adding integrations, which could be "
                    f"the result of prompt injection."
                ),
                metadata={
                    "integration_name": integration_name,
                    "known_integrations": list(self.known_integrations),
                },
                reference="https://www.penligent.ai/hackinglabs/the-openclaw-prompt-injection-problem-persistence-tool-hijack-and-the-security-boundary-that-doesnt-exist/",
            )
            self.alert_manager.send(alert)
            return alert

        return None

    def add_known_integration(self, integration_name: str) -> None:
        """Add an integration to the known list (baseline)."""
        self.known_integrations.add(integration_name)

    def add_egress_whitelist(self, domain: str) -> None:
        """Add a domain to the egress whitelist."""
        self.egress_whitelist.add(domain.lower())

    def cleanup_history(self, max_age_hours: int = 24) -> int:
        """Clean up old action history.

        Args:
            max_age_hours: Maximum age of records to keep

        Returns:
            Number of records removed
        """
        cutoff = datetime.now() - timedelta(hours=max_age_hours)
        removed = 0

        for action_type in list(self.action_history.keys()):
            original_count = len(self.action_history[action_type])
            self.action_history[action_type] = [
                a for a in self.action_history[action_type]
                if a.timestamp > cutoff
            ]
            removed += original_count - len(self.action_history[action_type])

        return removed

    def get_status(self) -> Dict:
        """Get current anomaly detector status.

        Returns:
            Dict with status information
        """
        return {
            "rate_limits": {
                name: {"max": rl.max_count, "period_seconds": rl.period_seconds}
                for name, rl in self.rate_limits.items()
            },
            "egress_whitelist": list(self.egress_whitelist),
            "known_integrations": list(self.known_integrations),
            "recent_actions": {
                action_type: len(records)
                for action_type, records in self.action_history.items()
            },
            "recent_ingestions": len(self.recent_ingestion),
        }
