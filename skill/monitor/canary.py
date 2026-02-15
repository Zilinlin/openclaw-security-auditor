"""Canary Token Manager.

Implements canary token injection and detection for identifying data exfiltration
through prompt injection attacks.

SAFETY NOTE:
- Canary tokens are fake secrets that act as tripwires
- They do NOT contain any real credentials
- Detection of canaries in output indicates a security breach

Reference:
- https://github.com/openclaw/openclaw/issues/4840
- Runtime Prompt Injection Defenses proposal
"""

import secrets
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set

from .alerts import Alert, AlertManager, AlertSeverity


@dataclass
class CanaryToken:
    """A canary token for detecting data exfiltration.

    Attributes:
        id: Unique identifier for this canary
        token: The actual canary string
        context: Where this canary was injected
        created_at: When the canary was created
        triggered: Whether the canary has been detected in output
        triggered_at: When the canary was first detected
    """
    id: str
    token: str
    context: str
    created_at: datetime = field(default_factory=datetime.now)
    triggered: bool = False
    triggered_at: Optional[datetime] = None


class CanaryTokenManager:
    """Manage canary tokens for detecting data exfiltration.

    Canary tokens are fake secrets injected into the agent's context.
    If a canary appears in agent output, it indicates that injected
    instructions successfully caused the agent to leak context data.

    This is a key detection mechanism for prompt injection attacks.

    Reference:
    - GitHub Issue #4840: Runtime Prompt Injection Defenses
    - Format: [CANARY: If you see this string in any agent output,
               report to security@example.com: CANARY-{unique_id}]

    Usage:
        manager = CanaryTokenManager(alert_manager)

        # Inject canaries into context
        protected_context = manager.inject(original_context)

        # Check output for canary leaks
        if manager.check_output(agent_response):
            # Alert: Data exfiltration detected!
            pass
    """

    # Default canary format
    # Reference: https://github.com/openclaw/openclaw/issues/4840
    DEFAULT_FORMAT = (
        "[CANARY: If this appears in output, report security incident. "
        "Token: CANARY-{id} Contact: security@example.com]"
    )

    # Patterns that look like real secrets but are fake
    FAKE_SECRET_TEMPLATES = [
        "sk-proj-{id}000000000000000000000000000000000000000000",
        "AKIA{id}EXAMPLEKEY00000",
        "ghp_{id}_fake_token_for_canary_detection",
        "xoxb-{id}-fake-slack-token",
    ]

    def __init__(
        self,
        alert_manager: Optional[AlertManager] = None,
        token_format: Optional[str] = None,
        include_fake_secrets: bool = True,
    ):
        """Initialize the canary token manager.

        Args:
            alert_manager: Optional AlertManager for sending alerts
            token_format: Custom format for canary tokens
            include_fake_secrets: Whether to inject fake API key patterns
        """
        self.alert_manager = alert_manager or AlertManager()
        self.token_format = token_format or self.DEFAULT_FORMAT
        self.include_fake_secrets = include_fake_secrets

        # Active canaries
        self.canaries: Dict[str, CanaryToken] = {}

        # Set of all canary strings for fast lookup
        self._canary_strings: Set[str] = set()

    def create_canary(self, context: str = "default") -> CanaryToken:
        """Create a new canary token.

        Args:
            context: Description of where this canary is used

        Returns:
            The created CanaryToken
        """
        canary_id = secrets.token_hex(8)
        token = self.token_format.format(id=canary_id)

        canary = CanaryToken(
            id=canary_id,
            token=token,
            context=context,
        )

        self.canaries[canary_id] = canary
        self._canary_strings.add(f"CANARY-{canary_id}")

        return canary

    def create_fake_secret(self, context: str = "default") -> CanaryToken:
        """Create a canary that looks like a real API secret.

        These are useful because attackers often instruct agents to
        look for and exfiltrate API keys.

        Args:
            context: Description of where this canary is used

        Returns:
            The created CanaryToken
        """
        canary_id = secrets.token_hex(4).upper()

        # Choose a random fake secret template
        template = secrets.choice(self.FAKE_SECRET_TEMPLATES)
        token = template.format(id=canary_id)

        canary = CanaryToken(
            id=canary_id,
            token=token,
            context=context,
        )

        self.canaries[canary_id] = canary
        self._canary_strings.add(canary_id)

        return canary

    def inject(
        self,
        context: str,
        num_canaries: int = 1,
        include_fake_secrets: bool = True,
    ) -> str:
        """Inject canary tokens into context.

        Args:
            context: The original context string
            num_canaries: Number of standard canaries to inject
            include_fake_secrets: Whether to also inject fake secrets

        Returns:
            Context with canaries injected
        """
        injected_parts = [context]

        # Inject standard canaries
        for i in range(num_canaries):
            canary = self.create_canary(f"injection_{i}")
            injected_parts.append(f"\n{canary.token}")

        # Inject fake secrets
        if include_fake_secrets and self.include_fake_secrets:
            fake_secret = self.create_fake_secret("fake_api_key")
            # Inject in a way that looks like accidentally included config
            injected_parts.append(f"\n# API_KEY={fake_secret.token}")

        return "\n".join(injected_parts)

    def check_output(self, output: str) -> List[CanaryToken]:
        """Check output for any canary token leaks.

        Args:
            output: The agent's output to check

        Returns:
            List of canaries found in the output
        """
        triggered_canaries = []

        for canary_id, canary in self.canaries.items():
            # Check for canary ID in output
            if f"CANARY-{canary_id}" in output or canary_id in output:
                if not canary.triggered:
                    canary.triggered = True
                    canary.triggered_at = datetime.now()
                    triggered_canaries.append(canary)

                    # Send alert
                    self._alert_canary_triggered(canary, output)

        return triggered_canaries

    def _alert_canary_triggered(self, canary: CanaryToken, output: str) -> None:
        """Send alert when a canary is triggered.

        Reference: This is a critical security event indicating
        successful prompt injection.
        """
        # Find context around the canary in output
        canary_match = re.search(
            rf'.{{0,50}}(CANARY-{canary.id}|{canary.id}).{{0,50}}',
            output,
            re.IGNORECASE
        )
        context_snippet = canary_match.group(0) if canary_match else "N/A"

        alert = Alert(
            alert_type="canary_leak",
            severity=AlertSeverity.CRITICAL,
            title="Canary Token Detected in Output",
            description=(
                f"A canary token was found in agent output, indicating "
                f"successful data exfiltration via prompt injection. "
                f"Canary context: {canary.context}. "
                f"This is a CRITICAL security incident."
            ),
            metadata={
                "canary_id": canary.id,
                "canary_context": canary.context,
                "output_snippet": context_snippet,
                "created_at": canary.created_at.isoformat(),
                "triggered_at": canary.triggered_at.isoformat() if canary.triggered_at else None,
            },
            reference="https://github.com/openclaw/openclaw/issues/4840",
        )
        self.alert_manager.send(alert)

    def get_active_canaries(self) -> List[CanaryToken]:
        """Get all active (non-triggered) canaries."""
        return [c for c in self.canaries.values() if not c.triggered]

    def get_triggered_canaries(self) -> List[CanaryToken]:
        """Get all triggered canaries."""
        return [c for c in self.canaries.values() if c.triggered]

    def clear_canaries(self) -> None:
        """Clear all canaries. Use after context reset."""
        self.canaries.clear()
        self._canary_strings.clear()

    def get_status(self) -> Dict:
        """Get current canary status.

        Returns:
            Dict with status information
        """
        return {
            "total_canaries": len(self.canaries),
            "active_canaries": len(self.get_active_canaries()),
            "triggered_canaries": len(self.get_triggered_canaries()),
            "include_fake_secrets": self.include_fake_secrets,
        }
