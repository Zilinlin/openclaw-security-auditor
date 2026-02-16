"""Dynamic vulnerability detectors for OpenClaw."""

from .base import BaseDetector, DetectorResult, DetectorFinding, DetectorSeverity, VulnerabilityStatus
from .websocket_detector import WebSocketOriginDetector
from .prompt_injection_detector import PromptInjectionDetector
from .api_bypass_detector import APIHookBypassDetector
from .auth_detector import AuthWeaknessDetector

__all__ = [
    "BaseDetector",
    "DetectorResult",
    "DetectorFinding",
    "WebSocketOriginDetector",
    "PromptInjectionDetector",
    "APIHookBypassDetector",
    "AuthWeaknessDetector",
    "DetectorSeverity",
    "VulnerabilityStatus",
]

# Registry of available detectors
DETECTORS = {
    "websocket": WebSocketOriginDetector,
    "prompt_injection": PromptInjectionDetector,
    "api_bypass": APIHookBypassDetector,
    "auth": AuthWeaknessDetector,
}
