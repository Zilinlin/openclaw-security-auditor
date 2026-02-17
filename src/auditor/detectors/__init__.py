"""Dynamic vulnerability detectors for OpenClaw."""

from .api_bypass_detector import APIHookBypassDetector
from .auth_detector import AuthWeaknessDetector
from .base import (
    BaseDetector,
    DetectorFinding,
    DetectorResult,
    DetectorSeverity,
    VulnerabilityStatus,
)
from .prompt_injection_detector import PromptInjectionDetector
from .websocket_detector import WebSocketOriginDetector

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
