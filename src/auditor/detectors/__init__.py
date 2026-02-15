"""Dynamic vulnerability detectors for OpenClaw."""

from .base import BaseDetector, DetectorResult, DetectorFinding
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
]

# Registry of available detectors
DETECTORS = {
    "websocket": WebSocketOriginDetector,
    "prompt_injection": PromptInjectionDetector,
    "api_bypass": APIHookBypassDetector,
    "auth": AuthWeaknessDetector,
}
