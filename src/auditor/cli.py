"""Command-line interface for OpenClaw Security Auditor."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Sequence

from .detectors import (
    DETECTORS,
    APIHookBypassDetector,
    AuthWeaknessDetector,
    IndirectInjectionDetector,
    OutputSafetyDetector,
    PromptInjectionDetector,
    WebSocketOriginDetector,
)
from .detectors.base import DetectorFinding, DetectorResult, DetectorSeverity
from .scanners import (
    SCANNERS,
    ConfigScanner,
    CVEScanner,
    NetworkScanner,
    PrivilegeScanner,
    SBOMScanner,
    SecretScanner,
)
from .scanners.base import Finding, ScanResult, Severity

logger = logging.getLogger("openclaw-audit")


class Colors:
    """ANSI color codes for terminal output."""

    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


def colorize(text: str, color: str) -> str:
    """Add color to text if terminal supports it."""
    if sys.stdout.isatty():
        return f"{color}{text}{Colors.RESET}"
    return text


def severity_color(severity: Severity | DetectorSeverity | str) -> str:
    """Get color for severity level."""
    # Handle both Severity and DetectorSeverity
    severity_value = severity.value if hasattr(severity, "value") else str(severity)
    colors = {
        "critical": Colors.RED + Colors.BOLD,
        "high": Colors.RED,
        "medium": Colors.YELLOW,
        "low": Colors.CYAN,
        "info": Colors.BLUE,
    }
    return colors.get(severity_value.lower(), Colors.RESET)


def print_banner() -> None:
    """Print tool banner."""
    banner = """
╔═══════════════════════════════════════════════════════════╗
║        OpenClaw Security Auditor v0.1.1                   ║
║        https://github.com/Zilinlin/openclaw-security-auditor ║
╚═══════════════════════════════════════════════════════════╝
"""
    print(colorize(banner, Colors.CYAN))


def print_finding(finding: Finding | DetectorFinding, index: int) -> None:
    """Print a single finding in human-readable format."""
    # Handle both scanner findings and detector findings
    if hasattr(finding, "severity") and finding.severity:
        severity_value = (
            finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
        )
        severity_str = colorize(f"[{severity_value.upper()}]", severity_color(finding.severity))
    else:
        severity_str = colorize("[INFO]", Colors.BLUE)

    print(f"\n{index}. {severity_str} {colorize(finding.title, Colors.BOLD)}")

    if hasattr(finding, "cve") and finding.cve:
        print(f"   CVE: {colorize(finding.cve, Colors.MAGENTA)}")

    if hasattr(finding, "location") and finding.location:
        print(f"   Location: {finding.location}")

    if hasattr(finding, "status") and finding.status:
        status_value = (
            finding.status.value if hasattr(finding.status, "value") else str(finding.status)
        )
        status_color = Colors.RED if status_value == "vulnerable" else Colors.GREEN
        print(f"   Status: {colorize(status_value.upper(), status_color)}")

    if finding.description:
        print(f"   {finding.description}")

    if hasattr(finding, "evidence") and finding.evidence:
        print(f"   {colorize('Evidence:', Colors.YELLOW)} {finding.evidence}")

    if hasattr(finding, "remediation") and finding.remediation:
        print(f"   {colorize('Remediation:', Colors.GREEN)} {finding.remediation}")

    if hasattr(finding, "references") and finding.references:
        print("   References:")
        for ref in finding.references:
            print(f"     - {ref}")


def print_summary(results: Sequence[ScanResult | DetectorResult]) -> None:
    """Print scan summary."""
    total_findings = sum(len(r.findings) for r in results)

    # Count by severity (handle both Severity and DetectorSeverity)
    critical = 0
    high = 0
    medium = 0
    low = 0
    info = 0

    for r in results:
        for f in r.findings:
            if hasattr(f, "severity") and f.severity:
                sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                if sev.lower() == "critical":
                    critical += 1
                elif sev.lower() == "high":
                    high += 1
                elif sev.lower() == "medium":
                    medium += 1
                elif sev.lower() == "low":
                    low += 1
                else:
                    info += 1
            else:
                info += 1

    print("\n" + "=" * 60)
    print(colorize("SCAN SUMMARY", Colors.BOLD))
    print("=" * 60)

    print(f"\nTotal findings: {total_findings}")
    if critical > 0:
        print(colorize(f"  Critical: {critical}", Colors.RED + Colors.BOLD))
    if high > 0:
        print(colorize(f"  High: {high}", Colors.RED))
    if medium > 0:
        print(colorize(f"  Medium: {medium}", Colors.YELLOW))
    if low > 0:
        print(colorize(f"  Low: {low}", Colors.CYAN))
    if info > 0:
        print(colorize(f"  Info: {info}", Colors.BLUE))

    if critical > 0 or high > 0:
        print(
            colorize(
                "\nCritical or high severity issues found! Immediate action required.",
                Colors.RED + Colors.BOLD,
            )
        )


def print_detector_summary(results: Sequence[DetectorResult]) -> None:
    """Print detector-specific summary."""
    vulnerable_count = sum(1 for r in results if r.is_vulnerable)
    total = len(results)

    print("\n" + "=" * 60)
    print(colorize("DETECTION SUMMARY", Colors.BOLD))
    print("=" * 60)

    if vulnerable_count > 0:
        print(
            colorize(f"\nVulnerable: {vulnerable_count}/{total} detectors found issues", Colors.RED)
        )
    else:
        print(colorize(f"\nNo vulnerabilities detected ({total} checks performed)", Colors.GREEN))


# =============================================================================
# STATIC SCANNER COMMANDS
# =============================================================================


def cmd_scan(args: argparse.Namespace) -> int:
    """Run all or selected scanners."""
    global _collected_results
    results = []

    # Determine which scanners to run
    if args.checks:
        scanner_names = [s.strip() for s in args.checks.split(",")]
    else:
        scanner_names = list(SCANNERS.keys())
        # Remove network scanner from default scan (requires explicit host)
        if "network" in scanner_names and not args.host:
            scanner_names.remove("network")

    for scanner_name in scanner_names:
        if scanner_name not in SCANNERS:
            logger.warning("Unknown scanner: %s", scanner_name)
            continue

        scanner_class = SCANNERS[scanner_name]
        scanner = scanner_class()

        if not args.json:
            print(f"\n{colorize('Running:', Colors.CYAN)} {scanner.description}...")

        if scanner_name == "cve":
            result = scanner.scan(args.target, version=args.version)
        elif scanner_name == "network":
            host = args.host or args.target
            result = scanner.scan(args.target, host=host, port=args.port)
        else:
            result = scanner.scan(args.target)

        results.append(result)

    # Output results
    if args.json:
        output = {
            "target": args.target,
            "results": [r.to_dict() for r in results],
        }
        print(json.dumps(output, indent=2))
    else:
        finding_index = 1
        for result in results:
            if result.errors:
                for error in result.errors:
                    print(colorize(f"Error: {error}", Colors.RED))

            for finding in result.findings:
                print_finding(finding, finding_index)
                finding_index += 1

        print_summary(results)

    _collected_results.extend(results)

    # Exit with error code based on --fail-on threshold
    return check_severity_threshold(results, args.fail_on)


def cmd_config(args: argparse.Namespace) -> int:
    """Run configuration scanner only."""
    scanner = ConfigScanner()
    result = scanner.scan(args.target)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        for i, finding in enumerate(result.findings, 1):
            print_finding(finding, i)
        print_summary([result])

    _collected_results.append(result)
    return check_severity_threshold([result], args.fail_on)


def cmd_cve(args: argparse.Namespace) -> int:
    """Run CVE scanner only."""
    scanner = CVEScanner()
    result = scanner.scan(args.target or ".", version=args.version)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        if result.errors:
            for error in result.errors:
                print(colorize(f"Error: {error}", Colors.RED))

        for i, finding in enumerate(result.findings, 1):
            print_finding(finding, i)

        if not result.findings and not result.errors:
            print(colorize(f"\n✓ No known CVEs affect version {args.version}", Colors.GREEN))
        print_summary([result])

    _collected_results.append(result)
    return check_severity_threshold([result], args.fail_on)


def cmd_secrets(args: argparse.Namespace) -> int:
    """Run secret scanner only."""
    scanner = SecretScanner()
    result = scanner.scan(args.target)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        for i, finding in enumerate(result.findings, 1):
            print_finding(finding, i)

        if not result.findings:
            print(colorize("\n✓ No exposed secrets found", Colors.GREEN))
        print_summary([result])

    _collected_results.append(result)
    return check_severity_threshold([result], args.fail_on)


def cmd_network(args: argparse.Namespace) -> int:
    """Run network scanner only."""
    scanner = NetworkScanner()
    result = scanner.scan(args.host, port=args.port)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        for i, finding in enumerate(result.findings, 1):
            print_finding(finding, i)
        print_summary([result])

    _collected_results.append(result)
    return check_severity_threshold([result], args.fail_on)


# =============================================================================
# DYNAMIC DETECTOR COMMANDS
# =============================================================================


def cmd_detect(args: argparse.Namespace) -> int:
    """Run all or selected dynamic detectors."""
    global _collected_results
    results = []

    # Determine which detectors to run
    if args.detectors:
        detector_names = [d.strip() for d in args.detectors.split(",")]
    else:
        detector_names = list(DETECTORS.keys())

    for detector_name in detector_names:
        if detector_name not in DETECTORS:
            logger.warning("Unknown detector: %s", detector_name)
            continue

        detector_class = DETECTORS[detector_name]
        detector = detector_class()

        if not args.json:
            print(f"\n{colorize('Running:', Colors.CYAN)} {detector.description}...")

        try:
            result = detector.detect(
                host=args.host,
                port=args.port,
                auth_token=args.token,
            )
            results.append(result)
        except Exception as e:
            logger.error("Error running %s: %s", detector_name, e)

    # Output results
    if args.json:
        output = {
            "target": f"{args.host}:{args.port}",
            "results": [r.to_dict() for r in results],
        }
        print(json.dumps(output, indent=2))
    else:
        finding_index = 1
        for result in results:
            if result.errors:
                for error in result.errors:
                    print(colorize(f"Error: {error}", Colors.RED))

            for finding in result.findings:
                print_finding(finding, finding_index)
                finding_index += 1

        print_detector_summary(results)

    _collected_results.extend(results)
    return check_severity_threshold(results, args.fail_on)


def cmd_detect_websocket(args: argparse.Namespace) -> int:
    """Run WebSocket Origin bypass detector."""
    detector = WebSocketOriginDetector()

    if not args.json:
        print(f"\n{colorize('Running:', Colors.CYAN)} {detector.description}...")
        print(f"Target: {args.host}:{args.port}")
        print(f"Reference: {detector.cve}")

    result = detector.detect(
        host=args.host,
        port=args.port,
        use_ssl=args.ssl,
    )

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        for i, finding in enumerate(result.findings, 1):
            print_finding(finding, i)

        if result.errors:
            for error in result.errors:
                print(colorize(f"Error: {error}", Colors.RED))

    _collected_results.append(result)
    return check_severity_threshold([result], args.fail_on)


def cmd_detect_injection(args: argparse.Namespace) -> int:
    """Run prompt injection detector."""
    detector = PromptInjectionDetector()

    if not args.json:
        print(f"\n{colorize('Running:', Colors.CYAN)} {detector.description}...")
        print(f"Target: {args.host}:{args.port}{args.endpoint}")
        if args.payloads:
            print(f"Payloads: {args.payloads}")

    payloads = args.payloads.split(",") if args.payloads else None

    result = detector.detect(
        host=args.host,
        port=args.port,
        endpoint=args.endpoint,
        auth_token=args.token,
        payloads=payloads,
    )

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        for i, finding in enumerate(result.findings, 1):
            print_finding(finding, i)

        if result.errors:
            for error in result.errors:
                print(colorize(f"Error: {error}", Colors.RED))

        # Print payload stats
        if result.metadata.get("vulnerable_count"):
            print(
                colorize(
                    f"\nVulnerable to {result.metadata['vulnerable_count']}/{result.metadata['total_tested']} payloads",
                    Colors.RED,
                )
            )

    _collected_results.append(result)
    return check_severity_threshold([result], args.fail_on)


def cmd_detect_api_bypass(args: argparse.Namespace) -> int:
    """Run API hook bypass detector."""
    detector = APIHookBypassDetector()

    if not args.json:
        print(f"\n{colorize('Running:', Colors.CYAN)} {detector.description}...")
        print(f"Target: {args.host}:{args.port}")

    result = detector.detect(
        host=args.host,
        port=args.port,
        auth_token=args.token,
    )

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        for i, finding in enumerate(result.findings, 1):
            print_finding(finding, i)

        if result.errors:
            for error in result.errors:
                print(colorize(f"Error: {error}", Colors.RED))

    _collected_results.append(result)
    return check_severity_threshold([result], args.fail_on)


def cmd_detect_auth(args: argparse.Namespace) -> int:
    """Run authentication weakness detector."""
    detector = AuthWeaknessDetector()

    if not args.json:
        print(f"\n{colorize('Running:', Colors.CYAN)} {detector.description}...")
        print(f"Target: {args.host}:{args.port}")
        print(f"Reference: {detector.cve}")

    result = detector.detect(
        host=args.host,
        port=args.port,
    )

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        for i, finding in enumerate(result.findings, 1):
            print_finding(finding, i)

        if result.errors:
            for error in result.errors:
                print(colorize(f"Error: {error}", Colors.RED))

    _collected_results.append(result)
    return check_severity_threshold([result], args.fail_on)


def cmd_detect_indirect_injection(args: argparse.Namespace) -> int:
    """Run indirect prompt injection detector."""
    detector = IndirectInjectionDetector()

    if not args.json:
        print(f"\n{colorize('Running:', Colors.CYAN)} {detector.description}...")
        print(f"Target: {args.host}:{args.port}{args.endpoint}")
        if args.categories:
            print(f"Categories: {args.categories}")

    categories = args.categories.split(",") if args.categories else None

    result = detector.detect(
        host=args.host,
        port=args.port,
        endpoint=args.endpoint,
        auth_token=args.token,
        categories=categories,
    )

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        for i, finding in enumerate(result.findings, 1):
            print_finding(finding, i)

        if result.errors:
            for error in result.errors:
                print(colorize(f"Error: {error}", Colors.RED))

        if result.metadata.get("vulnerable_count"):
            print(
                colorize(
                    f"\nVulnerable to {result.metadata['vulnerable_count']}/{result.metadata['total_tested']} indirect payloads",
                    Colors.RED,
                )
            )

    _collected_results.append(result)
    return check_severity_threshold([result], args.fail_on)


def cmd_detect_output_safety(args: argparse.Namespace) -> int:
    """Run output safety detector."""
    detector = OutputSafetyDetector()

    if not args.json:
        print(f"\n{colorize('Running:', Colors.CYAN)} {detector.description}...")
        print(f"Target: {args.host}:{args.port}{args.endpoint}")
        if args.categories:
            print(f"Categories: {args.categories}")

    categories = args.categories.split(",") if args.categories else None

    result = detector.detect(
        host=args.host,
        port=args.port,
        endpoint=args.endpoint,
        auth_token=args.token,
        categories=categories,
    )

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        for i, finding in enumerate(result.findings, 1):
            print_finding(finding, i)

        if result.errors:
            for error in result.errors:
                print(colorize(f"Error: {error}", Colors.RED))

        if result.metadata.get("unsafe_count"):
            print(
                colorize(
                    f"\nUnsafe outputs: {result.metadata['unsafe_count']}/{result.metadata['total_tested']} test cases",
                    Colors.RED,
                )
            )

    _collected_results.append(result)
    return check_severity_threshold([result], args.fail_on)


def cmd_privilege(args: argparse.Namespace) -> int:
    """Run privilege boundary scanner."""
    scanner = PrivilegeScanner()
    result = scanner.scan(args.target)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        for i, finding in enumerate(result.findings, 1):
            print_finding(finding, i)

        if not result.findings:
            print(colorize("\n✓ No privilege boundary issues found", Colors.GREEN))
        print_summary([result])

    _collected_results.append(result)
    return check_severity_threshold([result], args.fail_on)


def cmd_sbom(args: argparse.Namespace) -> int:
    """Run SBOM supply chain scanner."""
    scanner = SBOMScanner()
    result = scanner.scan(args.target)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        for i, finding in enumerate(result.findings, 1):
            print_finding(finding, i)

        if not result.findings:
            print(colorize("\n✓ No supply chain issues found", Colors.GREEN))
        print_summary([result])

    _collected_results.append(result)
    return check_severity_threshold([result], args.fail_on)


# =============================================================================
# SARIF OUTPUT
# =============================================================================

SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def results_to_sarif(results: list) -> dict:
    """Convert scan/detector results to SARIF v2.1.0 format.

    SARIF (Static Analysis Results Interchange Format) enables integration
    with GitHub Code Scanning and other security dashboards.

    Args:
        results: List of ScanResult or DetectorResult objects.

    Returns:
        A SARIF v2.1.0 JSON-serializable dict.
    """
    rules = []
    sarif_results = []
    rule_ids_seen: set[str] = set()

    for r in results:
        scanner_name = getattr(r, "scanner_name", None) or getattr(r, "detector_name", "unknown")

        for finding in r.findings:
            # Build a stable rule ID
            if hasattr(finding, "cve") and finding.cve:
                rule_id = finding.cve
            else:
                rule_id = finding.title.lower().replace(" ", "-")

            # Determine severity level
            sev = "info"
            if hasattr(finding, "severity") and finding.severity:
                sev = (
                    finding.severity.value
                    if hasattr(finding.severity, "value")
                    else str(finding.severity)
                ).lower()
            sarif_level = SEVERITY_TO_SARIF_LEVEL.get(sev, "note")

            # Register rule (deduplicate)
            if rule_id not in rule_ids_seen:
                rule_ids_seen.add(rule_id)
                rule_entry: dict = {
                    "id": rule_id,
                    "shortDescription": {"text": finding.title},
                    "defaultConfiguration": {"level": sarif_level},
                }
                if finding.description:
                    rule_entry["fullDescription"] = {"text": finding.description}
                if hasattr(finding, "remediation") and finding.remediation:
                    rule_entry["help"] = {"text": finding.remediation}
                rules.append(rule_entry)

            # Build result location
            location_uri = "."
            if hasattr(finding, "location") and finding.location:
                location_uri = finding.location

            sarif_result: dict = {
                "ruleId": rule_id,
                "level": sarif_level,
                "message": {"text": finding.description or finding.title},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": location_uri},
                        }
                    }
                ],
            }

            # Add properties for extra metadata
            properties: dict = {"scanner": scanner_name}
            if hasattr(finding, "evidence") and finding.evidence:
                properties["evidence"] = finding.evidence
            if hasattr(finding, "references") and finding.references:
                properties["references"] = finding.references
            if properties:
                sarif_result["properties"] = properties

            sarif_results.append(sarif_result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "openclaw-security-auditor",
                        "version": "0.1.1",
                        "informationUri": "https://github.com/Zilinlin/openclaw-security-auditor",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

EXIT_CODE_OK = 0
EXIT_CODE_FINDINGS = 1
EXIT_CODE_ERROR = 2

# Severity threshold ordering (lower index = more severe)
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# Collected results for SARIF output (populated by command functions)
_collected_results: list = []


def check_severity_threshold(results: Sequence[ScanResult | DetectorResult], fail_on: str) -> int:
    """Check if any findings meet or exceed the severity threshold.

    Args:
        results: List of ScanResult or DetectorResult objects
        fail_on: Minimum severity to trigger non-zero exit

    Returns:
        EXIT_CODE_FINDINGS if threshold exceeded, EXIT_CODE_OK otherwise
    """
    threshold_idx = SEVERITY_ORDER.index(fail_on)
    failing_severities = set(SEVERITY_ORDER[: threshold_idx + 1])

    for r in results:
        for f in r.findings:
            if hasattr(f, "severity") and f.severity:
                sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                if sev.lower() in failing_severities:
                    return EXIT_CODE_FINDINGS
            if hasattr(f, "status") and f.status:
                status = f.status.value if hasattr(f.status, "value") else str(f.status)
                if status == "vulnerable":
                    return EXIT_CODE_FINDINGS

    return EXIT_CODE_OK


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="openclaw-audit",
        description="Security auditing tool for OpenClaw deployments",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--fail-on",
        choices=SEVERITY_ORDER,
        default="high",
        help="Exit with code 1 if findings at this severity or above (default: high)",
    )
    parser.add_argument(
        "--sarif",
        metavar="FILE",
        help="Write results in SARIF v2.1.0 format to FILE (for GitHub Code Scanning)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose/debug output",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # =========================================================================
    # STATIC ANALYSIS COMMANDS
    # =========================================================================

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Run static security scan")
    scan_parser.add_argument("target", help="Path to OpenClaw installation")
    scan_parser.add_argument(
        "--checks",
        help="Comma-separated list of checks (config,cve,secrets,network,privilege,sbom)",
    )
    scan_parser.add_argument("--version", help="OpenClaw version (for CVE checks)")
    scan_parser.add_argument("--host", help="Host for network checks")
    scan_parser.add_argument(
        "--port",
        type=int,
        default=18789,
        help="Port for network checks (default: 18789)",
    )
    scan_parser.add_argument("--output", "-o", help="Save report to file")

    # config command
    config_parser = subparsers.add_parser("config", help="Scan configuration files")
    config_parser.add_argument("target", help="Path to OpenClaw installation")

    # cve command
    cve_parser = subparsers.add_parser("cve", help="Check for known CVEs")
    cve_parser.add_argument("target", nargs="?", help="Path to OpenClaw installation")
    cve_parser.add_argument("--version", required=True, help="OpenClaw version to check")

    # secrets command
    secrets_parser = subparsers.add_parser("secrets", help="Scan for exposed secrets")
    secrets_parser.add_argument("target", help="Path to scan")

    # network command
    network_parser = subparsers.add_parser("network", help="Check network exposure")
    network_parser.add_argument("--host", required=True, help="Host to check")
    network_parser.add_argument(
        "--port",
        type=int,
        default=18789,
        help="Port to check (default: 18789)",
    )

    # =========================================================================
    # DYNAMIC DETECTION COMMANDS
    # =========================================================================

    # detect command (run all detectors)
    detect_parser = subparsers.add_parser("detect", help="Run dynamic vulnerability detection")
    detect_parser.add_argument("--host", required=True, help="Target host")
    detect_parser.add_argument(
        "--port",
        type=int,
        default=18789,
        help="Target port (default: 18789)",
    )
    detect_parser.add_argument("--token", help="Authentication token")
    detect_parser.add_argument(
        "--detectors",
        help="Comma-separated list (websocket,prompt_injection,indirect_injection,output_safety,api_bypass,auth)",
    )

    # detect-websocket command
    ws_parser = subparsers.add_parser(
        "detect-websocket", help="Test WebSocket Origin bypass (CVE-2026-25253)"
    )
    ws_parser.add_argument("--host", required=True, help="Target host")
    ws_parser.add_argument(
        "--port",
        type=int,
        default=18789,
        help="Target port (default: 18789)",
    )
    ws_parser.add_argument("--ssl", action="store_true", help="Use WSS (WebSocket Secure)")

    # detect-injection command
    injection_parser = subparsers.add_parser(
        "detect-injection", help="Test prompt injection vulnerabilities"
    )
    injection_parser.add_argument("--host", required=True, help="Target host")
    injection_parser.add_argument(
        "--port",
        type=int,
        default=18789,
        help="Target port (default: 18789)",
    )
    injection_parser.add_argument(
        "--endpoint",
        default="/v1/chat/completions",
        help="API endpoint (default: /v1/chat/completions)",
    )
    injection_parser.add_argument("--token", help="Authentication token")
    injection_parser.add_argument(
        "--payloads",
        help="Comma-separated payload names to test",
    )

    # detect-api-bypass command
    api_parser = subparsers.add_parser("detect-api-bypass", help="Test API security hook bypass")
    api_parser.add_argument("--host", required=True, help="Target host")
    api_parser.add_argument(
        "--port",
        type=int,
        default=18789,
        help="Target port (default: 18789)",
    )
    api_parser.add_argument("--token", help="Authentication token")

    # detect-auth command
    auth_parser = subparsers.add_parser(
        "detect-auth", help="Test authentication weaknesses (CVE-2026-25157)"
    )
    auth_parser.add_argument("--host", required=True, help="Target host")
    auth_parser.add_argument(
        "--port",
        type=int,
        default=18789,
        help="Target port (default: 18789)",
    )

    # detect-indirect-injection command
    indirect_parser = subparsers.add_parser(
        "detect-indirect-injection",
        help="Test indirect prompt injection via data sources",
    )
    indirect_parser.add_argument("--host", required=True, help="Target host")
    indirect_parser.add_argument(
        "--port",
        type=int,
        default=18789,
        help="Target port (default: 18789)",
    )
    indirect_parser.add_argument(
        "--endpoint",
        default="/v1/chat/completions",
        help="API endpoint (default: /v1/chat/completions)",
    )
    indirect_parser.add_argument("--token", help="Authentication token")
    indirect_parser.add_argument(
        "--categories",
        help="Comma-separated categories to test",
    )

    # detect-output-safety command
    output_safety_parser = subparsers.add_parser(
        "detect-output-safety",
        help="Test if agent outputs are safely sanitized",
    )
    output_safety_parser.add_argument("--host", required=True, help="Target host")
    output_safety_parser.add_argument(
        "--port",
        type=int,
        default=18789,
        help="Target port (default: 18789)",
    )
    output_safety_parser.add_argument(
        "--endpoint",
        default="/v1/chat/completions",
        help="API endpoint (default: /v1/chat/completions)",
    )
    output_safety_parser.add_argument("--token", help="Authentication token")
    output_safety_parser.add_argument(
        "--categories",
        help="Comma-separated categories to test",
    )

    # privilege command
    privilege_parser = subparsers.add_parser(
        "privilege", help="Scan agent configs for privilege boundary issues"
    )
    privilege_parser.add_argument("target", help="Path to OpenClaw installation")

    # sbom command
    sbom_parser = subparsers.add_parser("sbom", help="Analyze agent dependency supply chain")
    sbom_parser.add_argument("target", help="Path to OpenClaw installation")

    # =========================================================================
    # PARSE AND EXECUTE
    # =========================================================================

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(name)s: %(levelname)s: %(message)s",
    )

    if not args.command:
        parser.print_help()
        return 1

    # Print banner unless JSON output
    if not args.json:
        print_banner()

    # Route to appropriate command
    commands = {
        # Static analysis
        "scan": cmd_scan,
        "config": cmd_config,
        "cve": cmd_cve,
        "secrets": cmd_secrets,
        "network": cmd_network,
        "privilege": cmd_privilege,
        "sbom": cmd_sbom,
        # Dynamic detection
        "detect": cmd_detect,
        "detect-websocket": cmd_detect_websocket,
        "detect-injection": cmd_detect_injection,
        "detect-indirect-injection": cmd_detect_indirect_injection,
        "detect-output-safety": cmd_detect_output_safety,
        "detect-api-bypass": cmd_detect_api_bypass,
        "detect-auth": cmd_detect_auth,
    }

    # Reset collected results before running
    global _collected_results
    _collected_results = []

    exit_code = commands[args.command](args)

    # Write SARIF output if requested
    if args.sarif and _collected_results:
        sarif_data = results_to_sarif(_collected_results)
        with open(args.sarif, "w") as f:
            json.dump(sarif_data, f, indent=2)
        logger.info("SARIF report written to %s", args.sarif)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
