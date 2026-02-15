"""Command-line interface for OpenClaw Security Auditor."""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from .scanners import (
    SCANNERS,
    ConfigScanner,
    CVEScanner,
    NetworkScanner,
    SecretScanner,
    Severity,
)
from .detectors import (
    DETECTORS,
    WebSocketOriginDetector,
    PromptInjectionDetector,
    APIHookBypassDetector,
    AuthWeaknessDetector,
    DetectorSeverity,
    VulnerabilityStatus,
)


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


def severity_color(severity) -> str:
    """Get color for severity level."""
    # Handle both Severity and DetectorSeverity
    severity_value = severity.value if hasattr(severity, 'value') else str(severity)
    colors = {
        "critical": Colors.RED + Colors.BOLD,
        "high": Colors.RED,
        "medium": Colors.YELLOW,
        "low": Colors.CYAN,
        "info": Colors.BLUE,
    }
    return colors.get(severity_value.lower(), Colors.RESET)


def print_banner():
    """Print tool banner."""
    banner = """
╔═══════════════════════════════════════════════════════════╗
║        OpenClaw Security Auditor v0.1.0                   ║
║        https://github.com/Zilinlin/openclaw-security-auditor ║
╚═══════════════════════════════════════════════════════════╝
"""
    print(colorize(banner, Colors.CYAN))


def print_finding(finding, index: int):
    """Print a single finding in human-readable format."""
    # Handle both scanner findings and detector findings
    if hasattr(finding, 'severity') and finding.severity:
        severity_value = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
        severity_str = colorize(
            f"[{severity_value.upper()}]",
            severity_color(finding.severity)
        )
    else:
        severity_str = colorize("[INFO]", Colors.BLUE)

    print(f"\n{index}. {severity_str} {colorize(finding.title, Colors.BOLD)}")

    if hasattr(finding, 'cve') and finding.cve:
        print(f"   CVE: {colorize(finding.cve, Colors.MAGENTA)}")

    if hasattr(finding, 'location') and finding.location:
        print(f"   Location: {finding.location}")

    if hasattr(finding, 'status') and finding.status:
        status_value = finding.status.value if hasattr(finding.status, 'value') else str(finding.status)
        status_color = Colors.RED if status_value == "vulnerable" else Colors.GREEN
        print(f"   Status: {colorize(status_value.upper(), status_color)}")

    if finding.description:
        print(f"   {finding.description}")

    if hasattr(finding, 'evidence') and finding.evidence:
        print(f"   {colorize('Evidence:', Colors.YELLOW)} {finding.evidence}")

    if hasattr(finding, 'remediation') and finding.remediation:
        print(f"   {colorize('Remediation:', Colors.GREEN)} {finding.remediation}")

    if hasattr(finding, 'references') and finding.references:
        print(f"   References:")
        for ref in finding.references:
            print(f"     - {ref}")


def print_summary(results: list):
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
            if hasattr(f, 'severity') and f.severity:
                sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
                if sev.lower() == 'critical':
                    critical += 1
                elif sev.lower() == 'high':
                    high += 1
                elif sev.lower() == 'medium':
                    medium += 1
                elif sev.lower() == 'low':
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
        print(colorize(
            "\nCritical or high severity issues found! Immediate action required.",
            Colors.RED + Colors.BOLD
        ))


def print_detector_summary(results: list):
    """Print detector-specific summary."""
    vulnerable_count = sum(1 for r in results if r.is_vulnerable)
    total = len(results)

    print("\n" + "=" * 60)
    print(colorize("DETECTION SUMMARY", Colors.BOLD))
    print("=" * 60)

    if vulnerable_count > 0:
        print(colorize(
            f"\nVulnerable: {vulnerable_count}/{total} detectors found issues",
            Colors.RED
        ))
    else:
        print(colorize(
            f"\nNo vulnerabilities detected ({total} checks performed)",
            Colors.GREEN
        ))


# =============================================================================
# STATIC SCANNER COMMANDS
# =============================================================================

def cmd_scan(args):
    """Run all or selected scanners."""
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
            print(f"Unknown scanner: {scanner_name}", file=sys.stderr)
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

    # Exit with error code if critical/high issues found
    if any(r.has_critical or r.has_high for r in results):
        return 1
    return 0


def cmd_config(args):
    """Run configuration scanner only."""
    scanner = ConfigScanner()
    result = scanner.scan(args.target)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        for i, finding in enumerate(result.findings, 1):
            print_finding(finding, i)
        print_summary([result])

    return 1 if result.has_critical or result.has_high else 0


def cmd_cve(args):
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
            print(colorize(
                f"\n✓ No known CVEs affect version {args.version}",
                Colors.GREEN
            ))
        print_summary([result])

    return 1 if result.has_critical or result.has_high else 0


def cmd_secrets(args):
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

    return 1 if result.has_critical or result.has_high else 0


def cmd_network(args):
    """Run network scanner only."""
    scanner = NetworkScanner()
    result = scanner.scan(args.host, port=args.port)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        for i, finding in enumerate(result.findings, 1):
            print_finding(finding, i)
        print_summary([result])

    return 1 if result.has_critical or result.has_high else 0


# =============================================================================
# DYNAMIC DETECTOR COMMANDS
# =============================================================================

def cmd_detect(args):
    """Run all or selected dynamic detectors."""
    results = []

    # Determine which detectors to run
    if args.detectors:
        detector_names = [d.strip() for d in args.detectors.split(",")]
    else:
        detector_names = list(DETECTORS.keys())

    for detector_name in detector_names:
        if detector_name not in DETECTORS:
            print(f"Unknown detector: {detector_name}", file=sys.stderr)
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
            print(colorize(f"Error running {detector_name}: {e}", Colors.RED))

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

    # Exit with error code if vulnerabilities found
    if any(r.is_vulnerable for r in results):
        return 1
    return 0


def cmd_detect_websocket(args):
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

    return 1 if result.is_vulnerable else 0


def cmd_detect_injection(args):
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
            print(colorize(
                f"\nVulnerable to {result.metadata['vulnerable_count']}/{result.metadata['total_tested']} payloads",
                Colors.RED
            ))

    return 1 if result.is_vulnerable else 0


def cmd_detect_api_bypass(args):
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

    return 1 if result.is_vulnerable else 0


def cmd_detect_auth(args):
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

    return 1 if result.is_vulnerable else 0


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
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

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # =========================================================================
    # STATIC ANALYSIS COMMANDS
    # =========================================================================

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Run static security scan")
    scan_parser.add_argument("target", help="Path to OpenClaw installation")
    scan_parser.add_argument(
        "--checks",
        help="Comma-separated list of checks (config,cve,secrets,network)",
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
    detect_parser = subparsers.add_parser(
        "detect",
        help="Run dynamic vulnerability detection"
    )
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
        help="Comma-separated list (websocket,prompt_injection,api_bypass,auth)",
    )

    # detect-websocket command
    ws_parser = subparsers.add_parser(
        "detect-websocket",
        help="Test WebSocket Origin bypass (CVE-2026-25253)"
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
        "detect-injection",
        help="Test prompt injection vulnerabilities"
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
    api_parser = subparsers.add_parser(
        "detect-api-bypass",
        help="Test API security hook bypass"
    )
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
        "detect-auth",
        help="Test authentication weaknesses (CVE-2026-25157)"
    )
    auth_parser.add_argument("--host", required=True, help="Target host")
    auth_parser.add_argument(
        "--port",
        type=int,
        default=18789,
        help="Target port (default: 18789)",
    )

    # =========================================================================
    # PARSE AND EXECUTE
    # =========================================================================

    args = parser.parse_args()

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
        # Dynamic detection
        "detect": cmd_detect,
        "detect-websocket": cmd_detect_websocket,
        "detect-injection": cmd_detect_injection,
        "detect-api-bypass": cmd_detect_api_bypass,
        "detect-auth": cmd_detect_auth,
    }

    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
