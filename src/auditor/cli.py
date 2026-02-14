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


def severity_color(severity: Severity) -> str:
    """Get color for severity level."""
    colors = {
        Severity.CRITICAL: Colors.RED + Colors.BOLD,
        Severity.HIGH: Colors.RED,
        Severity.MEDIUM: Colors.YELLOW,
        Severity.LOW: Colors.CYAN,
        Severity.INFO: Colors.BLUE,
    }
    return colors.get(severity, Colors.RESET)


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
    severity_str = colorize(
        f"[{finding.severity.value.upper()}]",
        severity_color(finding.severity)
    )

    print(f"\n{index}. {severity_str} {colorize(finding.title, Colors.BOLD)}")

    if finding.cve:
        print(f"   CVE: {colorize(finding.cve, Colors.MAGENTA)}")

    if finding.location:
        print(f"   Location: {finding.location}")

    print(f"   {finding.description}")

    if finding.remediation:
        print(f"   {colorize('Remediation:', Colors.GREEN)} {finding.remediation}")

    if finding.references:
        print(f"   References:")
        for ref in finding.references:
            print(f"     - {ref}")


def print_summary(results: list):
    """Print scan summary."""
    total_findings = sum(len(r.findings) for r in results)
    critical = sum(
        sum(1 for f in r.findings if f.severity == Severity.CRITICAL)
        for r in results
    )
    high = sum(
        sum(1 for f in r.findings if f.severity == Severity.HIGH)
        for r in results
    )
    medium = sum(
        sum(1 for f in r.findings if f.severity == Severity.MEDIUM)
        for r in results
    )
    low = sum(
        sum(1 for f in r.findings if f.severity == Severity.LOW)
        for r in results
    )
    info = sum(
        sum(1 for f in r.findings if f.severity == Severity.INFO)
        for r in results
    )

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
            "\n⚠️  Critical or high severity issues found! Immediate action required.",
            Colors.RED + Colors.BOLD
        ))


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

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Run security scan")
    scan_parser.add_argument("target", help="Path to OpenClaw installation")
    scan_parser.add_argument(
        "--checks",
        help="Comma-separated list of checks to run (config,cve,secrets,network)",
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
    config_parser.add_argument("target", help="Path to OpenClaw installation or config file")

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

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Print banner unless JSON output
    if not args.json:
        print_banner()

    # Route to appropriate command
    commands = {
        "scan": cmd_scan,
        "config": cmd_config,
        "cve": cmd_cve,
        "secrets": cmd_secrets,
        "network": cmd_network,
    }

    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
