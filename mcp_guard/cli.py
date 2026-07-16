#!/usr/bin/env python3
"""mcp-guard CLI — Security audit for MCP configurations.

Usage:
    mcp-guard scan              # Scan all found MCP configs
    mcp-guard scan --path PATH  # Scan a specific file
    mcp-guard scan --json       # Output as JSON (for CI/CD)
    mcp-guard scan --ci         # Exit non-zero if critical issues found
    mcp-guard rules             # List all security rules
    mcp-guard version           # Show version
"""

import json
import sys
from pathlib import Path

from . import __version__
from .scanner import scan_all, scan_file
from .rules import ALL_RULES, KNOWN_CVES


# ── Terminal Colors ────────────────────────────────────

class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @staticmethod
    def disable():
        for attr in dir(Colors):
            if not attr.startswith("_") and attr.isupper() and attr != "RESET":
                setattr(Colors, attr, "")


def _severity_icon(severity: str) -> str:
    icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
    return icons.get(severity, "⚪")


def _severity_label(severity: str) -> str:
    labels = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}
    return labels.get(severity, "UNKNOWN")


def _grade_color(grade: str) -> str:
    gc = {"A": Colors.GREEN, "B": Colors.CYAN, "C": Colors.YELLOW, "D": Colors.RED, "F": Colors.RED + Colors.BOLD}
    return gc.get(grade, Colors.RESET)


# ── Commands ───────────────────────────────────────────

def cmd_scan(args: list[str]):
    """Scan MCP configurations for security issues."""
    paths = []
    output_json = False
    ci_mode = False

    # Parse args
    i = 0
    while i < len(args):
        if args[i] in ("--path", "-p") and i + 1 < len(args):
            paths.append(args[i + 1])
            i += 2
        elif args[i] == "--json":
            output_json = True
            i += 1
        elif args[i] == "--ci":
            ci_mode = True
            i += 1
        elif args[i] == "--no-color":
            Colors.disable()
            i += 1
        else:
            i += 1

    # Scan
    if paths:
        results = []
        for p in paths:
            r = scan_file(Path(p).expanduser().resolve())
            if r:
                results.append(r)
            else:
                print(f"mcp-guard: could not parse: {p}", file=sys.stderr)
    else:
        results = scan_all()

    if not results:
        print("mcp-guard: no MCP configuration files found.")
        print("  Specify a path: mcp-guard scan --path ~/.cursor/mcp.json")
        sys.exit(0)

    if output_json:
        _output_json(results)
    else:
        _output_pretty(results)

    # CI mode: exit non-zero if critical/high issues
    if ci_mode:
        total_critical = sum(r.critical_count + r.high_count for r in results)
        if total_critical > 0:
            sys.exit(1)
    sys.exit(0)


def _output_pretty(results):
    """Human-readable terminal output."""
    total_findings = sum(len(r.findings) for r in results)
    total_critical = sum(r.critical_count for r in results)
    total_high = sum(r.high_count for r in results)
    total_servers = sum(r.total_servers for r in results)

    print()
    print(f"  {Colors.BOLD}{Colors.CYAN}╔══════════════════════════════════════╗{Colors.RESET}")
    print(f"  {Colors.BOLD}{Colors.CYAN}║       MCP GUARD — Security Audit     ║{Colors.RESET}")
    print(f"  {Colors.BOLD}{Colors.CYAN}╚══════════════════════════════════════╝{Colors.RESET}")
    print()

    for result in results:
        grade_color = _grade_color(result.grade)
        print(f"  {Colors.BOLD}📄 {result.file_path}{Colors.RESET}")
        print(f"     Servers: {result.total_servers}  |  "
              f"Findings: {Colors.RED}{result.critical_count} critical{Colors.RESET}, "
              f"{Colors.YELLOW}{result.high_count} high{Colors.RESET}, "
              f"{len(result.findings) - result.critical_count - result.high_count} other  |  "
              f"Score: {grade_color}{result.score}/100 ({result.grade}){Colors.RESET}")
        print()

        if not result.findings:
            print(f"  {Colors.GREEN}✅ No issues found.{Colors.RESET}")
            print()
            continue

        for finding in result.findings:
            icon = _severity_icon(finding.severity)
            label = _severity_label(finding.severity)
            print(f"  {icon} {Colors.BOLD}[{label}]{Colors.RESET} {finding.title}")
            print(f"     {Colors.DIM}{finding.location}{Colors.RESET}")
            print(f"     {finding.description}")
            print(f"     {Colors.GREEN}Fix: {finding.remediation}{Colors.RESET}")
            if finding.cve_id:
                print(f"     {Colors.RED}CVE: {finding.cve_id}{Colors.RESET}")
            print()

    # Summary
    print(f"  {Colors.BOLD}{'─' * 40}{Colors.RESET}")
    print(f"  Files scanned:  {len(results)}")
    print(f"  Total servers:  {total_servers}")
    print(f"  Total findings: {total_findings}")
    if total_critical > 0:
        print(f"  {Colors.RED}  {total_critical} CRITICAL{Colors.RESET}")
    if total_high > 0:
        print(f"  {Colors.YELLOW}  {total_high} HIGH{Colors.RESET}")
    print(f"  {'─' * 40}")
    print()

    if total_critical > 0:
        print(f"  {Colors.RED}{Colors.BOLD}⚠️  CRITICAL ISSUES FOUND — fix immediately{Colors.RESET}")
    elif total_high > 0:
        print(f"  {Colors.YELLOW}⚠️  High-severity issues found — fix soon{Colors.RESET}")
    else:
        print(f"  {Colors.GREEN}✅ No critical or high-severity issues{Colors.RESET}")
    print()


def _output_json(results):
    """Machine-readable JSON output."""
    output = {
        "scanned_at": None,  # Could add timestamp
        "total_files": len(results),
        "total_servers": sum(r.total_servers for r in results),
        "total_findings": sum(len(r.findings) for r in results),
        "files": []
    }
    for result in results:
        output["files"].append({
            "path": result.file_path,
            "servers": result.total_servers,
            "score": result.score,
            "grade": result.grade,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "location": f.location,
                    "remediation": f.remediation,
                    "cve_id": f.cve_id,
                }
                for f in result.findings
            ]
        })
    print(json.dumps(output, indent=2))


def cmd_rules():
    """List all security rules."""
    print(f"\n  {Colors.BOLD}MCP Guard — Security Rules{Colors.RESET}\n")
    print(f"  {Colors.DIM}Known CVEs tracked: {len(KNOWN_CVES)}{Colors.RESET}")
    print(f"  {Colors.DIM}API key patterns detected: {len(__import__('mcp_guard.rules').API_KEY_PATTERNS)}{Colors.RESET}")
    print(f"  {Colors.DIM}Rules loaded: {len(ALL_RULES)}{Colors.RESET}")
    print()

    rule_descriptions = [
        ("HARDCODED-KEY", "critical", "Detect hardcoded API keys, tokens, and secrets in config files"),
        ("EXCESSIVE-FS-ACCESS", "high", "Flag MCP servers with overly broad filesystem permissions"),
        ("INSECURE-TRANSPORT", "medium", "Warn about MCP servers using HTTP without TLS"),
        ("SUSPICIOUS-SOURCE", "high", "Flag MCP servers from untrusted or unverifiable sources"),
        ("UNPINNED-VERSION", "medium", "Warn about npx packages without pinned versions"),
        ("KNOWN-CVE", "critical", "Check MCP server versions against known CVE database"),
        ("ENV-SECRET-EXPOSED", "high", "Detect secrets in environment variable blocks"),
        ("MISSING-ENV-VAR", "low", "Flag referenced environment variables not declared in config"),
    ]

    for rule_id, severity, desc in rule_descriptions:
        icon = _severity_icon(severity)
        print(f"  {icon} [{severity.upper()}] {Colors.BOLD}{rule_id}{Colors.RESET}")
        print(f"     {desc}")
        print()


def cmd_fix(args: list[str]):
    """Auto-fix security issues in MCP configurations."""
    from .fixer import fix_all, fix_file

    dry_run = "--dry-run" in args or "-n" in args
    paths = []
    i = 0
    while i < len(args):
        if args[i] in ("--path", "-p") and i + 1 < len(args):
            paths.append(args[i + 1])
            i += 2
        elif args[i] in ("--no-color",):
            Colors.disable()
            i += 1
        else:
            i += 1

    if paths:
        for p in paths:
            file_path = Path(p).expanduser().resolve()
            if not file_path.exists():
                print(f"mcp-guard: file not found: {p}")
                continue
            result = fix_file(file_path, dry_run=dry_run)
            _print_fix_result(result, dry_run)
    else:
        results = fix_all(dry_run=dry_run)
        if not results:
            print(f"{Colors.GREEN}✅ No fixable issues found.{Colors.RESET}")
            return
        for result in results:
            _print_fix_result(result, dry_run)


def _print_fix_result(result: dict, dry_run: bool):
    file_path = result.get("file", "unknown")
    fixed = result.get("fixed_count", 0)
    skipped = result.get("skipped_count", 0)
    backup = result.get("backup_path", "")
    changes = result.get("changes", [])
    preview = result.get("preview", "")

    print()
    print(f"  {Colors.BOLD}📄 {file_path}{Colors.RESET}")
    print(f"  Fixed: {Colors.GREEN}{fixed}{Colors.RESET}  |  Skipped: {Colors.YELLOW}{skipped}{Colors.RESET}  |  Mode: {'DRY-RUN (preview only)' if dry_run else 'APPLIED'}")

    for change in changes:
        print(f"  ✅ {change['description']}")
        if change.get("env_var_added"):
            print(f"     {Colors.YELLOW}💡 Add to your .env: {change['env_var_added']}=your_real_value{Colors.RESET}")

    if preview:
        print(f"\n  {Colors.DIM}{'─' * 40}{Colors.RESET}")
        print(f"  {Colors.BOLD}Preview of changes:{Colors.RESET}")
        for line in preview.split("\n")[:30]:
            if line.startswith("+"):
                print(f"  {Colors.GREEN}{line}{Colors.RESET}")
            elif line.startswith("-"):
                print(f"  {Colors.RED}{line}{Colors.RESET}")
            elif line.startswith("@@"):
                print(f"  {Colors.CYAN}{line}{Colors.RESET}")

    if backup:
        print(f"\n  {Colors.DIM}📦 Backup saved to: {backup}{Colors.RESET}")
    print()


def cmd_version():
    """Show version."""
    print(f"mcp-guard v{__version__}")


# ── Main ───────────────────────────────────────────────

def main():
    args = sys.argv[1:]

    if not args:
        cmd_scan([])
    elif args[0] in ("scan", "s"):
        cmd_scan(args[1:])
    elif args[0] in ("fix", "f"):
        cmd_fix(args[1:])
    elif args[0] in ("rules", "r"):
        cmd_rules()
    elif args[0] in ("version", "v", "--version", "-v"):
        cmd_version()
    elif args[0] in ("help", "h", "--help", "-h"):
        print(__doc__)
    else:
        cmd_scan(args)


if __name__ == "__main__":
    main()
