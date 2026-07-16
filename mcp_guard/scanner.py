"""MCP configuration scanner.

Discovers and parses MCP configuration files from:
  - Cursor: ~/.cursor/mcp.json
  - Claude Desktop: ~/Library/Application Support/Claude/claude_desktop_config.json
  - Claude Code: ~/.claude/mcp.json, .claude/mcp.json (project)
  - VS Code: .vscode/mcp.json
  - Windsurf: ~/.windsurf/mcp.json
  - Custom path (user-specified)
"""

import json
import os
from pathlib import Path
from typing import Optional

from .rules import (
    ALL_RULES,
    Finding,
    ScanResult,
    check_known_vulnerabilities,
    check_server_source,
)


def find_config_files() -> list[Path]:
    """Auto-discover MCP configuration files on the system."""
    home = Path.home()
    candidates = [
        # Cursor
        home / ".cursor" / "mcp.json",
        # Claude Desktop (macOS)
        home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
        # Claude Desktop (Windows)
        Path(os.getenv("APPDATA", "")) / "Claude" / "claude_desktop_config.json",
        # Claude Code (global)
        home / ".claude" / "mcp.json",
        # VS Code (workspace — scanned recursively in project)
        # Windsurf
        home / ".windsurf" / "mcp.json",
    ]

    found = []
    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            found.append(candidate)

    # Also check current directory for .claude/mcp.json or .vscode/mcp.json
    cwd = Path.cwd()
    for pattern in [".claude/mcp.json", ".vscode/mcp.json", "mcp.json"]:
        p = cwd / pattern
        if p.exists() and p.is_file() and p not in found:
            found.append(p)

    return found


def parse_mcp_config(file_path: Path) -> Optional[dict]:
    """Parse an MCP configuration file into a normalized dict.

    Supports both:
      - Standard format: {"mcpServers": {"name": {...}, ...}}
      - Simplified format: {"name": {...}, ...} (without mcpServers wrapper)
    """
    try:
        text = file_path.read_text(encoding="utf-8")
        config = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        return None

    # Normalize: extract servers
    if "mcpServers" in config:
        servers = config["mcpServers"]
    else:
        # Assume top-level keys are server names
        servers = {k: v for k, v in config.items() if isinstance(v, dict)}

    return {
        "raw_text": text,
        "servers": [
            {"name": name, **cfg}
            for name, cfg in servers.items()
            if isinstance(cfg, dict)
        ],
        "config": config,
    }


def scan_file(file_path: Path) -> Optional[ScanResult]:
    """Run all security rules against a single MCP config file."""
    parsed = parse_mcp_config(file_path)
    if parsed is None:
        return None

    servers = parsed.get("servers", [])
    raw_text = parsed.get("raw_text", "")

    result = ScanResult(
        file_path=str(file_path),
        total_servers=len(servers),
    )

    # Run each rule
    for rule_fn in ALL_RULES:
        try:
            # Rules that need server list
            if rule_fn in (check_server_source, check_known_vulnerabilities):
                continue  # handled below with unified call
            if rule_fn.__name__ in ("check_hardcoded_keys",):
                findings = rule_fn(raw_text, str(file_path))
            elif rule_fn.__name__ in ("check_excessive_filesystem_access", "check_transport_security",
                                       "check_missing_env_vars", "check_env_var_usage"):
                findings = rule_fn(servers, str(file_path))
            else:
                findings = rule_fn(servers, str(file_path))
            result.findings.extend(findings)
        except Exception:
            continue

    # Run server-source rules
    try:
        result.findings.extend(check_server_source(servers, str(file_path)))
        result.findings.extend(check_known_vulnerabilities(servers, str(file_path)))
    except Exception:
        pass

    # Sort findings by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    result.findings.sort(key=lambda f: severity_order.get(f.severity, 5))

    return result


def scan_all(extra_paths: list[str] = None) -> list[ScanResult]:
    """Scan all discovered MCP config files plus any extra paths specified."""
    files = find_config_files()

    # Add user-specified paths
    if extra_paths:
        for p in extra_paths:
            path = Path(p).expanduser().resolve()
            if path.exists() and path not in files:
                files.append(path)

    results = []
    for file_path in files:
        result = scan_file(file_path)
        if result is not None:
            results.append(result)

    return results
