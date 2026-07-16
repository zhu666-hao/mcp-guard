"""Auto-fix engine for MCP configuration security issues.

mcp-vigil fix    — Automatically fix common security issues
mcp-vigil fix --dry-run  — Preview changes without applying
"""

import json
import os
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional

from .scanner import scan_file, parse_mcp_config
from .rules import (
    API_KEY_PATTERNS,
    Finding,
    check_hardcoded_keys,
    check_env_var_usage,
    check_transport_security,
    check_server_source,
)


def fix_file(file_path: Path, dry_run: bool = False) -> dict:
    """Auto-fix security issues in an MCP config file.

    Returns:
        dict with 'fixed_count', 'skipped_count', 'backup_path', 'changes'
    """
    # Scan first to find issues
    result = scan_file(file_path)
    if not result or not result.findings:
        return {"fixed_count": 0, "skipped_count": 0, "backup_path": None, "changes": []}

    original_text = file_path.read_text(encoding="utf-8")
    fixed_text = original_text
    changes = []
    fixed = 0
    skipped = 0

    # Process each fixable finding
    for finding in result.findings:
        change = _apply_fix(finding, fixed_text, file_path)
        if change:
            fixed_text = change["new_text"]
            changes.append(change)
            fixed += 1
        else:
            skipped += 1

    if not changes:
        return {"fixed_count": 0, "skipped_count": skipped, "backup_path": None, "changes": []}

    if dry_run:
        return {
            "fixed_count": fixed,
            "skipped_count": skipped,
            "backup_path": None,
            "changes": changes,
            "preview": _generate_diff(original_text, fixed_text),
        }

    # Create backup
    backup_path = file_path.with_suffix(file_path.suffix + f".bak.{datetime.now().strftime('%Y%m%d%H%M%S')}")
    shutil.copy2(file_path, backup_path)

    # Write fixed file
    file_path.write_text(fixed_text, encoding="utf-8")

    return {
        "fixed_count": fixed,
        "skipped_count": skipped,
        "backup_path": str(backup_path),
        "changes": changes,
    }


def _apply_fix(finding: Finding, text: str, file_path: Path) -> Optional[dict]:
    """Apply a single fix. Returns the change dict or None if unfixable."""

    rule_handlers = {
        "ENV-SECRET-EXPOSED": _fix_env_secret,
        "HARDCODED-KEY": _fix_hardcoded_key,
        "INSECURE-TRANSPORT": _fix_http_to_https,
        "UNPINNED-VERSION": _fix_pin_version,
    }

    handler = rule_handlers.get(finding.rule_id)
    if not handler:
        return None

    return handler(finding, text, file_path)


def _fix_env_secret(finding: Finding, text: str, file_path: Path) -> Optional[dict]:
    """Replace hardcoded env var values with external references."""
    # Extract the key name from location
    # Format: "file_path (server: name, env: KEY_NAME)"
    location = finding.location
    match = re.search(r'env:\s*(\w+)', location)
    if not match:
        return None

    env_key = match.group(1)

    # Find the line with this env key and replace the value
    lines = text.split("\n")
    new_lines = []
    changed = False

    for line in lines:
        if f'"{env_key}"' in line or f"'{env_key}'" in line:
            # Replace: "KEY": "hardcoded_value" → "KEY": "${KEY}"
            new_line = re.sub(
                rf'("{env_key}"\s*:\s*)".*?"',
                rf'\1"${{{env_key}}}"',
                line,
            )
            new_line = re.sub(
                rf"('{env_key}'\s*:\s*)'.*?'",
                rf"\1'${{{env_key}}}'",
                new_line,
            )
            if new_line != line:
                changed = True
            new_lines.append(new_line)
        else:
            new_lines.append(line)

    if not changed:
        return None

    return {
        "rule_id": finding.rule_id,
        "description": f"Replaced hardcoded value for {env_key} with ${{{env_key}}} reference",
        "new_text": "\n".join(new_lines),
        "env_var_added": env_key,
    }


def _fix_hardcoded_key(finding: Finding, text: str, file_path: Path) -> Optional[dict]:
    """Replace hardcoded API keys with env var references."""
    # Extract the line number from location
    location = finding.location
    match = re.search(r':(\d+)', location)
    if not match:
        return None

    line_num = int(match.group(1))
    lines = text.split("\n")

    if line_num > len(lines):
        return None

    old_line = lines[line_num - 1]

    # Try to figure out a good env var name based on the key type in the title
    title = finding.title
    env_name = "API_KEY"
    if "GitHub" in title:
        env_name = "GITHUB_TOKEN"
    elif "OpenAI" in title or "DeepSeek" in title:
        env_name = "OPENAI_API_KEY"
    elif "Slack" in title:
        env_name = "SLACK_TOKEN"
    elif "AWS" in title:
        env_name = "AWS_ACCESS_KEY"
    elif "Anthropic" in title:
        env_name = "ANTHROPIC_API_KEY"

    # Replace the hardcoded value with env var reference
    # Pattern: key = "value" → key = "${ENV_NAME}"
    new_line = re.sub(
        r'(["\'])\S{10,}\1',
        f'"${{{env_name}}}"',
        old_line,
        count=1,
    )

    if new_line == old_line:
        return None

    lines[line_num - 1] = new_line

    return {
        "rule_id": finding.rule_id,
        "description": f"Replaced hardcoded key with ${{{env_name}}} on line {line_num}",
        "new_text": "\n".join(lines),
        "env_var_added": env_name,
    }


def _fix_http_to_https(finding: Finding, text: str, file_path: Path) -> Optional[dict]:
    """Change http:// URLs to https://."""
    location = finding.location

    # Find the server name
    match = re.search(r'server:\s*(\w+)', location)
    if not match:
        return None

    server_name = match.group(1)

    # Find the line with the server URL and replace http:// with https://
    lines = text.split("\n")
    new_lines = []
    changed = False

    in_server_block = False
    for line in lines:
        if f'"{server_name}"' in line:
            in_server_block = True
        elif in_server_block and line.strip().startswith('"') and ":" in line:
            in_server_block = False

        if in_server_block and "http://" in line and "localhost" not in line and "127.0.0.1" not in line:
            new_line = line.replace("http://", "https://")
            if new_line != line:
                changed = True
            new_lines.append(new_line)
        else:
            new_lines.append(line)

    if not changed:
        return None

    return {
        "rule_id": finding.rule_id,
        "description": f"Changed http:// to https:// for server '{server_name}'",
        "new_text": "\n".join(new_lines),
        "env_var_added": None,
    }


def _fix_pin_version(finding: Finding, text: str, file_path: Path) -> Optional[dict]:
    """Pin unpinned npx versions with a placeholder."""
    # For unpinned versions, we can't automatically determine the right version.
    # Instead, we flag it and suggest manual action.
    return None  # Auto-fix not possible without knowing the correct version


def _generate_diff(original: str, fixed: str) -> str:
    """Generate a simple unified diff."""
    import difflib
    diff = difflib.unified_diff(
        original.splitlines(keepends=True),
        fixed.splitlines(keepends=True),
        fromfile="original",
        tofile="fixed",
    )
    return "".join(diff)


def fix_all(dry_run: bool = False) -> list[dict]:
    """Fix all discovered MCP config files."""
    from .scanner import find_config_files, scan_file

    files = find_config_files()
    if not files:
        return []

    results = []
    for file_path in files:
        result = scan_file(file_path)
        if result and result.findings:
            fix_result = fix_file(file_path, dry_run=dry_run)
            fix_result["file"] = str(file_path)
            results.append(fix_result)

    return results
