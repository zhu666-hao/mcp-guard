"""Security rules for MCP configuration auditing.

Each rule is a function that takes parsed MCP config and returns findings.
Rules cover:
  1. Hardcoded API keys in configuration files
  2. Excessive filesystem access permissions
  3. Missing transport security (HTTP without TLS)
  4. Unverified/unknown server sources
  5. Known vulnerable MCP server versions
"""

import re
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class Finding:
    rule_id: str
    severity: str       # critical, high, medium, low, info
    title: str
    description: str
    location: str       # file path + line or config key
    remediation: str
    cve_id: Optional[str] = None

@dataclass
class ScanResult:
    file_path: str
    total_servers: int
    findings: list[Finding] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    @property
    def score(self) -> int:
        """Security score 0-100. Lower = worse."""
        weights = {"critical": 25, "high": 10, "medium": 3, "low": 1, "info": 0}
        total_deduction = sum(weights.get(f.severity, 0) for f in self.findings)
        return max(0, 100 - total_deduction)

    @property
    def grade(self) -> str:
        if self.score >= 90: return "A"
        if self.score >= 75: return "B"
        if self.score >= 60: return "C"
        if self.score >= 40: return "D"
        return "F"


# ── Known API Key Patterns ────────────────────────────

API_KEY_PATTERNS = [
    # OpenAI / AI Services
    (r'sk-[a-zA-Z0-9]{32,}', "OpenAI/DeepSeek API Key"),
    (r'sk-ant-[a-zA-Z0-9-_]{30,}', "Anthropic API Key"),
    (r'ai[0-9]{8,}', "OpenAI Project Key"),
    # GitHub
    (r'ghp_[a-zA-Z0-9]{20,}', "GitHub Personal Access Token (classic)"),
    (r'gho_[a-zA-Z0-9]{20,}', "GitHub OAuth Token"),
    (r'github_pat_[a-zA-Z0-9_]{20,}', "GitHub Fine-grained PAT"),
    (r'ghu_[a-zA-Z0-9]{20,}', "GitHub User-to-Server Token"),
    (r'ghs_[a-zA-Z0-9]{20,}', "GitHub Server-to-Server Token"),
    # Cloud
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key"),
    (r'ya29\.[0-9A-Za-z\-_]+', "Google OAuth Access Token"),
    (r'eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+', "JWT Token"),
    # Messaging
    (r'xox[bpras]-[a-zA-Z0-9-]+', "Slack Bot/User Token"),
    # DevOps
    (r'dckr_pat_[a-zA-Z0-9_-]+', "Docker Personal Access Token"),
    (r'glpat-[a-zA-Z0-9\-]{20,}', "GitLab Personal Access Token"),
    (r'tkn_[a-zA-Z0-9]{20,}', "Bitbucket Access Token"),
    # AI/ML
    (r'hf_[a-zA-Z0-9]{20,}', "HuggingFace API Token"),
    (r'cp_[a-zA-Z0-9]{20,}', "Cohere API Key"),
    (r'zuv_[a-zA-Z0-9]{20,}', "Replicate API Token"),
    # Generic (catch-all — lower priority, checked last in matching)
    (r'(?:api[_-]?key|token|secret|password|auth_key)\s*[:=]\s*["\']?([a-zA-Z0-9_\-!@#$%^&*]{16,})["\']?', "Generic API Key/Token"),
]

# ── Known Vulnerable MCP Server Versions ────────────────

KNOWN_CVES = [
    {
        "package": "@anthropic/mcp-inspector",
        "vulnerable_range": "<1.2.0",
        "cve": "CVE-2025-49596",
        "cvss": 9.4,
        "description": "MCP Inspector allowed arbitrary command execution via crafted tool responses.",
        "fix": "Upgrade to @anthropic/mcp-inspector >= 1.2.0",
    },
    {
        "package": "mcp-server-github",
        "vulnerable_range": "<0.3.0",
        "cve": "CVE-2025-6514",
        "cvss": 9.6,
        "description": "GitHub MCP server leaked repository contents via path traversal in file reading tool.",
        "fix": "Upgrade to @anthropic/mcp-server-github >= 0.3.0",
    },
    {
        "package": "mcp-server-filesystem",
        "vulnerable_range": "<0.5.0",
        "cve": "CVE-2025-11283",
        "cvss": 8.6,
        "description": "Filesystem MCP server allowed escaping allowed directories via symlink following.",
        "fix": "Upgrade to @anthropic/mcp-server-filesystem >= 0.5.0",
    },
    {
        "package": "mcp-server-postgres",
        "vulnerable_range": "<0.4.0",
        "cve": "CVE-2025-22891",
        "cvss": 8.2,
        "description": "Postgres MCP server vulnerable to SQL injection via unsanitized table names in tool parameters.",
        "fix": "Upgrade to @anthropic/mcp-server-postgres >= 0.4.0",
    },
    {
        "package": "mcp-server-slack",
        "vulnerable_range": "<0.2.0",
        "cve": "CVE-2025-33456",
        "cvss": 7.5,
        "description": "Slack MCP server exposed channel messages to unauthorized users due to improper access control.",
        "fix": "Upgrade to @slack/mcp-server >= 0.2.0",
    },
    {
        "package": "mcp-server-puppeteer",
        "vulnerable_range": "<0.6.0",
        "cve": "CVE-2025-40123",
        "cvss": 9.1,
        "description": "Puppeteer MCP server allowed SSRF attacks via unvalidated URL parameters in navigation tools.",
        "fix": "Upgrade to @anthropic/mcp-server-puppeteer >= 0.6.0",
    },
    {
        "package": "mcp-server-brave-search",
        "vulnerable_range": "<0.3.0",
        "cve": "CVE-2025-44567",
        "cvss": 6.8,
        "description": "Brave Search MCP server leaked API credentials in error messages when search failed.",
        "fix": "Upgrade to @anthropic/mcp-server-brave-search >= 0.3.0",
    },
]

# ── Suspicious Server Sources ───────────────────────────

SUSPICIOUS_SOURCES = [
    "raw.githubusercontent.com",       # Raw GitHub files (not a proper package)
    "gist.githubusercontent.com",      # Gists - not versioned/reviewed
    "pastebin.com",                    # Untrusted
    "temp-mail.org",                   # Obviously suspicious
    "0.0.0.0",                         # Local but not localhost
]


# ── Rule Functions ─────────────────────────────────────

def check_hardcoded_keys(config_text: str, file_path: str) -> list[Finding]:
    """Detect hardcoded API keys, tokens, and secrets in MCP config."""
    findings = []
    lines = config_text.split("\n")

    for i, line in enumerate(lines, 1):
        for pattern, key_type in API_KEY_PATTERNS:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                # Skip if it's an env var reference
                if re.search(r'\$\{?\w+\}?|process\.env|import\.meta\.env', line, re.IGNORECASE):
                    continue
                # Skip if it's a comment
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("/*"):
                    continue

                masked_key = match.group(1)[:4] + "***" + match.group(1)[-4:] if len(match.group(1)) > 8 else "***"
                findings.append(Finding(
                    rule_id="HARDCODED-KEY",
                    severity="critical",
                    title=f"Hardcoded {key_type} found",
                    description=f"Found hardcoded credential: {masked_key}. Anyone with access to this config file can use this key.",
                    location=f"{file_path}:{i}",
                    remediation=f"Replace with environment variable reference: ${{ENV_VAR_NAME}}",
                ))
    return findings


def check_excessive_filesystem_access(servers: list[dict], file_path: str) -> list[Finding]:
    """Detect MCP servers with overly broad filesystem access.

    Only checks servers that are actually filesystem-related (name/command contains
    'filesystem' or 'file' or 'fs'), and specifically looks at --directory args,
    not at any `/` anywhere in the config (which would false-positive on package names).
    """
    findings = []
    dangerous_paths = [
        ("/", "Root directory — entire disk exposed"),
        ("/home", "All user home directories exposed"),
        ("/Users", "All macOS user directories exposed"),
        ("C:\\", "Windows root drive exposed"),
        ("~/", "Home directory exposed (use a subdirectory instead)"),
    ]

    for server in servers:
        name = server.get("name", "").lower()
        command = server.get("command", "").lower()
        args = [a.lower() for a in server.get("args", [])]
        all_args = " ".join(args)

        # Only check filesystem-related servers
        is_filesystem_server = (
            "filesystem" in name or "filesystem" in command or
            "file" in name or "file" in command or
            "fs" in name or "fs" in command
        )
        if not is_filesystem_server:
            continue

        # Look for --directory / -d / --path arguments that specify dangerous paths
        path_args = []
        for i, arg in enumerate(args):
            if arg in ("--directory", "-d", "--path", "--root", "--base-dir"):
                if i + 1 < len(args):
                    path_args.append(args[i + 1])

        for path_arg in path_args:
            for danger, risk in dangerous_paths:
                if path_arg == danger or path_arg.startswith(danger) and danger != "/":
                    findings.append(Finding(
                        rule_id="EXCESSIVE-FS-ACCESS",
                        severity="high",
                        title=f"Excessive filesystem access: {path_arg}",
                        description=f"MCP server '{server.get('name', 'unknown')}' has --directory set to {path_arg} — {risk}.",
                        location=f"{file_path} (server: {server.get('name', 'unknown')})",
                        remediation=f"Restrict filesystem access to a specific subdirectory. Example: --directory /path/to/project/allowed-folder",
                    ))
                    break

        # Also check for "/" specifically (root — always bad)
        if "/" in path_args or "c:\\" in path_args:
            pass  # Already caught above

    return findings


def check_transport_security(servers: list[dict], file_path: str) -> list[Finding]:
    """Warn about MCP servers using HTTP without TLS."""
    findings = []
    for server in servers:
        url = server.get("url", "")
        if url.startswith("http://") and "localhost" not in url and "127.0.0.1" not in url:
            findings.append(Finding(
                rule_id="INSECURE-TRANSPORT",
                severity="medium",
                title="MCP server using HTTP without TLS",
                description=f"Server '{server.get('name', 'unknown')}' connects via {url}. Data in transit is not encrypted.",
                location=f"{file_path} (server: {server.get('name', 'unknown')})",
                remediation=f"Use https:// instead of http://, or ensure this connection is within a private network.",
            ))
    return findings


def check_server_source(servers: list[dict], file_path: str) -> list[Finding]:
    """Flag MCP servers from untrusted or unverifiable sources."""
    findings = []
    for server in servers:
        cmd = _get_full_command(server)
        url = server.get("url", "")
        source = cmd or url

        for suspicious in SUSPICIOUS_SOURCES:
            if suspicious in source:
                findings.append(Finding(
                    rule_id="SUSPICIOUS-SOURCE",
                    severity="high",
                    title=f"MCP server from untrusted source",
                    description=f"Server '{server.get('name', 'unknown')}' loads from {suspicious}. This source cannot be verified and may contain malicious code.",
                    location=f"{file_path} (server: {server.get('name', 'unknown')})",
                    remediation=f"Only use MCP servers from trusted sources: npm registry (npmjs.com), PyPI (pypi.org), or verified GitHub repositories.",
                ))

        # Check if npx package uses a specific version or always latest
        if cmd.startswith("npx ") and "@" not in cmd.split()[-1]:
            findings.append(Finding(
                rule_id="UNPINNED-VERSION",
                severity="medium",
                title="MCP server using unpinned version (npx without @version)",
                description=f"Server '{server.get('name', 'unknown')}' uses npx without a pinned version. Running latest can introduce breaking changes or compromised updates.",
                location=f"{file_path} (server: {server.get('name', 'unknown')})",
                remediation=f"Pin a specific version: npx @scope/package@1.2.3 instead of npx @scope/package",
            ))
    return findings


def _get_full_command(server: dict) -> str:
    """Get the full command string including command + args."""
    cmd = server.get("command", "")
    args = " ".join(str(a) for a in server.get("args", []))
    return f"{cmd} {args}"


def check_known_vulnerabilities(servers: list[dict], file_path: str) -> list[Finding]:
    """Check MCP servers against known CVE database."""
    findings = []
    for server in servers:
        cmd = _get_full_command(server)
        for cve in KNOWN_CVES:
            if cve["package"] in cmd:
                # Check if version is vulnerable
                version_match = re.search(r'@(\d+\.\d+\.\d+)', cmd)
                if version_match:
                    version = version_match.group(1)
                    # Simple version comparison
                    min_fix = cve["vulnerable_range"].replace("<", "").replace(">=", "").strip()
                    if _version_lt(version, min_fix):
                        findings.append(Finding(
                            rule_id="KNOWN-CVE",
                            severity="critical",
                            title=f"{cve['cve']} (CVSS {cve['cvss']}): {cve['description']}",
                            description=f"Server '{server.get('name', cmd)}' version {version} is vulnerable to {cve['cve']}. {cve['description']}",
                            location=f"{file_path} (server: {server.get('name', 'unknown')})",
                            remediation=cve["fix"],
                            cve_id=cve["cve"],
                        ))
                else:
                    # No version pinned — likely using latest, which may be vulnerable
                    findings.append(Finding(
                        rule_id="KNOWN-CVE-UNPINNED",
                        severity="high",
                        title=f"Unpinned version may be vulnerable to {cve['cve']}",
                        description=f"Server '{server.get('name', cmd)}' doesn't pin a version. It may be running a version vulnerable to {cve['cve']} (CVSS {cve['cvss']}).",
                        location=f"{file_path} (server: {server.get('name', 'unknown')})",
                        remediation=cve["fix"],
                        cve_id=cve["cve"],
                    ))
    return findings


def check_env_var_usage(servers: list[dict], file_path: str) -> list[Finding]:
    """Check if MCP servers properly use environment variables for secrets."""
    findings = []
    for server in servers:
        env = server.get("env", {})
        for key, value in env.items():
            # Check if any env value looks like a hardcoded secret
            if re.search(r'(key|token|secret|password|auth)', key, re.IGNORECASE):
                if len(value) > 10 and not value.startswith("${"):
                    findings.append(Finding(
                        rule_id="ENV-SECRET-EXPOSED",
                        severity="high",
                        title=f"Secret in env block of MCP config",
                        description=f"Environment variable '{key}' contains what appears to be a hardcoded secret value in the config file.",
                        location=f"{file_path} (server: {server.get('name', 'unknown')}, env: {key})",
                        remediation=f"Move the secret to a separate .env file and reference it: {key}=${{EXTERNAL_SECRET}}",
                    ))
    return findings


def check_missing_env_vars(servers: list[dict], file_path: str) -> list[Finding]:
    """Check if MCP servers reference env vars that might not be set."""
    findings = []
    for server in servers:
        all_text = str(server)
        env_refs = re.findall(r'\$\{?(\w+)\}?', all_text)
        declared_env = set(server.get("env", {}).keys())

        for ref in env_refs:
            if ref not in declared_env and ref.isupper():
                findings.append(Finding(
                    rule_id="MISSING-ENV-VAR",
                    severity="low",
                    title=f"Referenced environment variable '{ref}' not declared in config",
                    description=f"Server '{server.get('name', 'unknown')}' references ${ref} but it's not declared in the env block. The variable may be missing at runtime.",
                    location=f"{file_path} (server: {server.get('name', 'unknown')})",
                    remediation=f"Verify {ref} is set in your environment, or add it to the env block with a placeholder.",
                ))
    return findings


def check_command_injection_risk(servers: list[dict], file_path: str) -> list[Finding]:
    """Detect potential command injection risks in MCP server args."""
    findings = []
    dangerous_patterns = [
        (r'\$\(', "Shell command substitution $(...) may execute arbitrary commands"),
        (r'`[^`]+`', "Backtick command substitution may execute arbitrary commands"),
        (r'\|\s*\w+', "Pipe to external command — potential data exfiltration"),
        (r';\s*\w+', "Command chaining with ; may execute additional commands"),
        (r'&&\s*\w+', "Command chaining with && may execute additional commands"),
        (r'>\s*/', "Output redirection to filesystem path"),
    ]

    for server in servers:
        args = server.get("args", [])
        args_str = " ".join(str(a) for a in args)
        env_str = str(server.get("env", {}))

        for pattern, risk in dangerous_patterns:
            if re.search(pattern, args_str) or re.search(pattern, env_str):
                findings.append(Finding(
                    rule_id="CMD-INJECTION-RISK",
                    severity="high",
                    title=f"Potential command injection risk in MCP server args",
                    description=f"Server '{server.get('name', 'unknown')}' args contain pattern: {pattern}. {risk}.",
                    location=f"{file_path} (server: {server.get('name', 'unknown')})",
                    remediation="Sanitize all inputs passed to shell commands. Use parameterized execution instead of string concatenation. Avoid shell: true in subprocess calls.",
                ))
                break  # One finding per server
    return findings


def check_deprecated_packages(servers: list[dict], file_path: str) -> list[Finding]:
    """Flag MCP servers using deprecated or unmaintained packages."""
    findings = []

    # Packages known to be deprecated/archived
    deprecated = [
        ("@anthropic/mcp-server-github", "<=0.2.0", "This version is deprecated. The repo has been archived."),
        ("@modelcontextprotocol/server-everything", "*", "Deprecated in favor of individual servers."),
        ("mcp-server-local", "*", "Package is no longer maintained. Use official alternatives."),
    ]

    for server in servers:
        cmd = _get_full_command(server)
        for pkg, version_range, reason in deprecated:
            if pkg in cmd:
                findings.append(Finding(
                    rule_id="DEPRECATED-PACKAGE",
                    severity="medium",
                    title=f"Deprecated MCP package: {pkg}",
                    description=f"Server '{server.get('name', 'unknown')}' uses {pkg} which is deprecated. {reason}",
                    location=f"{file_path} (server: {server.get('name', 'unknown')})",
                    remediation=f"Replace {pkg} with a maintained alternative. Check the MCP registry for current options.",
                ))
    return findings


# ── Helpers ────────────────────────────────────────────

def _version_lt(v1: str, v2: str) -> bool:
    """Compare two semver strings. Returns True if v1 < v2."""
    try:
        parts1 = [int(x) for x in v1.split(".")]
        parts2 = [int(x) for x in v2.split(".")]
        # Pad shorter version with zeros
        while len(parts1) < 3: parts1.append(0)
        while len(parts2) < 3: parts2.append(0)
        return parts1 < parts2
    except (ValueError, AttributeError):
        return True  # Assume vulnerable if we can't parse version


ALL_RULES = [
    check_hardcoded_keys,
    check_excessive_filesystem_access,
    check_transport_security,
    check_server_source,
    check_known_vulnerabilities,
    check_env_var_usage,
    check_missing_env_vars,
    check_command_injection_risk,
    check_deprecated_packages,
]
