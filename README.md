# 🛡️ mcp-vigil

**Security audit CLI for MCP (Model Context Protocol) configurations.**

Find leaked API keys, excessive permissions, and vulnerable servers before attackers do.

```bash
pip install mcp-vigil
mcp-vigil scan
```

---

## Demo

```bash
$ mcp-vigil scan
```

![mcp-vigil demo](assets/demo.png)

```
╔══════════════════════════════════════╗
║       MCP VIGIL — Security Audit     ║
╚══════════════════════════════════════╝

📄 ~/.cursor/mcp.json
   Servers: 5  |  Findings: 1 critical, 5 high, 4 other  |  Score: 13/100 (F)

🔴 [CRITICAL] CVE-2025-6514 (CVSS 9.6): GitHub MCP server leaked repository contents
   Server 'github' v0.2.0 is vulnerable. Upgrade to >= 0.3.0.

🟠 [HIGH] Excessive filesystem access: /
   Server 'filesystem' has --directory set to / — entire disk exposed.

🟠 [HIGH] Secret in env block of MCP config
   Server 'github', env: GITHUB_PERSONAL_ACCESS_TOKEN is hardcoded.

🟠 [HIGH] Secret in env block of MCP config
   Server 'slack', env: SLACK_BOT_TOKEN is hardcoded.

🟠 [HIGH] MCP server from untrusted source
   Server 'unknown-source' loads from raw.githubusercontent.com.

🟠 [HIGH] Unpinned version may be vulnerable to CVE-2025-11283

🟡 [MEDIUM] MCP server using HTTP without TLS

🟡 [MEDIUM] Deprecated MCP package: @anthropic/mcp-server-github

🟡 [MEDIUM] MCP server using unpinned version (npx without @version)

🟡 [MEDIUM] MCP server using unpinned version (npx without @version)

────────────────────────────────────────
  Files: 1  |  Servers: 5  |  Findings: 10
    1 CRITICAL  ·  5 HIGH  ·  4 MEDIUM
────────────────────────────────────────

⚠️  CRITICAL ISSUES FOUND — fix immediately
```

---

## What it does

- 🔴 **Hardcoded API keys** — 22 patterns: GitHub, OpenAI, Anthropic, AWS, Slack, Docker, GitLab, JWT, more
- 🔴 **Known CVEs** — 7 tracked vulnerabilities: CVE-2025-6514 (CVSS 9.6), CVE-2025-49596 (CVSS 9.4), and more
- 🟠 **Excessive filesystem access** — Servers with access to `/` or `/home`
- 🟠 **Untrusted server sources** — MCP servers from pastebin, raw GitHub gists, etc
- 🟠 **Command injection risks** — Shell metacharacters in server arguments
- 🟡 **Unpinned versions** — npx packages without version pins (supply chain risk)
- 🟡 **Insecure transport** — HTTP without TLS for remote servers
- 🟡 **Deprecated packages** — Flag archived/unmaintained MCP servers
- 🟡 **Environment secrets exposed** — Hardcoded values in env blocks
- 🔵 **Missing environment variables** — Referenced but undeclared env vars

---

## Quick Start

```bash
# Install
pip install mcp-vigil

# Scan all found MCP configs
mcp-vigil scan

# Scan a specific file
mcp-vigil scan --path ~/.cursor/mcp.json

# Auto-fix common issues
mcp-vigil fix

# Preview fixes without applying
mcp-vigil fix --dry-run

# JSON output (for CI/CD)
mcp-vigil scan --json

# Fail CI if critical issues found
mcp-vigil scan --ci

# List all security rules
mcp-vigil rules
```

---

## Supported Config Locations

Auto-discovers MCP configs in:
- Cursor: `~/.cursor/mcp.json`
- Claude Desktop: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Claude Code: `~/.claude/mcp.json`, `.claude/mcp.json`
- VS Code: `.vscode/mcp.json`
- Windsurf: `~/.windsurf/mcp.json`

---

## Auto-Fix

```bash
$ mcp-vigil fix --dry-run

📄 ~/.cursor/mcp.json
  Fixed: 2  |  Skipped: 8  |  Mode: DRY-RUN (preview only)

✅ Replaced hardcoded value for GITHUB_PERSONAL_ACCESS_TOKEN with ${GITHUB_PERSONAL_ACCESS_TOKEN}
   💡 Add to your .env: GITHUB_PERSONAL_ACCESS_TOKEN=your_real_value

✅ Replaced hardcoded value for SLACK_BOT_TOKEN with ${SLACK_BOT_TOKEN}
   💡 Add to your .env: SLACK_BOT_TOKEN=your_real_value

--- original
+++ fixed
-  "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_YOUR_TOKEN_HERE_REPLACE_ME"
+  "GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_PERSONAL_ACCESS_TOKEN}"
```

---

## GitHub Action (CI/CD)

```yaml
- uses: mcp-vigil/action@v1
  with:
    fail-on: critical
```

Block merges if MCP security issues are introduced.

---

## Why this exists

10,000+ MCP servers exist. 53% use static API keys. Developers add MCP servers to their AI coding tools daily — often without reading the source code or checking permissions.

As AI agents get access to terminals, files, and APIs through MCP, a single misconfigured server becomes a critical attack vector.

**mcp-vigil is `npm audit` for the MCP ecosystem.**

---

## Roadmap

- [x] Auto-fix mode (`mcp-vigil fix`)
- [ ] VS Code extension (real-time warnings in editor)
- [ ] Web dashboard for team management (paid)
- [ ] Custom rule support (company security policies)
- [ ] Integration with Smithery/PulseMCP registry for trust verification

---

## License

MIT © 2026
