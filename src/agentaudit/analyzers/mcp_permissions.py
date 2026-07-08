"""MCP config and Claude-settings analyzer (structural checks on JSON trees).

Text-level JSON rules (inline secrets, plain-http URLs) live in
``rules/mcp.yml``; this analyzer walks the parsed tree for what regexes can't
see: capability combinations, unpinned package execution, and hooks.
"""

from __future__ import annotations

import re

from agentaudit.analyzers import AnalyzerRule, ScanContext
from agentaudit.models import FileKind, Finding, ParsedFile, Severity, escape_snippet
from agentaudit.parsers.jsonyaml import find_line

ANALYZER_RULES = [
    AnalyzerRule(
        "AA-MCP-001",
        "MCP server combines filesystem and network access",
        "high",
        "mcp",
        "A single server that can both read local files and reach the network has everything it needs to exfiltrate data.",
    ),
    AnalyzerRule(
        "AA-MCP-002",
        "MCP server runs an unpinned package (npx/uvx @latest)",
        "medium",
        "mcp",
        "npx/uvx without a pinned version executes whatever the registry serves next — a supply-chain hole in your agent.",
    ),
    AnalyzerRule(
        "AA-MCP-005",
        "Settings hook executes a shell command",
        "info",
        "mcp",
        "Hooks run automatically with your privileges on agent events. Every hook command deserves review.",
    ),
    AnalyzerRule(
        "AA-MCP-006",
        "Settings hook runs a dangerous command",
        "high",
        "mcp",
        "A hook command matches a high-risk pattern (pipe-to-shell, recursive delete, encoded payload, network egress of files).",
    ),
]

_FS_HINT_RE = re.compile(
    r"(?i)(filesystem|file-system|server-fs\b|read[_-]?file|--allow-dir|--root\b|mcp-fs\b)"
)
_NET_HINT_RE = re.compile(
    r"(?i)(fetch|http|request|curl|browser|puppeteer|playwright|websocket|webhook|network|scrape)"
)

_RUNNERS = {"npx", "uvx", "pnpm", "bunx", "yarn"}
_RUNNER_FLAGS = {"-y", "--yes", "-q", "--quiet", "dlx", "exec", "-p", "--package"}

_DANGEROUS_HOOK_RE = re.compile(
    r"(?i)(\b(curl|wget)\b[^|;\r\n]*\|\s*(ba|z)?sh\b"
    r"|\brm\s+-[a-zA-Z]*r[a-zA-Z]*f"
    r"|base64\s+(-d|--decode|-D)"
    r"|/dev/tcp/"
    r"|\b(nc|ncat)\b.{0,40}\s-e\b"
    r"|\.(env|ssh|aws)\b.{0,60}\b(curl|wget|POST|upload)\b"
    r"|\b(curl|wget)\b.{0,60}\.(env|ssh|aws)\b)"
)


def analyze(parsed: ParsedFile, context: ScanContext) -> list[Finding]:
    if parsed.kind is not FileKind.JSON:
        return []
    tree = parsed.metadata.get("tree")
    if not isinstance(tree, dict):
        return []
    findings: list[Finding] = []
    servers = tree.get("mcpServers") or tree.get("servers") or {}
    if isinstance(servers, dict):
        for name, spec in servers.items():
            if isinstance(spec, dict):
                findings.extend(_check_server(parsed, name, spec))
    hooks = tree.get("hooks")
    if isinstance(hooks, dict):
        findings.extend(_check_hooks(parsed, hooks))
    return findings


def _server_text(name: str, spec: dict) -> str:
    parts = [name, str(spec.get("command", "")), str(spec.get("url", ""))]
    args = spec.get("args", [])
    if isinstance(args, list):
        parts.extend(str(a) for a in args)
    return " ".join(parts)


def _check_server(parsed: ParsedFile, name: str, spec: dict) -> list[Finding]:
    findings: list[Finding] = []
    line = find_line(parsed.lines, f'"{name}"')
    text = _server_text(name, spec)
    if _FS_HINT_RE.search(text) and _NET_HINT_RE.search(text):
        findings.append(
            Finding(
                rule_id="AA-MCP-001",
                severity=Severity.HIGH,
                category="mcp",
                file=parsed.path,
                line=line,
                message=f'Server "{name}" combines filesystem read + network access',
                snippet=escape_snippet(text, 100),
                remediation="Split capabilities across separate, minimally-scoped servers.",
            )
        )
    unpinned = _unpinned_package(spec)
    if unpinned:
        findings.append(
            Finding(
                rule_id="AA-MCP-002",
                severity=Severity.MEDIUM,
                category="mcp",
                file=parsed.path,
                line=line,
                message=f'Server "{name}" runs unpinned package "{unpinned}" — executes whatever the registry serves',
                snippet=escape_snippet(unpinned),
                remediation='Pin an exact version, e.g. "@modelcontextprotocol/server-filesystem@0.6.2".',
            )
        )
    return findings


def _unpinned_package(spec: dict) -> str | None:
    command = str(spec.get("command", "")).lower().rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if command not in _RUNNERS:
        return None
    args = spec.get("args", [])
    if not isinstance(args, list):
        return None
    for arg in args:
        arg = str(arg)
        if arg in _RUNNER_FLAGS or arg.startswith("-"):
            continue
        # First positional arg is the package spec.
        if arg.endswith("@latest"):
            return arg
        # "@scope/name@1.2.3" pins; "@scope/name" or "name" does not.
        body = arg[1:] if arg.startswith("@") else arg
        return None if "@" in body else arg
    return None


def _check_hooks(parsed: ParsedFile, hooks: dict, _event: str = "") -> list[Finding]:
    findings: list[Finding] = []
    for event, entries in hooks.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            for hook in entry.get("hooks", [entry]):
                if not isinstance(hook, dict):
                    continue
                command = hook.get("command")
                if not isinstance(command, str) or not command.strip():
                    continue
                line = find_line(parsed.lines, command.splitlines()[0][:60])
                if _DANGEROUS_HOOK_RE.search(command):
                    findings.append(
                        Finding(
                            rule_id="AA-MCP-006",
                            severity=Severity.HIGH,
                            category="mcp",
                            file=parsed.path,
                            line=line,
                            message=f'Hook on "{event}" runs a dangerous command',
                            snippet=escape_snippet(command),
                            remediation="Remove the hook or replace the command; hooks run automatically with your privileges.",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            rule_id="AA-MCP-005",
                            severity=Severity.INFO,
                            category="mcp",
                            file=parsed.path,
                            line=line,
                            message=f'Hook on "{event}" executes a shell command — review it',
                            snippet=escape_snippet(command),
                        )
                    )
    return findings
