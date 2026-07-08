"""Dangerous-command analyzer.

The command patterns themselves are YAML rules (AA-CMD-001 … AA-CMD-009),
which the rule engine automatically downgrades inside documented-example
fences. This analyzer adds the context check regexes can't do alone: an
explicit imperative ("run the following…") pointing at a dangerous command —
the strongest signal that the agent is *meant to execute it*, not read it.
"""

from __future__ import annotations

import re

from agentaudit.analyzers import AnalyzerRule, ScanContext
from agentaudit.models import FileKind, Finding, ParsedFile, Severity, escape_snippet
from agentaudit.parsers.markdown import line_in_fence

ANALYZER_RULES = [
    AnalyzerRule(
        "AA-CMD-100",
        "Agent explicitly instructed to execute a dangerous command",
        "high",
        "command",
        "An imperative instruction ('run the following…') is immediately followed by a high-risk shell command.",
    ),
]

_IMPERATIVE_RE = re.compile(
    r"(?i)\b(run|execute)\s+(the\s+following|this|these|it)\b"
    r"|\byou\s+(must|should|need\s+to|have\s+to)\s+(run|execute)\b"
    r"|\b(always|first|now)\s+run\b"
    r"|\bstart\s+by\s+running\b"
)

_HIGH_RISK_RE = re.compile(
    r"(?i)\b(curl|wget)\b[^|\r\n]*\|\s*(sudo\s+)?(ba|z|da|fi)?sh\b"
    r"|\brm\s+-[a-zA-Z]*r[a-zA-Z]*f"
    r"|base64\s+(-d|--decode|-D)\b[^|\r\n]*\|"
    r"|\b(nc|ncat|netcat)\b.{0,50}\s-e\b"
    r"|/dev/tcp/"
)

_LOOKAHEAD = 5  # lines after the imperative to search


def analyze(parsed: ParsedFile, context: ScanContext) -> list[Finding]:
    if parsed.kind is not FileKind.MARKDOWN:
        return []
    findings: list[Finding] = []
    fences = parsed.metadata.get("fences", [])
    for line_no, line in enumerate(parsed.lines, start=1):
        if not _IMPERATIVE_RE.search(line):
            continue
        window = parsed.lines[line_no - 1 : line_no + _LOOKAHEAD]
        for offset, candidate in enumerate(window):
            if not _HIGH_RISK_RE.search(candidate):
                continue
            cmd_line = line_no + offset
            fence = line_in_fence(fences, cmd_line)
            if fence is not None and fence.is_example:
                continue  # documented example — base YAML rule already reports it (downgraded)
            findings.append(
                Finding(
                    rule_id="AA-CMD-100",
                    severity=Severity.HIGH,
                    category="command",
                    file=parsed.path,
                    line=line_no,
                    message=f"Agent explicitly instructed to execute a dangerous command (line {cmd_line})",
                    snippet=escape_snippet(candidate.strip()),
                    remediation="Remove the instruction or replace the command with a safe, reviewable alternative.",
                )
            )
            break
    return findings
