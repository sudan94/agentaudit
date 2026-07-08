"""Exfiltration analyzer.

Same-line combos and suspicious destinations are YAML rules
(AA-EXF-001 … AA-EXF-006). This analyzer adds the check a single-line regex
cannot express: a sensitive credential path and a network egress verb in
*close proximity* across neighboring lines.
"""

from __future__ import annotations

import re

from agentaudit.analyzers import AnalyzerRule, ScanContext
from agentaudit.models import FileKind, Finding, ParsedFile, Severity, escape_snippet

ANALYZER_RULES = [
    AnalyzerRule(
        "AA-EXF-100",
        "Sensitive file and network egress in close proximity",
        "high",
        "exfiltration",
        "A credential/secret path and a network send appear within a few lines of each other — a multi-line exfiltration instruction.",
    ),
]

_SENSITIVE_RE = re.compile(
    r"(?i)(\.env\b|\.ssh\b|id_rsa|id_ed25519|\.aws\b|\.netrc|\bkeychain\b|"
    r"credentials?\.(json|ya?ml|csv)|\bapi[_ ]?keys?\b|\bsecrets?\b)"
)
_EGRESS_RE = re.compile(
    r"(?i)\b(curl|wget|POST|upload|send\s+(it|them|the|to)|submit\s+to|transmit|"
    r"webhook|requests\.(post|put)|fetch\()\b"
)

_PROXIMITY = 3  # lines


def analyze(parsed: ParsedFile, context: ScanContext) -> list[Finding]:
    if parsed.kind is not FileKind.MARKDOWN:
        return []
    findings: list[Finding] = []
    sensitive_lines = [
        i for i, line in enumerate(parsed.lines, start=1) if _SENSITIVE_RE.search(line)
    ]
    egress_lines = [
        i for i, line in enumerate(parsed.lines, start=1) if _EGRESS_RE.search(line)
    ]
    reported: set[int] = set()
    for s_line in sensitive_lines:
        for e_line in egress_lines:
            # Same line is AA-EXF-001 (YAML rule); only cross-line proximity here.
            if s_line == e_line or abs(s_line - e_line) > _PROXIMITY:
                continue
            anchor = min(s_line, e_line)
            if anchor in reported:
                continue
            reported.add(anchor)
            findings.append(
                Finding(
                    rule_id="AA-EXF-100",
                    severity=Severity.HIGH,
                    category="exfiltration",
                    file=parsed.path,
                    line=anchor,
                    message=f"Sensitive file (line {s_line}) and network egress (line {e_line}) in close proximity",
                    snippet=escape_snippet(parsed.lines[anchor - 1].strip()),
                    remediation="No agent skill should move credential files toward the network.",
                )
            )
    return findings
