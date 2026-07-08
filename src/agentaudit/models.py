"""Core data model: severities, findings, parsed files, and scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Severity(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"high": 3, "medium": 2, "low": 1, "info": 0}[self.value]

    def __ge__(self, other: Severity) -> bool:
        return self.rank >= other.rank

    def __gt__(self, other: Severity) -> bool:
        return self.rank > other.rank

    def __le__(self, other: Severity) -> bool:
        return self.rank <= other.rank

    def __lt__(self, other: Severity) -> bool:
        return self.rank < other.rank

    @classmethod
    def from_str(cls, value: str) -> Severity:
        return cls(value.strip().lower())


class FileKind(Enum):
    MARKDOWN = "markdown"
    JSON = "json"
    YAML = "yaml"


SNIPPET_MAX_LEN = 120

#: Characters that can hide or reorder text. Snippets containing these must be
#: rendered escaped — the scanner must not be vulnerable to the tricks it detects.
_DANGEROUS_CHARS = (
    "​‌‍‎‏⁠﻿"  # zero-width / marks
    "‪‫‬‭‮⁦⁧⁨⁩"  # bidi controls
)


def escape_snippet(text: str, max_len: int = SNIPPET_MAX_LEN) -> str:
    """Truncate and escape control / invisible characters for safe display."""
    out: list[str] = []
    for ch in text:
        if ch in _DANGEROUS_CHARS or (ord(ch) < 0x20 and ch not in "\t"):
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    escaped = "".join(out)
    if len(escaped) > max_len:
        escaped = escaped[: max_len - 1] + "…"
    return escaped


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    category: str
    file: Path
    message: str
    line: int | None = None
    column: int | None = None
    snippet: str | None = None
    remediation: str | None = None

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "category": self.category,
            "file": self.file.as_posix(),
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "snippet": self.snippet,
            "remediation": self.remediation,
        }


@dataclass
class ParsedFile:
    path: Path
    kind: FileKind
    raw: str
    lines: list[str]
    metadata: dict = field(default_factory=dict)


@dataclass
class ScanResult:
    root: Path
    files_scanned: int
    duration_ms: int
    findings: list[Finding] = field(default_factory=list)

    @property
    def counts(self) -> dict[Severity, int]:
        counts = {sev: 0 for sev in Severity}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def exit_code(self, fail_threshold: Severity = Severity.HIGH) -> int:
        return 1 if any(f.severity >= fail_threshold for f in self.findings) else 0

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (-f.severity.rank, f.file.as_posix(), f.line or 0),
        )
