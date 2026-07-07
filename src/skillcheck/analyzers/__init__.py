"""Analyzer registry and shared protocol.

Each analyzer module exposes ``analyze(parsed, context) -> list[Finding]`` and
an ``ANALYZER_RULES`` list describing the rule IDs it can emit (so
``skillcheck rules`` can list them alongside the YAML rules).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

from skillcheck.models import Finding, ParsedFile

if TYPE_CHECKING:
    from skillcheck.rule_engine import RuleEngine


@dataclass
class ScanContext:
    """Shared state handed to every analyzer."""

    rule_engine: RuleEngine | None = None
    depth: int = 0  # decoded-payload re-scan depth (obfuscation stops at 1)
    ai_enabled: bool = False
    extra: dict = field(default_factory=dict)


class Analyzer(Protocol):
    def analyze(self, parsed: ParsedFile, context: ScanContext) -> list[Finding]: ...


@dataclass(frozen=True)
class AnalyzerRule:
    """Descriptor for a rule implemented in Python rather than YAML."""

    id: str
    title: str
    severity: str
    category: str
    description: str


def get_analyzers() -> list:
    """Import and return all built-in analyzers (deterministic order)."""
    from skillcheck.analyzers import (
        dangerous_commands,
        exfiltration,
        hidden_content,
        injection_patterns,
        mcp_permissions,
        obfuscation,
    )

    return [
        hidden_content,
        injection_patterns,
        exfiltration,
        dangerous_commands,
        obfuscation,
        mcp_permissions,
    ]


def get_analyzer_rules() -> list[AnalyzerRule]:
    rules: list[AnalyzerRule] = []
    for module in get_analyzers():
        rules.extend(getattr(module, "ANALYZER_RULES", []))
    return rules
