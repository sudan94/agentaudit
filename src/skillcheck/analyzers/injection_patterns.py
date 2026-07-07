"""Injection-pattern analyzer.

Deliberately thin: injection phrasing is exactly what the YAML rule engine is
for, so all deception/override/persistence patterns live in
``rules/injection.yml`` (SC-INJ-001 … SC-INJ-007) where the community can
extend them without touching Python. This module exists to host any future
injection checks that need real parsing context rather than a regex.
"""

from __future__ import annotations

from skillcheck.analyzers import ScanContext
from skillcheck.models import Finding, ParsedFile

ANALYZER_RULES: list = []


def analyze(parsed: ParsedFile, context: ScanContext) -> list[Finding]:
    return []
