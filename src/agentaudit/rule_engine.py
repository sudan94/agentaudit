"""YAML-driven rule engine (detection Layer 2).

Rules are declarative regex patterns loaded from ``src/agentaudit/rules/*.yml``
plus any user-supplied directories. All regexes are compiled once at load time.
Markdown rules are fence-aware: a match inside a code fence that the parser
identified as a *documented example* is downgraded rather than reported at
full severity — a doc about dangerous commands is not itself dangerous.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

import yaml

from agentaudit.models import Finding, ParsedFile, Severity, escape_snippet
from agentaudit.parsers.markdown import line_in_fence

_RULE_ID_RE = re.compile(r"^AA-[A-Z]{2,4}-\d{3}$")


@dataclass
class Rule:
    id: str
    title: str
    severity: Severity
    category: str
    applies_to: list[str]  # markdown | json | yaml | all
    description: str
    patterns: list[re.Pattern] = field(default_factory=list)
    remediation: str | None = None
    examples: dict = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    #: What to do when a match falls inside a fence marked as a documented
    #: example: "keep" (report as-is), "downgrade" (drop to LOW), "skip".
    example_fences: str = "downgrade"
    source: str = "built-in"


class RuleLoadError(Exception):
    pass


def _parse_rule(data: dict, source: str) -> Rule:
    rule_id = data.get("id", "")
    if not _RULE_ID_RE.match(rule_id):
        raise RuleLoadError(f"{source}: invalid or missing rule id: {rule_id!r}")
    try:
        severity = Severity.from_str(data["severity"])
    except (KeyError, ValueError) as exc:
        raise RuleLoadError(f"{source}: rule {rule_id}: bad severity") from exc
    patterns = []
    for entry in data.get("patterns", []):
        regex = entry.get("regex") if isinstance(entry, dict) else entry
        if not regex:
            raise RuleLoadError(f"{source}: rule {rule_id}: empty pattern")
        try:
            patterns.append(re.compile(regex))
        except re.error as exc:
            raise RuleLoadError(f"{source}: rule {rule_id}: bad regex: {exc}") from exc
    if not patterns:
        raise RuleLoadError(f"{source}: rule {rule_id}: no patterns")
    applies_to = data.get("applies_to", ["all"])
    if isinstance(applies_to, str):
        applies_to = [applies_to]
    return Rule(
        id=rule_id,
        title=data.get("title", rule_id),
        severity=severity,
        category=data.get("category", "general"),
        applies_to=applies_to,
        description=str(data.get("description", "")).strip(),
        patterns=patterns,
        remediation=data.get("remediation"),
        examples=data.get("examples", {}),
        references=data.get("references", []),
        example_fences=data.get("example_fences", "downgrade"),
        source=source,
    )


def _load_rules_from_text(text: str, source: str) -> list[Rule]:
    data = yaml.safe_load(text)
    if data is None:
        return []
    if isinstance(data, dict) and "rules" in data:
        data = data["rules"]
    if not isinstance(data, list):
        raise RuleLoadError(f"{source}: expected a list of rules")
    return [_parse_rule(item, source) for item in data]


def load_builtin_rules() -> list[Rule]:
    rules: list[Rule] = []
    pkg = resources.files("agentaudit") / "rules"
    for entry in sorted(pkg.iterdir(), key=lambda e: e.name):
        if entry.name.endswith(".yml"):
            rules.extend(_load_rules_from_text(entry.read_text(encoding="utf-8"), entry.name))
    return rules


def load_rules_dir(directory: Path) -> list[Rule]:
    rules: list[Rule] = []
    for path in sorted(directory.glob("*.yml")) + sorted(directory.glob("*.yaml")):
        rules.extend(
            _load_rules_from_text(path.read_text(encoding="utf-8"), str(path))
        )
    return rules


class RuleEngine:
    def __init__(self, extra_dirs: list[Path] | None = None, ignore_rules: set[str] | None = None):
        self.rules = load_builtin_rules()
        for directory in extra_dirs or []:
            if directory.is_dir():
                self.rules.extend(load_rules_dir(directory))
        if ignore_rules:
            self.rules = [r for r in self.rules if r.id not in ignore_rules]
        seen: set[str] = set()
        for rule in self.rules:
            if rule.id in seen:
                raise RuleLoadError(f"duplicate rule id: {rule.id}")
            seen.add(rule.id)

    def get(self, rule_id: str) -> Rule | None:
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None

    def analyze(self, parsed: ParsedFile) -> list[Finding]:
        findings: list[Finding] = []
        kind = parsed.kind.value
        fences = parsed.metadata.get("fences", [])
        for rule in self.rules:
            if "all" not in rule.applies_to and kind not in rule.applies_to:
                continue
            for line_no, line in enumerate(parsed.lines, start=1):
                for pattern in rule.patterns:
                    match = pattern.search(line)
                    if not match:
                        continue
                    severity = rule.severity
                    note = ""
                    fence = line_in_fence(fences, line_no) if fences else None
                    if fence is not None and fence.is_example:
                        if rule.example_fences == "skip":
                            break
                        if rule.example_fences == "downgrade":
                            severity = Severity.LOW if severity > Severity.LOW else Severity.INFO
                            note = " (inside documented example)"
                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            severity=severity,
                            category=rule.category,
                            file=parsed.path,
                            line=line_no,
                            column=match.start() + 1,
                            message=rule.title + note,
                            snippet=escape_snippet(match.group(0)),
                            remediation=rule.remediation,
                        )
                    )
                    break  # one finding per rule per line
        return findings
