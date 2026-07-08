from __future__ import annotations

from pathlib import Path

import pytest

from agentaudit.models import FileKind, ParsedFile, Severity
from agentaudit.parsers.markdown import parse_markdown
from agentaudit.rule_engine import (
    RuleEngine,
    RuleLoadError,
    _load_rules_from_text,
    load_builtin_rules,
)

_KIND = {"json": FileKind.JSON, "yaml": FileKind.YAML, "markdown": FileKind.MARKDOWN}


def _parse_as_rule_kind(rule, text: str) -> ParsedFile:
    # Pick a parser kind the rule applies to, so applies_to filtering doesn't skip it.
    kind = FileKind.MARKDOWN
    for name in ("markdown", "json", "yaml"):
        if name in rule.applies_to:
            kind = _KIND[name]
            break
    if kind is FileKind.MARKDOWN:
        return parse_markdown(Path("t.md"), text)
    return ParsedFile(path=Path("t"), kind=kind, raw=text, lines=text.splitlines(), metadata={})


def test_builtin_rules_load_and_are_unique():
    rules = load_builtin_rules()
    assert len(rules) >= 20
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids))


def test_engine_ignore_rules():
    engine = RuleEngine(ignore_rules={"AA-INJ-001"})
    assert engine.get("AA-INJ-001") is None
    assert engine.get("AA-INJ-003") is not None


def test_rule_matches_expected_examples():
    engine = RuleEngine()
    for rule in engine.rules:
        match = rule.examples.get("match")
        if match:
            parsed = _parse_as_rule_kind(rule, match)
            fired = {f.rule_id for f in engine.analyze(parsed)}
            assert rule.id in fired, f"{rule.id} failed to match its own example"


def test_rule_no_match_examples_are_clean():
    engine = RuleEngine()
    for rule in engine.rules:
        no_match = rule.examples.get("no_match")
        if no_match:
            parsed = _parse_as_rule_kind(rule, no_match)
            fired = {f.rule_id for f in engine.analyze(parsed)}
            assert rule.id not in fired, f"{rule.id} false-matched its no_match example"


def test_example_fence_downgrades_severity():
    engine = RuleEngine()
    raw = "For example:\n```bash\nrm -rf /tmp/build\n```\n"
    parsed = parse_markdown(Path("t.md"), raw)
    findings = [f for f in engine.analyze(parsed) if f.rule_id == "AA-CMD-002"]
    assert findings
    assert findings[0].severity <= Severity.LOW


def test_imperative_fence_keeps_severity():
    engine = RuleEngine()
    raw = "Run this now:\n```bash\nrm -rf /tmp/build\n```\n"
    parsed = parse_markdown(Path("t.md"), raw)
    findings = [f for f in engine.analyze(parsed) if f.rule_id == "AA-CMD-002"]
    assert findings
    assert findings[0].severity is Severity.HIGH


def test_bad_rule_id_rejected():
    with pytest.raises(RuleLoadError):
        _load_rules_from_text("- id: BADID\n  severity: high\n  patterns: [x]\n", "t")


def test_bad_regex_rejected():
    text = "- id: AA-XX-001\n  severity: high\n  patterns:\n    - regex: '('\n"
    with pytest.raises(RuleLoadError):
        _load_rules_from_text(text, "t")


def test_custom_rules_dir(tmp_path: Path):
    rule_file = tmp_path / "custom.yml"
    rule_file.write_text(
        "- id: AA-CUS-001\n"
        "  title: Custom test rule\n"
        "  severity: medium\n"
        "  category: injection\n"
        "  applies_to: [markdown]\n"
        "  patterns:\n"
        "    - regex: 'forbidden-token'\n",
        encoding="utf-8",
    )
    engine = RuleEngine(extra_dirs=[tmp_path])
    assert engine.get("AA-CUS-001") is not None
    parsed = parse_markdown(Path("t.md"), "this has a forbidden-token in it")
    assert any(f.rule_id == "AA-CUS-001" for f in engine.analyze(parsed))
