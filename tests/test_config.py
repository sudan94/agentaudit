from __future__ import annotations

from pathlib import Path

from agentaudit.config import inline_suppressed, load_config
from agentaudit.models import Finding, Severity


def _finding(rule_id="AA-INJ-001", path="SKILL.md", line=5):
    return Finding(
        rule_id=rule_id,
        severity=Severity.HIGH,
        category="injection",
        file=Path(path),
        line=line,
        message="x",
    )


def test_load_config_defaults(tmp_path: Path):
    config = load_config(tmp_path)
    assert config.fail_on is Severity.HIGH
    assert config.respect_gitignore is True


def test_load_config_values(tmp_path: Path):
    (tmp_path / ".agentaudit.yml").write_text(
        "fail_on: medium\n"
        "ignore_paths:\n  - docs/**\n"
        "ignore_rules:\n  - AA-CMD-002\n"
        "allow:\n  - rule: AA-INJ-001\n    path: SKILL.md\n    reason: fp\n"
        "extra_targets:\n  - prompts/**/*.md\n",
        encoding="utf-8",
    )
    config = load_config(tmp_path)
    assert config.fail_on is Severity.MEDIUM
    assert config.ignore_paths == ["docs/**"]
    assert "AA-CMD-002" in config.ignore_rules
    assert config.extra_targets == ["prompts/**/*.md"]
    assert config.is_allowed(_finding())
    assert not config.is_allowed(_finding(rule_id="AA-INJ-002"))


def test_inline_suppression():
    lines = [
        "intro",
        "<!-- agentaudit: ignore AA-INJ-001 -->",
        "the offending line",
        "unrelated",
    ]
    assert inline_suppressed(_finding(line=3), lines) is True
    assert inline_suppressed(_finding(rule_id="AA-INJ-999", line=3), lines) is False


def test_inline_suppression_all():
    lines = ["<!-- agentaudit: ignore all -->", "offending line"]
    assert inline_suppressed(_finding(line=2), lines) is True
