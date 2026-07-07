"""Fixture-driven corpus tests: the regression suite and the demo material.

Every malicious fixture asserts the rule IDs in its expected.json fire; every
benign fixture asserts no finding at or above MEDIUM (its false-positive guard).
"""

from __future__ import annotations

from pathlib import Path

from skillcheck.models import Severity
from skillcheck.scanner import scan
from tests.conftest import _target_file, load_expected


def _scan_fixture(fixture_dir: Path):
    target = _target_file(fixture_dir)
    result = scan(target)
    return result, {f.rule_id for f in result.findings}


def test_malicious_fixture(malicious_fixture: Path):
    expected = load_expected(malicious_fixture)
    _result, fired = _scan_fixture(malicious_fixture)
    for rule_id in expected["must_fire"]:
        assert rule_id in fired, (
            f"{malicious_fixture.name}: expected {rule_id} to fire; got {sorted(fired)}"
        )
    for rule_id in expected.get("must_not_fire", []):
        assert rule_id not in fired, f"{malicious_fixture.name}: {rule_id} should not fire"


def test_benign_fixture(benign_fixture: Path):
    expected = load_expected(benign_fixture)
    result, fired = _scan_fixture(benign_fixture)
    max_sev = Severity.from_str(expected.get("max_severity", "low"))
    offenders = [f for f in result.findings if f.severity > max_sev]
    assert not offenders, (
        f"{benign_fixture.name}: unexpected finding(s) above {max_sev.value}: "
        + ", ".join(f"{f.rule_id}@L{f.line}" for f in offenders)
    )
    for rule_id in expected.get("must_not_fire", []):
        assert rule_id not in fired, f"{benign_fixture.name}: {rule_id} false positive"
