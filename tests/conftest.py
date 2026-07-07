from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def _fixture_dirs(kind: str) -> list[Path]:
    base = FIXTURES / kind
    return sorted(p for p in base.iterdir() if p.is_dir())


def _target_file(fixture_dir: Path) -> Path:
    for path in sorted(fixture_dir.rglob("*")):
        if path.is_file() and path.name != "expected.json":
            return path
    raise AssertionError(f"no target file in {fixture_dir}")


@pytest.fixture
def fixtures_root() -> Path:
    return FIXTURES


def load_expected(fixture_dir: Path) -> dict:
    return json.loads((fixture_dir / "expected.json").read_text(encoding="utf-8"))


def pytest_generate_tests(metafunc):
    if "malicious_fixture" in metafunc.fixturenames:
        dirs = _fixture_dirs("malicious")
        metafunc.parametrize("malicious_fixture", dirs, ids=[d.name for d in dirs])
    if "benign_fixture" in metafunc.fixturenames:
        dirs = _fixture_dirs("benign")
        metafunc.parametrize("benign_fixture", dirs, ids=[d.name for d in dirs])
