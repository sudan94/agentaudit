from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from skillcheck.cli import app

runner = CliRunner()
MAL = Path(__file__).parent / "fixtures" / "malicious"
BEN = Path(__file__).parent / "fixtures" / "benign"


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "skillcheck" in result.stdout


def test_rules_list():
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    assert "SC-INJ-001" in result.stdout


def test_rules_explain():
    result = runner.invoke(app, ["rules", "--explain", "SC-INJ-001"])
    assert result.exit_code == 0
    assert "override" in result.stdout.lower()


def test_scan_malicious_exit_1():
    result = runner.invoke(app, ["scan", str(MAL / "env_exfiltration"), "--format", "json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    ids = {f["rule_id"] for f in payload["findings"]}
    assert "SC-EXF-001" in ids


def test_scan_benign_exit_0():
    result = runner.invoke(app, ["scan", str(BEN / "normal_skill"), "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["counts"]["high"] == 0


def test_scan_fail_on_threshold():
    # A benign fixture with only low/info findings stays exit 0 even at --fail-on low
    # if nothing reaches it; but a high-finding fixture flips to 1.
    high = runner.invoke(app, ["scan", str(MAL / "curl_pipe_sh"), "--fail-on", "high", "-q"])
    assert high.exit_code == 1


def test_scan_missing_path_exit_2():
    result = runner.invoke(app, ["scan", "does-not-exist-xyz"])
    assert result.exit_code == 2


def test_scan_output_to_file(tmp_path: Path):
    out = tmp_path / "report.json"
    result = runner.invoke(
        app, ["scan", str(MAL / "env_exfiltration"), "--format", "json", "-o", str(out)]
    )
    assert result.exit_code == 1
    assert out.is_file()
    json.loads(out.read_text(encoding="utf-8"))


def test_scan_sarif_format():
    result = runner.invoke(app, ["scan", str(MAL / "mcp_overreach"), "--format", "sarif"])
    payload = json.loads(result.stdout)
    assert payload["version"] == "2.1.0"
