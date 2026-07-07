from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console

from skillcheck.models import Finding, ScanResult, Severity
from skillcheck.reporters import console as console_reporter
from skillcheck.reporters import json_reporter, markdown_reporter, sarif


def _result():
    return ScanResult(
        root=Path("."),
        files_scanned=3,
        duration_ms=42,
        findings=[
            Finding("SC-INJ-001", Severity.HIGH, "injection", Path("SKILL.md"), "override", line=7, column=1, snippet="ignore all previous"),
            Finding("SC-MCP-005", Severity.INFO, "mcp", Path(".claude/settings.json"), "hook", line=3),
        ],
    )


def test_json_reporter_roundtrip():
    payload = json.loads(json_reporter.render(_result()))
    assert payload["tool"] == "skillcheck"
    assert payload["files_scanned"] == 3
    assert payload["counts"]["high"] == 1
    assert payload["findings"][0]["rule_id"] == "SC-INJ-001"


def test_sarif_shape():
    payload = json.loads(sarif.render(_result()))
    assert payload["version"] == "2.1.0"
    run = payload["runs"][0]
    assert run["tool"]["driver"]["name"] == "skillcheck"
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 7


def test_markdown_reporter_has_table():
    md = markdown_reporter.render(_result())
    assert "skillcheck report" in md
    assert "| Severity |" in md
    assert "SC-INJ-001" in md


def test_console_reporter_renders():
    capture = Console(record=True, width=100)
    console_reporter.render(_result(), console=capture)
    text = capture.export_text()
    assert "skillcheck" in text
    assert "SC-INJ-001" in text
    assert "HIGH" in text


def test_console_reporter_clean():
    capture = Console(record=True, width=100)
    clean = ScanResult(root=Path("."), files_scanned=1, duration_ms=1, findings=[])
    console_reporter.render(clean, console=capture)
    assert "No issues found" in capture.export_text()
