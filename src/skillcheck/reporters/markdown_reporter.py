"""Markdown reporter — suitable for pasting into a PR comment."""

from __future__ import annotations

from skillcheck import __version__
from skillcheck.models import ScanResult, Severity

_EMOJI = {
    Severity.HIGH: "🔴",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def render(result: ScanResult) -> str:
    lines = [
        "## 🛡 skillcheck report",
        "",
        f"Scanned **{result.files_scanned}** file(s) in {result.duration_ms / 1000:.1f}s "
        f"(skillcheck v{__version__}).",
        "",
    ]
    if not result.findings:
        lines.append("✅ **No issues found.**")
        return "\n".join(lines) + "\n"
    counts = result.counts
    summary = " · ".join(
        f"{_EMOJI[sev]} {counts[sev]} {sev.value}" for sev in Severity if counts[sev]
    )
    lines += [summary, "", "| Severity | Location | Rule | Finding |", "|---|---|---|---|"]
    for finding in result.sorted_findings():
        location = finding.file.as_posix() + (f":{finding.line}" if finding.line else "")
        message = finding.message.replace("|", "\\|")
        if finding.snippet:
            safe_snippet = finding.snippet.replace("|", "\\|")
            snippet = f"<br><code>{safe_snippet}</code>"
        else:
            snippet = ""
        lines.append(
            f"| {_EMOJI[finding.severity]} {finding.severity.value.upper()} "
            f"| `{location}` | `{finding.rule_id}` | {message}{snippet} |"
        )
    return "\n".join(lines) + "\n"
