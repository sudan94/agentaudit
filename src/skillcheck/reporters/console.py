"""Pretty console reporter (Rich)."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text

from skillcheck import __version__
from skillcheck.models import ScanResult, Severity

_SEVERITY_STYLE = {
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold blue",
    Severity.INFO: "dim",
}


def _can_encode(console: Console, text: str) -> bool:
    encoding = getattr(console.file, "encoding", None) or "utf-8"
    try:
        text.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def render(result: ScanResult, console: Console | None = None, verbose: bool = False) -> None:
    console = console or Console()
    seconds = result.duration_ms / 1000
    shield = "🛡 " if _can_encode(console, "🛡") else "[skillcheck]"
    check = "✓" if _can_encode(console, "✓") else "OK:"
    console.print()
    console.print(
        f"  [bold]{shield} skillcheck[/bold] [dim]v{__version__}[/dim] — "
        f"scanned [bold]{result.files_scanned}[/bold] file(s) in {seconds:.1f}s"
    )
    console.print()

    if not result.findings:
        console.print(f"  [bold green]{check} No issues found.[/bold green]")
        console.print()
        return

    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    table.add_column("Severity", no_wrap=True)
    table.add_column("Location", no_wrap=True, style="cyan")
    table.add_column("Rule", no_wrap=True, style="dim")
    table.add_column("Finding")

    for finding in result.sorted_findings():
        location = finding.file.as_posix()
        if finding.line:
            location += f":{finding.line}"
        body = Text(finding.message)
        if finding.snippet:
            body.append("\n" + finding.snippet, style="dim")
        if verbose and finding.remediation:
            body.append("\n↳ " + finding.remediation, style="italic dim")
        table.add_row(
            Text(finding.severity.value.upper(), style=_SEVERITY_STYLE[finding.severity]),
            location,
            finding.rule_id,
            body,
        )
    console.print(table)
    console.print()
    console.print("  " + summary_line(result))
    console.print()


def summary_line(result: ScanResult) -> str:
    counts = result.counts
    parts = [
        f"[{_SEVERITY_STYLE[sev]}]{counts[sev]} {sev.value}[/]"
        for sev in Severity
        if counts[sev]
    ]
    return " · ".join(parts) if parts else "[green]clean[/green]"
