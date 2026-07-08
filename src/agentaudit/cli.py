"""agentaudit CLI (Typer)."""

from __future__ import annotations

import contextlib
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from agentaudit import __version__
from agentaudit.analyzers import get_analyzer_rules
from agentaudit.config import ConfigError, load_config
from agentaudit.models import Severity
from agentaudit.reporters import console as console_reporter
from agentaudit.reporters import json_reporter, markdown_reporter, sarif
from agentaudit.rule_engine import RuleEngine, RuleLoadError
from agentaudit.scanner import scan as run_scan

app = typer.Typer(
    name="agentaudit",
    help="Read-only security scanner for AI agent skills, rule files, and MCP configs.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_show_locals=False,
)


def _prefer_utf8() -> None:
    """Best-effort switch of stdio to UTF-8 so Windows legacy consoles don't
    crash on the shield emoji / unicode snippets."""
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(AttributeError, ValueError):
            stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]


_prefer_utf8()
_stdout = Console()
_stderr = Console(stderr=True)

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


@app.command("scan")
def scan_command(
    path: Path = typer.Argument(Path("."), help="Directory or file to scan."),
    output_format: str = typer.Option(
        "pretty", "--format", "-f", help="Output format: pretty | json | sarif | md."
    ),
    ai: bool = typer.Option(False, "--ai", help="Enable the optional LLM deep-scan (needs ANTHROPIC_API_KEY)."),
    fail_on: str | None = typer.Option(
        None, "--fail-on", help="Exit 1 at/above this severity: high | medium | low | info."
    ),
    rules_dir: Path | None = typer.Option(
        None, "--rules", help="Directory of additional custom rule YAML files."
    ),
    no_gitignore: bool = typer.Option(False, "--no-gitignore", help="Scan gitignored files too."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress the pretty report (exit code only)."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Include remediation advice in output."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write the report to a file."),
) -> None:
    """Scan PATH (default: current directory) for malicious agent instructions."""
    if not path.exists():
        _stderr.print(f"[red]error:[/red] path does not exist: {path}")
        raise typer.Exit(EXIT_ERROR)
    if output_format not in ("pretty", "json", "sarif", "md"):
        _stderr.print(f"[red]error:[/red] unknown format: {output_format}")
        raise typer.Exit(EXIT_ERROR)

    try:
        config = load_config(path.resolve())
    except ConfigError as exc:
        _stderr.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(EXIT_ERROR) from None

    if fail_on:
        try:
            config.fail_on = Severity.from_str(fail_on)
        except ValueError:
            _stderr.print(f"[red]error:[/red] invalid --fail-on: {fail_on}")
            raise typer.Exit(EXIT_ERROR) from None
    if rules_dir:
        config.custom_rules_dir = rules_dir.resolve()
    if no_gitignore:
        config.respect_gitignore = False

    try:
        result = run_scan(path, config=config, ai=ai)
    except RuleLoadError as exc:
        _stderr.print(f"[red]rule error:[/red] {exc}")
        raise typer.Exit(EXIT_ERROR) from None
    except Exception as exc:  # noqa: BLE001 — CLI boundary
        _stderr.print(f"[red]internal error:[/red] {exc}")
        raise typer.Exit(EXIT_ERROR) from None

    if output_format == "json":
        report = json_reporter.render(result)
    elif output_format == "sarif":
        report = sarif.render(result)
    elif output_format == "md":
        report = markdown_reporter.render(result)
    else:
        report = None

    if output:
        if report is None:
            capture = Console(record=True, width=120)
            console_reporter.render(result, console=capture, verbose=verbose)
            report = capture.export_text()
        output.write_text(report, encoding="utf-8")
        if not quiet:
            _stderr.print(f"report written to {output}")
    elif report is not None:
        sys.stdout.write(report + "\n")
    elif not quiet:
        console_reporter.render(result, console=_stdout, verbose=verbose)

    raise typer.Exit(result.exit_code(config.fail_on))


@app.command("rules")
def rules_command(
    explain: str | None = typer.Option(None, "--explain", help="Show full details for one rule ID."),
) -> None:
    """List all loaded detection rules."""
    try:
        engine = RuleEngine()
    except RuleLoadError as exc:
        _stderr.print(f"[red]rule error:[/red] {exc}")
        raise typer.Exit(EXIT_ERROR) from None
    analyzer_rules = get_analyzer_rules()

    if explain:
        rule = engine.get(explain)
        if rule:
            _stdout.print(f"[bold]{rule.id}[/bold] — {rule.title}")
            _stdout.print(f"severity: {rule.severity.value} · category: {rule.category} · applies to: {', '.join(rule.applies_to)}")
            if rule.description:
                _stdout.print(f"\n{rule.description}")
            if rule.remediation:
                _stdout.print(f"[italic]remediation:[/italic] {rule.remediation}")
            for pattern in rule.patterns:
                _stdout.print(f"  pattern: [dim]{pattern.pattern}[/dim]")
            if rule.examples.get("match"):
                _stdout.print(f"  matches:    {rule.examples['match']}")
            if rule.examples.get("no_match"):
                _stdout.print(f"  no match:   {rule.examples['no_match']}")
            for ref in rule.references:
                _stdout.print(f"  ref: {ref}")
            return
        for arule in analyzer_rules:
            if arule.id == explain:
                _stdout.print(f"[bold]{arule.id}[/bold] — {arule.title}")
                _stdout.print(f"severity: {arule.severity} · category: {arule.category} · implemented in Python analyzer")
                _stdout.print(f"\n{arule.description}")
                return
        _stderr.print(f"[red]error:[/red] unknown rule id: {explain}")
        raise typer.Exit(EXIT_ERROR)

    table = Table(title=f"agentaudit rules ({len(engine.rules) + len(analyzer_rules)} loaded)", box=None, padding=(0, 2))
    table.add_column("ID", style="bold")
    table.add_column("Severity")
    table.add_column("Category", style="dim")
    table.add_column("Title")
    table.add_column("Source", style="dim")
    for rule in engine.rules:
        table.add_row(rule.id, rule.severity.value, rule.category, rule.title, rule.source)
    for arule in analyzer_rules:
        table.add_row(arule.id, arule.severity, arule.category, arule.title, "analyzer")
    _stdout.print(table)


@app.command("version")
def version_command() -> None:
    """Print the agentaudit version."""
    _stdout.print(f"agentaudit {__version__}")


def main() -> None:  # pragma: no cover
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
