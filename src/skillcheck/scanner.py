"""Scan orchestrator: discovery → parse → rule engine + analyzers → result.

Read-only by design: this module opens files for reading and never writes.
"""

from __future__ import annotations

import time
from pathlib import Path

from skillcheck.analyzers import ScanContext, get_analyzers, llm_analyzer
from skillcheck.config import ScanConfig, inline_suppressed
from skillcheck.discovery import discover
from skillcheck.models import Finding, ScanResult
from skillcheck.parsers import parse_file
from skillcheck.rule_engine import RuleEngine


def scan(
    root: Path,
    config: ScanConfig | None = None,
    ai: bool = False,
    http_client: object | None = None,
) -> ScanResult:
    config = config or ScanConfig()
    root = root.resolve()
    started = time.perf_counter()

    extra_dirs = [config.custom_rules_dir] if config.custom_rules_dir else []
    engine = RuleEngine(extra_dirs=extra_dirs, ignore_rules=config.ignore_rules)
    context = ScanContext(
        rule_engine=engine,
        ai_enabled=ai,
        extra={"http_client": http_client} if http_client else {},
    )
    analyzers = get_analyzers()

    targets = discover(
        root,
        extra_targets=config.extra_targets,
        ignore_paths=config.ignore_paths,
        respect_gitignore=config.respect_gitignore,
    )

    base = root if root.is_dir() else root.parent
    findings: list[Finding] = []
    for rel_path, kind in targets:
        abs_path = root if root.is_file() else base / rel_path
        parsed = parse_file(abs_path, kind)
        parsed.path = rel_path  # findings report root-relative paths
        file_findings = engine.analyze(parsed)
        for analyzer in analyzers:
            file_findings.extend(analyzer.analyze(parsed, context))
        if ai:
            file_findings.extend(llm_analyzer.analyze(parsed, context))
        for finding in file_findings:
            if finding.rule_id in config.ignore_rules:
                continue
            if config.is_allowed(finding):
                continue
            if inline_suppressed(finding, parsed.lines):
                continue
            findings.append(finding)

    duration_ms = int((time.perf_counter() - started) * 1000)
    return ScanResult(
        root=root,
        files_scanned=len(targets),
        duration_ms=duration_ms,
        findings=findings,
    )
