"""Project configuration: ``.skillcheck.yml`` plus inline suppressions."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from skillcheck.discovery import glob_match
from skillcheck.models import Finding, Severity

CONFIG_FILENAME = ".skillcheck.yml"

_INLINE_SUPPRESS_RE = re.compile(
    r"skillcheck:\s*ignore\s+(?P<ids>(?:SC-[A-Z]{2,4}-\d{3}|all)(?:\s*,\s*SC-[A-Z]{2,4}-\d{3})*)",
    re.IGNORECASE,
)


@dataclass
class AllowEntry:
    rule: str
    path: str
    reason: str = ""


@dataclass
class ScanConfig:
    fail_on: Severity = Severity.HIGH
    ignore_paths: list[str] = field(default_factory=list)
    ignore_rules: set[str] = field(default_factory=set)
    allow: list[AllowEntry] = field(default_factory=list)
    custom_rules_dir: Path | None = None
    extra_targets: list[str] = field(default_factory=list)
    respect_gitignore: bool = True

    def is_allowed(self, finding: Finding) -> bool:
        posix = finding.file.as_posix()
        return any(
            entry.rule == finding.rule_id and glob_match(posix, entry.path)
            for entry in self.allow
        )


class ConfigError(Exception):
    pass


def load_config(root: Path) -> ScanConfig:
    config_path = root / CONFIG_FILENAME if root.is_dir() else root.parent / CONFIG_FILENAME
    config = ScanConfig()
    if not config_path.is_file():
        return config
    try:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{config_path}: invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{config_path}: expected a mapping")
    if "fail_on" in data:
        try:
            config.fail_on = Severity.from_str(str(data["fail_on"]))
        except ValueError as exc:
            raise ConfigError(f"{config_path}: fail_on must be high/medium/low/info") from exc
    config.ignore_paths = [str(p) for p in data.get("ignore_paths", [])]
    config.ignore_rules = {str(r) for r in data.get("ignore_rules", [])}
    for entry in data.get("allow", []):
        if isinstance(entry, dict) and "rule" in entry and "path" in entry:
            config.allow.append(
                AllowEntry(
                    rule=str(entry["rule"]),
                    path=str(entry["path"]),
                    reason=str(entry.get("reason", "")),
                )
            )
    if data.get("custom_rules_dir"):
        base = config_path.parent
        config.custom_rules_dir = (base / str(data["custom_rules_dir"])).resolve()
    config.extra_targets = [str(t) for t in data.get("extra_targets", [])]
    return config


def inline_suppressed(finding: Finding, lines: list[str]) -> bool:
    """True if the finding's line or the one above carries a suppression comment
    naming this rule (or 'all')."""
    if finding.line is None:
        return False
    candidates = []
    if 1 <= finding.line <= len(lines):
        candidates.append(lines[finding.line - 1])
    if finding.line >= 2:
        candidates.append(lines[finding.line - 2])
    for text in candidates:
        match = _INLINE_SUPPRESS_RE.search(text)
        if match:
            ids = {part.strip().upper() for part in match.group("ids").split(",")}
            if "ALL" in ids or finding.rule_id in ids:
                return True
    return False
