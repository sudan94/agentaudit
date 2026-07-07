"""Tolerant JSON / YAML parsing with best-effort line tracking.

JSON configs in the wild (VS Code, Claude Desktop) often contain `//` comments
and trailing commas, so we strip those before handing off to ``json.loads``.
Line numbers for findings are recovered by searching the raw text for the
key or value in question (see :func:`find_line`).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from skillcheck.models import FileKind, ParsedFile

_TRAILING_COMMA_RE = re.compile(r",(\s*[}\]])")


def strip_jsonc(raw: str) -> str:
    """Remove // and /* */ comments outside of strings; keep line count identical."""
    out: list[str] = []
    in_string = False
    in_line_comment = False
    in_block_comment = False
    escaped = False
    i = 0
    while i < len(raw):
        ch = raw[i]
        nxt = raw[i + 1] if i + 1 < len(raw) else ""
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
                out.append(ch)
            else:
                out.append(" ")
            i += 1
            continue
        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                out.append("  ")
                i += 2
            else:
                out.append(ch if ch == "\n" else " ")
                i += 1
            continue
        if in_string:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and nxt == "/":
            in_line_comment = True
            out.append("  ")
            i += 2
            continue
        if ch == "/" and nxt == "*":
            in_block_comment = True
            out.append("  ")
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def parse_json(path: Path, raw: str) -> ParsedFile:
    cleaned = _TRAILING_COMMA_RE.sub(r"\1", strip_jsonc(raw))
    tree: object = None
    error: str | None = None
    try:
        tree = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        error = str(exc)
    return ParsedFile(
        path=path,
        kind=FileKind.JSON,
        raw=raw,
        lines=raw.splitlines(),
        metadata={"tree": tree, "parse_error": error},
    )


def parse_yaml(path: Path, raw: str) -> ParsedFile:
    tree: object = None
    error: str | None = None
    try:
        tree = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        error = str(exc)
    return ParsedFile(
        path=path,
        kind=FileKind.YAML,
        raw=raw,
        lines=raw.splitlines(),
        metadata={"tree": tree, "parse_error": error},
    )


def find_line(lines: list[str], needle: str, start: int = 1) -> int | None:
    """Return the 1-based line number of the first line containing ``needle``."""
    for idx in range(start - 1, len(lines)):
        if needle in lines[idx]:
            return idx + 1
    return None
