"""File parsers producing ParsedFile objects with line-accurate metadata."""

from pathlib import Path

from skillcheck.models import FileKind, ParsedFile
from skillcheck.parsers.jsonyaml import parse_json, parse_yaml
from skillcheck.parsers.markdown import parse_markdown

__all__ = ["parse_file", "parse_json", "parse_markdown", "parse_yaml"]


def parse_file(path: Path, kind: FileKind, raw: str | None = None) -> ParsedFile:
    if raw is None:
        raw = path.read_text(encoding="utf-8", errors="replace")
    if kind is FileKind.MARKDOWN:
        return parse_markdown(path, raw)
    if kind is FileKind.JSON:
        return parse_json(path, raw)
    return parse_yaml(path, raw)
