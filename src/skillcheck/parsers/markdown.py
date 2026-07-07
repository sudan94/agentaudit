"""Markdown parser: lines, YAML frontmatter, HTML comments, code fences, links and URLs.

Everything is tracked by 1-based line number so findings can point at the
exact location in the file.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from skillcheck.models import FileKind, ParsedFile

_FENCE_RE = re.compile(r"^(\s*)(```+|~~~+)\s*(\S*)")
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_INLINE_LINK_RE = re.compile(r"\[([^\]]*)\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
_REF_DEF_RE = re.compile(r"^\s*\[([^\]]+)\]:\s+(\S+)")
_BARE_URL_RE = re.compile(r"https?://[^\s<>\")\]]+", re.IGNORECASE)

#: Words in surrounding prose that mark a code fence as a documented example
#: rather than an instruction the agent is told to execute.
_EXAMPLE_MARKERS = re.compile(
    r"(?i)\b(example|examples|e\.g\.|for instance|sample|illustration|"
    r"do not run|don'?t run|never run|avoid|bad practice|anti-pattern|dangerous pattern|"
    r"what it catches|detects?|flags?|such as)\b"
)


@dataclass
class HtmlComment:
    line: int  # 1-based line where the comment starts
    text: str  # inner text of the comment


@dataclass
class CodeFence:
    start: int  # 1-based line of the opening fence
    end: int  # 1-based line of the closing fence (or last line if unterminated)
    lang: str
    is_example: bool  # surrounding prose marks this as a documented example


@dataclass
class LinkRef:
    line: int
    text: str
    url: str
    is_reference_def: bool = False


def parse_markdown(path: Path, raw: str) -> ParsedFile:
    lines = raw.splitlines()
    frontmatter, fm_end = _extract_frontmatter(lines)
    fences = _extract_fences(lines)
    comments = _extract_html_comments(raw)
    links = _extract_links(lines)
    urls = _extract_urls(lines)
    return ParsedFile(
        path=path,
        kind=FileKind.MARKDOWN,
        raw=raw,
        lines=lines,
        metadata={
            "frontmatter": frontmatter,
            "frontmatter_end": fm_end,  # 1-based line of closing ---, or 0
            "fences": fences,
            "html_comments": comments,
            "links": links,
            "urls": urls,  # list[(line, url)]
        },
    )


def line_in_fence(fences: list[CodeFence], line: int) -> CodeFence | None:
    for fence in fences:
        if fence.start < line < fence.end:
            return fence
    return None


def _extract_frontmatter(lines: list[str]) -> tuple[dict, int]:
    if not lines or lines[0].strip() != "---":
        return {}, 0
    for idx in range(1, len(lines)):
        if lines[idx].strip() in ("---", "..."):
            block = "\n".join(lines[1:idx])
            try:
                data = yaml.safe_load(block)
            except yaml.YAMLError:
                return {}, idx + 1
            return (data if isinstance(data, dict) else {}), idx + 1
    return {}, 0


def _extract_fences(lines: list[str]) -> list[CodeFence]:
    fences: list[CodeFence] = []
    open_fence: tuple[int, str, str] | None = None  # (line, marker, lang)
    for idx, line in enumerate(lines, start=1):
        match = _FENCE_RE.match(line)
        if not match:
            continue
        marker, lang = match.group(2), match.group(3)
        if open_fence is None:
            open_fence = (idx, marker[0] * 3, lang)
        elif marker.startswith(open_fence[1][0]) and not lang:
            start, _, fence_lang = open_fence
            fences.append(
                CodeFence(
                    start=start,
                    end=idx,
                    lang=fence_lang,
                    is_example=_looks_like_example(lines, start),
                )
            )
            open_fence = None
    if open_fence is not None:
        start, _, fence_lang = open_fence
        fences.append(
            CodeFence(
                start=start,
                end=len(lines),
                lang=fence_lang,
                is_example=_looks_like_example(lines, start),
            )
        )
    return fences


def _looks_like_example(lines: list[str], fence_start: int) -> bool:
    """Check the 3 non-empty prose lines above a fence for example markers."""
    seen = 0
    for idx in range(fence_start - 2, -1, -1):
        text = lines[idx].strip()
        if not text:
            continue
        if _EXAMPLE_MARKERS.search(text):
            return True
        seen += 1
        if seen >= 3:
            break
    return False


def _extract_html_comments(raw: str) -> list[HtmlComment]:
    comments: list[HtmlComment] = []
    for match in _HTML_COMMENT_RE.finditer(raw):
        line = raw.count("\n", 0, match.start()) + 1
        comments.append(HtmlComment(line=line, text=match.group(1).strip()))
    return comments


def _extract_links(lines: list[str]) -> list[LinkRef]:
    links: list[LinkRef] = []
    for idx, line in enumerate(lines, start=1):
        for match in _INLINE_LINK_RE.finditer(line):
            links.append(LinkRef(line=idx, text=match.group(1), url=match.group(2)))
        ref = _REF_DEF_RE.match(line)
        if ref:
            links.append(
                LinkRef(line=idx, text=ref.group(1), url=ref.group(2), is_reference_def=True)
            )
    return links


def _extract_urls(lines: list[str]) -> list[tuple[int, str]]:
    urls: list[tuple[int, str]] = []
    for idx, line in enumerate(lines, start=1):
        for match in _BARE_URL_RE.finditer(line):
            urls.append((idx, match.group(0).rstrip(".,;:!?'\"")))
    return urls
