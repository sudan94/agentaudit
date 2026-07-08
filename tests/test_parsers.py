from __future__ import annotations

from pathlib import Path

from agentaudit.models import FileKind
from agentaudit.parsers import parse_file
from agentaudit.parsers.jsonyaml import find_line, strip_jsonc
from agentaudit.parsers.markdown import line_in_fence, parse_markdown


def test_markdown_frontmatter_and_lines():
    raw = "---\nname: demo\nversion: 1\n---\n# Title\nbody\n"
    parsed = parse_markdown(Path("x.md"), raw)
    assert parsed.metadata["frontmatter"] == {"name": "demo", "version": 1}
    assert parsed.metadata["frontmatter_end"] == 4
    assert parsed.lines[4] == "# Title"


def test_markdown_html_comment_line_tracking():
    raw = "line1\nline2\n<!-- hidden note -->\nline4\n"
    parsed = parse_markdown(Path("x.md"), raw)
    comments = parsed.metadata["html_comments"]
    assert len(comments) == 1
    assert comments[0].line == 3
    assert comments[0].text == "hidden note"


def test_markdown_multiline_html_comment_line():
    raw = "a\nb\n<!--\nmultiline\n-->\nc\n"
    parsed = parse_markdown(Path("x.md"), raw)
    assert parsed.metadata["html_comments"][0].line == 3


def test_fence_detection_and_example_flag():
    raw = (
        "Here is an example command:\n"
        "```bash\n"
        "rm -rf /tmp/x\n"
        "```\n"
        "Now run this for real:\n"
        "```bash\n"
        "echo hi\n"
        "```\n"
    )
    parsed = parse_markdown(Path("x.md"), raw)
    fences = parsed.metadata["fences"]
    assert len(fences) == 2
    assert fences[0].is_example is True
    assert fences[1].is_example is False
    assert line_in_fence(fences, 3).is_example is True
    assert line_in_fence(fences, 1) is None  # prose, not inside a fence


def test_markdown_url_and_link_extraction():
    raw = "See [docs](https://example.com/a) and https://bit.ly/x here.\n"
    parsed = parse_markdown(Path("x.md"), raw)
    urls = [u for _, u in parsed.metadata["urls"]]
    assert "https://example.com/a" in urls
    assert "https://bit.ly/x" in urls
    assert parsed.metadata["links"][0].url == "https://example.com/a"


def test_strip_jsonc_preserves_strings_and_lines():
    raw = '{\n  "url": "http://x//y", // comment\n  "n": 1\n}'
    stripped = strip_jsonc(raw)
    assert "// comment" not in stripped
    assert "http://x//y" in stripped  # slashes inside string untouched
    assert stripped.count("\n") == raw.count("\n")  # line count preserved


def test_parse_json_tolerates_comments_and_trailing_comma():
    raw = '{\n  // note\n  "a": 1,\n  "b": [1, 2,],\n}'
    parsed = parse_file(Path("c.json"), FileKind.JSON, raw)
    assert parsed.metadata["parse_error"] is None
    assert parsed.metadata["tree"] == {"a": 1, "b": [1, 2]}


def test_find_line():
    lines = ["alpha", "beta target", "gamma"]
    assert find_line(lines, "target") == 2
    assert find_line(lines, "missing") is None
