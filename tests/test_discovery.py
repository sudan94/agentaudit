from __future__ import annotations

from pathlib import Path

from agentaudit.discovery import classify, discover
from agentaudit.models import FileKind


def test_classify_known_targets():
    assert classify(Path("SKILL.md")) is FileKind.MARKDOWN
    assert classify(Path("CLAUDE.md")) is FileKind.MARKDOWN
    assert classify(Path(".cursorrules")) is FileKind.MARKDOWN
    assert classify(Path("AGENTS.md")) is FileKind.MARKDOWN
    assert classify(Path(".mcp.json")) is FileKind.JSON
    assert classify(Path(".claude/settings.json")) is FileKind.JSON
    assert classify(Path("skills/foo/helper.md")) is FileKind.MARKDOWN
    assert classify(Path(".cursor/rules/x.mdc")) is FileKind.MARKDOWN
    assert classify(Path(".github/copilot-instructions.md")) is FileKind.MARKDOWN


def test_classify_ignores_unrelated():
    assert classify(Path("README.md")) is None
    assert classify(Path("main.py")) is None
    assert classify(Path("package.json")) is None


def test_discover_walks_tree_and_skips_dirs(tmp_path: Path):
    (tmp_path / "SKILL.md").write_text("x", encoding="utf-8")
    (tmp_path / ".mcp.json").write_text("{}", encoding="utf-8")
    (tmp_path / "README.md").write_text("x", encoding="utf-8")
    nm = tmp_path / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / "SKILL.md").write_text("x", encoding="utf-8")
    sub = tmp_path / "skills" / "a"
    sub.mkdir(parents=True)
    (sub / "guide.md").write_text("x", encoding="utf-8")

    found = {p.as_posix() for p, _ in discover(tmp_path)}
    assert "SKILL.md" in found
    assert ".mcp.json" in found
    assert "skills/a/guide.md" in found
    assert "README.md" not in found
    assert not any("node_modules" in f for f in found)


def test_discover_respects_gitignore(tmp_path: Path):
    (tmp_path / ".gitignore").write_text("ignored/\n", encoding="utf-8")
    ign = tmp_path / "ignored"
    ign.mkdir()
    (ign / "SKILL.md").write_text("x", encoding="utf-8")
    (tmp_path / "SKILL.md").write_text("x", encoding="utf-8")

    respected = {p.as_posix() for p, _ in discover(tmp_path, respect_gitignore=True)}
    assert "ignored/SKILL.md" not in respected
    assert "SKILL.md" in respected

    override = {p.as_posix() for p, _ in discover(tmp_path, respect_gitignore=False)}
    assert "ignored/SKILL.md" in override


def test_discover_single_file(tmp_path: Path):
    f = tmp_path / "CLAUDE.md"
    f.write_text("x", encoding="utf-8")
    targets = discover(f)
    assert targets == [(Path("CLAUDE.md"), FileKind.MARKDOWN)]


def test_extra_targets(tmp_path: Path):
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "sys.md").write_text("x", encoding="utf-8")
    without = {p.as_posix() for p, _ in discover(tmp_path)}
    assert "prompts/sys.md" not in without
    with_extra = {p.as_posix() for p, _ in discover(tmp_path, extra_targets=["prompts/**/*.md"])}
    assert "prompts/sys.md" in with_extra
