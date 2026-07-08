"""Target discovery: walk a tree and classify files into scan targets.

Classification follows the target table in the README. Binary files,
dependency/VCS directories, and (by default) gitignored paths are skipped.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

from agentaudit.models import FileKind

_GLOB_CACHE: dict[str, re.Pattern] = {}


def glob_match(posix_path: str, pattern: str) -> bool:
    """fnmatch-style match that also understands ``**`` as cross-directory."""
    compiled = _GLOB_CACHE.get(pattern)
    if compiled is None:
        compiled = re.compile(_glob_to_regex(pattern))
        _GLOB_CACHE[pattern] = compiled
    return compiled.match(posix_path) is not None


def _glob_to_regex(pattern: str) -> str:
    i = 0
    out = ["(?s:"]
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "*":
            if pattern[i : i + 2] == "**":
                i += 2
                if pattern[i : i + 1] == "/":
                    i += 1
                    out.append("(?:.*/)?")  # zero or more directories
                else:
                    out.append(".*")
            else:
                out.append("[^/]*")
                i += 1
        elif ch == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(ch))
            i += 1
    out.append(r")\Z")
    return "".join(out)

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "venv",
    ".venv",
    "env",
    ".tox",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "dist",
    "build",
    ".eggs",
}

_JSON_BASENAMES = {
    ".mcp.json",
    "mcp.json",
    "claude_desktop_config.json",
}

_MARKDOWN_BASENAMES = {
    "skill.md",
    "claude.md",
    "claude.local.md",
    "agents.md",
    "gemini.md",
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
}


def classify(rel_path: Path) -> FileKind | None:
    """Classify a path (relative to the scan root) into a scan target kind."""
    posix = rel_path.as_posix().lower()
    name = rel_path.name.lower()
    if name in _JSON_BASENAMES or posix.endswith(".vscode/mcp.json"):
        return FileKind.JSON
    if posix.endswith(".claude/settings.json") or posix.endswith(".claude/settings.local.json"):
        return FileKind.JSON
    if name in _MARKDOWN_BASENAMES:
        return FileKind.MARKDOWN
    if name.endswith(".mdc") and "/.cursor/rules/" in f"/{posix}":
        return FileKind.MARKDOWN
    if posix.endswith(".github/copilot-instructions.md"):
        return FileKind.MARKDOWN
    if name.endswith(".md") and ("/skills/" in f"/{posix}" or ".skill/" in posix):
        return FileKind.MARKDOWN
    if name.endswith(".md") and ("/.claude/" in f"/{posix}" or posix.startswith(".claude/")):
        return FileKind.MARKDOWN
    return None


def classify_explicit(path: Path) -> FileKind:
    """Classify a file the user pointed at directly — always scan it."""
    kind = classify(Path(path.name))
    if kind:
        return kind
    suffix = path.suffix.lower()
    if suffix == ".json":
        return FileKind.JSON
    if suffix in (".yml", ".yaml"):
        return FileKind.YAML
    return FileKind.MARKDOWN


class GitignoreMatcher:
    """Minimal .gitignore support: literal names, globs, dir/ suffix,
    leading-/ anchors, and ** patterns. Root .gitignore only."""

    def __init__(self, root: Path):
        self.patterns: list[tuple[str, bool, bool]] = []  # (pattern, dir_only, anchored)
        gitignore = root / ".gitignore"
        if not gitignore.is_file():
            return
        for raw_line in gitignore.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue
            dir_only = line.endswith("/")
            line = line.rstrip("/")
            anchored = line.startswith("/")
            line = line.lstrip("/")
            if line:
                self.patterns.append((line, dir_only, anchored))

    def matches(self, rel_path: Path, is_dir: bool) -> bool:
        posix = rel_path.as_posix()
        parts = rel_path.parts
        for pattern, dir_only, anchored in self.patterns:
            if dir_only and not is_dir:
                # a dir pattern still hides files beneath that dir
                if not any(fnmatch.fnmatch(p, pattern) for p in parts[:-1]):
                    continue
                return True
            if anchored or "/" in pattern:
                if fnmatch.fnmatch(posix, pattern) or fnmatch.fnmatch(posix, pattern + "/*"):
                    return True
            else:
                if any(fnmatch.fnmatch(p, pattern) for p in parts):
                    return True
        return False


def _is_probably_binary(path: Path) -> bool:
    try:
        chunk = path.open("rb").read(1024)
    except OSError:
        return True
    return b"\x00" in chunk


def discover(
    root: Path,
    extra_targets: list[str] | None = None,
    ignore_paths: list[str] | None = None,
    respect_gitignore: bool = True,
) -> list[tuple[Path, FileKind]]:
    """Return (path, kind) scan targets under ``root``. Paths are relative to root."""
    root = root.resolve()
    if root.is_file():
        return [(Path(root.name), classify_explicit(root))]
    gitignore = GitignoreMatcher(root) if respect_gitignore else None
    extra = extra_targets or []
    ignores = ignore_paths or []
    targets: list[tuple[Path, FileKind]] = []

    def walk(directory: Path) -> None:
        try:
            entries = sorted(directory.iterdir(), key=lambda p: p.name.lower())
        except OSError:
            return
        for entry in entries:
            rel = entry.relative_to(root)
            if entry.is_dir():
                if entry.name in SKIP_DIRS:
                    continue
                if gitignore and gitignore.matches(rel, is_dir=True):
                    continue
                walk(entry)
                continue
            if gitignore and gitignore.matches(rel, is_dir=False):
                continue
            posix = rel.as_posix()
            if any(glob_match(posix, pat) for pat in ignores):
                continue
            kind = classify(rel)
            if kind is None and any(glob_match(posix, pat) for pat in extra):
                kind = classify_explicit(entry)
            if kind is None or _is_probably_binary(entry):
                continue
            targets.append((rel, kind))

    walk(root)
    return targets
