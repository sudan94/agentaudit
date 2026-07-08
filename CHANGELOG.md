# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-07-07

Initial release.

### Added
- Directory/file discovery for agent skills, Claude/Cursor/generic rule files,
  MCP configs, and Claude settings, with `.gitignore` support.
- Markdown parser with line-accurate tracking of frontmatter, HTML comments,
  code fences (documented-example detection), and links/URLs.
- Tolerant JSON/YAML parser (JSONC comments, trailing commas).
- YAML rule engine with 26 built-in rules across injection, hidden-content,
  exfiltration, command, and MCP categories; custom rule directories supported.
- Deterministic analyzers: hidden content (HTML comments, zero-width, bidi,
  homoglyphs), cross-line exfiltration, imperative dangerous commands,
  base64/hex obfuscation with one-level re-scan, and MCP permission/hook checks.
- Optional `--ai` LLM deep-scan (injection-resistant, mocked in tests).
- Reporters: pretty console (Rich), JSON, SARIF 2.1.0, and markdown.
- `.agentaudit.yml` config plus inline `<!-- agentaudit: ignore ... -->` suppressions.
- CLI: `scan`, `rules`, `rules --explain`, `version`; exit codes 0/1/2.
- Fixture-driven corpus of malicious and benign samples; 74 tests; self-scan in CI.
