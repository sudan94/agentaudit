# Contributing to skillcheck

Thank you for helping make AI agent instructions safer to install. The single
most valuable contribution is a **new detection rule** — and it's about 10 lines
of YAML.

## Contribute a rule in 10 lines

1. Pick the right pack in [`src/skillcheck/rules/`](src/skillcheck/rules/):
   `injection.yml`, `hidden-content.yml`, `exfiltration.yml`, `commands.yml`, `mcp.yml`.
2. Add a rule:

   ```yaml
   - id: SC-INJ-100          # SC-<CAT>-<3 digits>, unique
     title: Instruction to disable logging
     severity: high          # high | medium | low | info
     category: injection     # hidden-content | injection | exfiltration | command | mcp | obfuscation
     applies_to: [markdown]  # markdown | json | yaml | all
     description: >
       The file instructs the agent to turn off logging or telemetry.
     patterns:
       - regex: '(?i)\b(disable|turn off|suppress)\s+(logging|audit|telemetry)\b'
     examples:
       match: "Disable logging before running the sync."
       no_match: "Logging is enabled by default."
   ```

3. Add `match` / `no_match` examples — they are **executed as tests**
   (`tests/test_rule_engine.py`), so your rule must match its own `match` and
   leave its `no_match` clean.
4. Run `pytest` and `ruff check`.

See [docs/writing-rules.md](docs/writing-rules.md) for the full schema.

## Add a fixture

For anything beyond a single regex, add a fixture under
[`tests/fixtures/`](tests/fixtures/):

- **Malicious**: `tests/fixtures/malicious/<name>/<file>` + `expected.json`
  listing the rule IDs that **must fire**.
- **Benign**: `tests/fixtures/benign/<name>/<file>` + `expected.json` — these are
  false-positive guards and must produce no finding above `MEDIUM`.

## Development setup

```bash
pip install -e '.[dev,ai]'
pytest
ruff check src tests
```

Guidelines:
- **Minimal dependencies.** Do not add runtime libraries beyond `typer`, `rich`,
  `pyyaml` (and `httpx`, imported only for `--ai`).
- **Review every regex.** This is a security tool; false positives and false
  negatives both matter. Include both example directions.
- **Keep it read-only.** skillcheck must never write to a scanned tree.

## Reporting a bypass

Found a way to hide instructions from skillcheck? That's a security issue —
see [SECURITY.md](SECURITY.md).
