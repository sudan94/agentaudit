## What this changes

<!-- One or two sentences. Link any related issue. -->

## Checklist

- [ ] `pytest` passes
- [ ] `ruff check src tests` passes
- [ ] If adding/changing a rule: it has `match` and `no_match` examples
- [ ] If adding a detection: a malicious fixture (`expected.json`) and/or a benign guard was added
- [ ] No new runtime dependencies beyond `typer`, `rich`, `pyyaml` (and `httpx` for `--ai`)
- [ ] Change is documented in `CHANGELOG.md` (Unreleased)
