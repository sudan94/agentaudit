# Running agentaudit in CI

agentaudit exits `1` when it finds an issue at or above the `--fail-on`
threshold (default `high`), `0` when clean, and `2` on a usage/internal error —
so it drops into any CI system as a gate.

## GitHub Actions

Using the bundled action:

```yaml
name: agentaudit
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: sudan94/agentaudit@v0.1.0
        with:
          path: .
          fail-on: high
```

### Upload to the Code Scanning tab (SARIF)

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install agentaudit-scanner
      # continue-on-error so the SARIF still uploads even when findings exist
      - run: agentaudit scan . --format sarif -o agentaudit.sarif
        continue-on-error: true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: agentaudit.sarif
```

## GitLab CI

```yaml
agentaudit:
  image: python:3.12-slim
  script:
    - pip install agentaudit-scanner
    - agentaudit scan . --fail-on high
```

## pre-commit (manual hook)

Until a dedicated hook ships in v0.3, you can wire it as a local hook:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: agentaudit
        name: agentaudit
        entry: agentaudit scan
        language: python
        additional_dependencies: [agentaudit]
        pass_filenames: false
```

## Tuning

- `--fail-on medium` for a stricter gate.
- A `.agentaudit.yml` with `ignore_paths` / `allow` keeps intentional example
  content (like a security tutorial) from failing the build.
