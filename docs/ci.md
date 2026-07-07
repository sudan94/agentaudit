# Running skillcheck in CI

skillcheck exits `1` when it finds an issue at or above the `--fail-on`
threshold (default `high`), `0` when clean, and `2` on a usage/internal error —
so it drops into any CI system as a gate.

## GitHub Actions

Using the bundled action:

```yaml
name: skillcheck
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: sudanupadhaya/skillcheck@v0.1.0
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
      - run: pip install skillcheck
      # continue-on-error so the SARIF still uploads even when findings exist
      - run: skillcheck scan . --format sarif -o skillcheck.sarif
        continue-on-error: true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: skillcheck.sarif
```

## GitLab CI

```yaml
skillcheck:
  image: python:3.12-slim
  script:
    - pip install skillcheck
    - skillcheck scan . --fail-on high
```

## pre-commit (manual hook)

Until a dedicated hook ships in v0.3, you can wire it as a local hook:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: skillcheck
        name: skillcheck
        entry: skillcheck scan
        language: python
        additional_dependencies: [skillcheck]
        pass_filenames: false
```

## Tuning

- `--fail-on medium` for a stricter gate.
- A `.skillcheck.yml` with `ignore_paths` / `allow` keeps intentional example
  content (like a security tutorial) from failing the build.
