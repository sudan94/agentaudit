"""Output reporters: console (Rich), JSON, SARIF 2.1.0, and markdown."""

from skillcheck.reporters import console, json_reporter, markdown_reporter, sarif

FORMATS = {
    "pretty": console,
    "json": json_reporter,
    "sarif": sarif,
    "md": markdown_reporter,
}

__all__ = ["FORMATS", "console", "json_reporter", "markdown_reporter", "sarif"]
