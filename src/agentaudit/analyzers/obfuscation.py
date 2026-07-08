"""Obfuscation analyzer: base64/hex blobs.

Blobs above a size threshold are decoded (safely, in memory) and the decoded
text is re-scanned with the rule engine — one level deep only. A blob whose
decoded content matches rules is reported at HIGH; an undecodable or opaque
blob is reported at LOW ("cannot verify contents").
"""

from __future__ import annotations

import base64
import binascii
import re
from pathlib import Path

from agentaudit.analyzers import AnalyzerRule, ScanContext
from agentaudit.models import FileKind, Finding, ParsedFile, Severity, escape_snippet
from agentaudit.parsers.markdown import parse_markdown

ANALYZER_RULES = [
    AnalyzerRule(
        "AA-OBF-001",
        "Opaque base64/hex block — cannot verify contents",
        "low",
        "obfuscation",
        "A large encoded blob whose decoded form is not human-readable. Encoded payloads have no place in instruction files.",
    ),
    AnalyzerRule(
        "AA-OBF-002",
        "Encoded block conceals suspicious content",
        "high",
        "obfuscation",
        "Decoding a base64/hex blob revealed text that itself triggers detection rules.",
    ),
]

_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_HEX_RE = re.compile(r"(?:(?:0x)?[0-9a-fA-F]{2}[ ,]?){30,}")
_MIN_PRINTABLE_RATIO = 0.85

#: Long runs that are usually legitimate (hashes, lock-file integrity, tokens in examples
#: are caught elsewhere). Pure-hex of common digest lengths is skipped.
_DIGEST_LENGTHS = {32, 40, 64, 128}


def analyze(parsed: ParsedFile, context: ScanContext) -> list[Finding]:
    if parsed.kind is not FileKind.MARKDOWN or context.depth >= 1:
        return []
    findings: list[Finding] = []
    seen_spans: set[tuple[int, str]] = set()
    for line_no, line in enumerate(parsed.lines, start=1):
        for match in _BASE64_RE.finditer(line):
            blob = match.group(0)
            if len(blob) in _DIGEST_LENGTHS and re.fullmatch(r"[0-9a-fA-F]+", blob):
                continue  # likely a hash digest, not a payload
            if (line_no, blob) in seen_spans:
                continue
            seen_spans.add((line_no, blob))
            findings.extend(_inspect_blob(parsed, context, line_no, blob, "base64"))
    return findings


def _decode(blob: str, encoding: str) -> str | None:
    try:
        if encoding == "base64":
            padded = blob + "=" * (-len(blob) % 4)
            raw = base64.b64decode(padded, validate=True)
        else:
            raw = binascii.unhexlify(re.sub(r"[^0-9a-fA-F]", "", blob))
    except (binascii.Error, ValueError):
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
    if not text or printable / len(text) < _MIN_PRINTABLE_RATIO:
        return None
    return text


def _inspect_blob(
    parsed: ParsedFile, context: ScanContext, line_no: int, blob: str, encoding: str
) -> list[Finding]:
    size_kb = len(blob) / 1024
    decoded = _decode(blob, encoding)
    if decoded is not None and context.rule_engine is not None:
        inner = parse_markdown(Path(parsed.path), decoded)
        inner_findings = context.rule_engine.analyze(inner)
        # One level deep only: also run the hidden-content checks on the payload.
        from agentaudit.analyzers import hidden_content

        inner_context = ScanContext(rule_engine=context.rule_engine, depth=context.depth + 1)
        inner_findings.extend(hidden_content.analyze(inner, inner_context))
        if inner_findings:
            worst = max(inner_findings, key=lambda f: f.severity.rank)
            return [
                Finding(
                    rule_id="AA-OBF-002",
                    severity=Severity.HIGH,
                    category="obfuscation",
                    file=parsed.path,
                    line=line_no,
                    message=f"Decoded {encoding} block triggers {worst.rule_id}: {worst.message}",
                    snippet=escape_snippet(decoded.strip()),
                    remediation="Remove the encoded payload; instructions must be plaintext.",
                )
            ]
        if _looks_like_prose(decoded):
            return []  # decodes to harmless readable text — not worth reporting
    return [
        Finding(
            rule_id="AA-OBF-001",
            severity=Severity.LOW,
            category="obfuscation",
            file=parsed.path,
            line=line_no,
            message=f"{encoding.capitalize()}-encoded block ({size_kb:.1f} KB) — cannot verify contents",
            snippet=escape_snippet(blob, 60),
            remediation="Replace encoded blobs with plaintext, or document exactly what they contain.",
        )
    ]


def _looks_like_prose(text: str) -> bool:
    words = re.findall(r"[A-Za-z]{2,}", text)
    return len(words) >= 3 and sum(len(w) for w in words) / max(len(text), 1) > 0.5
