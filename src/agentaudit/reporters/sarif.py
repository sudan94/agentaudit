"""Minimal SARIF 2.1.0 reporter — enough for GitHub Code Scanning upload."""

from __future__ import annotations

import json

from agentaudit import __version__
from agentaudit.models import ScanResult, Severity

_LEVEL = {
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def render(result: ScanResult) -> str:
    rules_seen: dict[str, dict] = {}
    results = []
    for finding in result.sorted_findings():
        rules_seen.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "name": finding.rule_id.replace("-", ""),
                "shortDescription": {"text": finding.message},
                "properties": {"category": finding.category},
            },
        )
        entry = {
            "ruleId": finding.rule_id,
            "level": _LEVEL[finding.severity],
            "message": {"text": finding.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file.as_posix()},
                        "region": {
                            "startLine": finding.line or 1,
                            "startColumn": finding.column or 1,
                        },
                    }
                }
            ],
        }
        if finding.snippet:
            entry["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                "text": finding.snippet
            }
        results.append(entry)
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agentaudit",
                        "version": __version__,
                        "informationUri": "https://github.com/sudan94/agentaudit",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
