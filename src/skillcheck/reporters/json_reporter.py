"""Machine-readable JSON reporter."""

from __future__ import annotations

import json

from skillcheck import __version__
from skillcheck.models import ScanResult


def render(result: ScanResult) -> str:
    payload = {
        "tool": "skillcheck",
        "version": __version__,
        "root": result.root.as_posix(),
        "files_scanned": result.files_scanned,
        "duration_ms": result.duration_ms,
        "counts": {sev.value: count for sev, count in result.counts.items()},
        "findings": [f.to_dict() for f in result.sorted_findings()],
    }
    return json.dumps(payload, indent=2)
