"""Render a ScanReport to a JSON-serializable dict / string."""
from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from enum import Enum
from typing import Any

from mcp_sentinel.models import ScanReport


def _default(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def report_to_dict(report: ScanReport) -> dict[str, Any]:
    payload = asdict(report)
    payload["findings"] = [asdict(f) for f in report.findings_sorted()]
    payload["summary"] = {
        "total_servers": report.total_servers,
        "total_tools": report.total_tools,
        "counts_by_severity": {sev.value: count for sev, count in report.counts_by_severity.items()},
        "active_probes_run": report.active_probes_run,
    }
    return payload


def report_to_json(report: ScanReport, *, indent: int = 2) -> str:
    return json.dumps(report_to_dict(report), indent=indent, default=_default)
