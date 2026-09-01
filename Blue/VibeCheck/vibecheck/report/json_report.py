"""Render a ScanReport as JSON."""
from __future__ import annotations

import dataclasses
import json
from datetime import datetime
from enum import Enum
from typing import Any

from vibecheck.models import ScanReport


def _default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def report_to_json(report: ScanReport) -> str:
    payload = dataclasses.asdict(report)
    payload["findings"] = [dataclasses.asdict(f) for f in report.findings_sorted()]
    payload["counts_by_severity"] = {s.value: n for s, n in report.counts_by_severity.items()}
    payload["counts_by_category"] = {c.value: n for c, n in report.counts_by_category.items()}
    return json.dumps(payload, indent=2, default=_default)
