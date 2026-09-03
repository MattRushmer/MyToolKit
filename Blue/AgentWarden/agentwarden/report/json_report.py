"""Render AuditEvent lists and BlastRadiusReports as JSON."""
from __future__ import annotations

import json
from datetime import datetime
from enum import Enum
from typing import Any

from agentwarden.models import AuditEvent, BlastRadiusReport


def _default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def render_audit_events_json(events: list[AuditEvent]) -> str:
    import dataclasses

    payload = {
        "event_count": len(events),
        "events": [dataclasses.asdict(e) for e in events],
    }
    return json.dumps(payload, indent=2, default=_default)


def render_blast_radius_json(report: BlastRadiusReport) -> str:
    payload = {
        "root_session_id": report.root_session_id,
        "task_id": report.task_id,
        "computed_at": report.computed_at.isoformat(),
        "ceiling": report.ceiling,
        "distinct_upstreams": sorted(report.distinct_upstreams),
        "exceeded": report.exceeded,
        "sessions_visited": report.sessions_visited,
        "reachable": [
            {"upstream_server_id": upstream, "tool_name": tool, "path": report.path_by_pair.get((upstream, tool), [])}
            for upstream, tool in sorted(report.reachable)
        ],
    }
    return json.dumps(payload, indent=2, default=_default)
