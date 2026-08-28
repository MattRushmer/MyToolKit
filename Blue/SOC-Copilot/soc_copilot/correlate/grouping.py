"""Cluster normalized alerts into incidents.

This is the actual "correlate" in ingest -> correlate -> triage -> recommend:
an MSP tech looking at a dozen dashboards by hand mentally does exactly this -
"these three alerts on the same box ten minutes apart are probably one
story" - before ever deciding what the story means. We do the same thing
mechanically (same client + same host, within a rolling time window) so the
LLM triage step gets one incident with full context instead of three
disconnected alerts scored independently.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import timedelta

from soc_copilot.models import Alert, Incident

_NO_HOST = "(no host)"


def _dedupe(alerts: list[Alert]) -> list[Alert]:
    seen: set[str] = set()
    result = []
    for alert in alerts:
        key = f"{alert.client_id}:{alert.source}:{alert.alert_id}"
        if key in seen:
            continue
        seen.add(key)
        result.append(alert)
    return result


def _grouping_key(alert: Alert) -> tuple[str, str]:
    """Group by host when we have one; a host-less alert (e.g. a cloud sign-in
    event) falls back to grouping by user so it doesn't get isolated for no reason."""
    if alert.host:
        return (alert.client_id, f"host:{alert.host}")
    if alert.user:
        return (alert.client_id, f"user:{alert.user}")
    return (alert.client_id, _NO_HOST)


def _incident_id(client_id: str, group_key: str, opened_at) -> str:
    basis = f"{client_id}|{group_key}|{opened_at.isoformat()}"
    return f"inc-{hashlib.sha1(basis.encode('utf-8')).hexdigest()[:10]}"


def group_into_incidents(alerts: list[Alert], window_minutes: int) -> list[Incident]:
    """Sort each (client, host-or-user) bucket by time, then split into a new
    incident whenever the gap to the previous alert exceeds window_minutes."""
    alerts = _dedupe(alerts)
    buckets: dict[tuple[str, str], list[Alert]] = defaultdict(list)
    for alert in alerts:
        buckets[_grouping_key(alert)].append(alert)

    window = timedelta(minutes=window_minutes)
    incidents: list[Incident] = []
    for (client_id, group_key), bucket in buckets.items():
        bucket.sort(key=lambda a: a.timestamp)
        current: list[Alert] = []
        for alert in bucket:
            if current and alert.timestamp - current[-1].timestamp > window:
                incidents.append(_build_incident(client_id, group_key, current))
                current = []
            current.append(alert)
        if current:
            incidents.append(_build_incident(client_id, group_key, current))

    incidents.sort(key=lambda inc: inc.opened_at)
    return incidents


def _build_incident(client_id: str, group_key: str, members: list[Alert]) -> Incident:
    opened_at = min(a.timestamp for a in members)
    host = members[0].host
    user = next((a.user for a in members if a.user), "")
    return Incident(
        incident_id=_incident_id(client_id, group_key, opened_at),
        client_id=client_id,
        host=host,
        user=user,
        alerts=members,
    )
