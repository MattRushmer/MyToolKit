"""Field-mapping presets for the alert export formats an MSP actually deals with.

None of these vendors agree on column names, so each adapter is just an ordered
list of candidate source-column names per canonical field (first match wins,
case-insensitive) plus a severity vocabulary. "generic" is deliberately broad -
it's the fallback for "yet another dashboard's CSV export" that isn't one of
the named vendors below, and the named adapters exist to save an analyst from
having to rename columns by hand for the common cases.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class AdapterSpec:
    name: str
    field_map: dict[str, list[str]]
    severity_map: dict[str, str] = field(default_factory=dict)
    default_category: str = ""  # set when a source only ever reports one kind of alert


CANONICAL_FIELDS = ("alert_id", "timestamp", "host", "user", "category", "title", "description", "severity_raw")

_SEVERITY_WORDS = {
    "informational": "informational",
    "info": "informational",
    "low": "low",
    "medium": "medium",
    "moderate": "medium",
    "high": "high",
    "critical": "critical",
    "severe": "critical",
}

GENERIC = AdapterSpec(
    name="generic",
    field_map={
        "alert_id": ["alert_id", "alertid", "id", "alert id", "report id"],
        "timestamp": ["timestamp", "time", "created", "created_at", "created at", "date", "detected_at"],
        "host": ["host", "hostname", "device", "devicename", "device name", "computer", "asset"],
        "user": ["user", "username", "user_name", "account", "accountname", "account name"],
        "category": ["category", "type", "alert_type", "tactic", "classification"],
        "title": ["title", "name", "alert_title", "alert name", "summary_title"],
        "description": ["description", "summary", "details", "message"],
        "severity_raw": ["severity", "severity_name", "priority", "risk"],
    },
    severity_map=_SEVERITY_WORDS,
)

DEFENDER = AdapterSpec(
    name="defender",
    field_map={
        "alert_id": ["alertid", "alert id", "id"],
        "timestamp": ["timestamp", "createdtime", "alert creation time", "firstactivity"],
        "host": ["devicename", "device name", "computerdnsname"],
        "user": ["accountname", "initiatingprocessaccountname", "account name"],
        "category": ["category", "detectionsource"],
        "title": ["title", "alerttitle"],
        "description": ["description"],
        "severity_raw": ["severity"],
    },
    severity_map=_SEVERITY_WORDS,
)

CROWDSTRIKE = AdapterSpec(
    name="crowdstrike",
    field_map={
        "alert_id": ["detection_id", "composite_id", "id"],
        "timestamp": ["timestamp", "created_timestamp", "first_behavior"],
        "host": ["hostname", "device.hostname", "computer_name"],
        "user": ["user_name", "username"],
        "category": ["tactic", "technique"],
        "title": ["display_name", "title"],
        "description": ["description"],
        "severity_raw": ["severity_name", "severity"],
    },
    # CrowdStrike often reports severity as a 1-100 int, not just a name;
    # numeric handling is applied separately in normalize.map_severity().
    severity_map=_SEVERITY_WORDS,
)

HUNTRESS = AdapterSpec(
    name="huntress",
    field_map={
        "alert_id": ["report id", "incident report id", "id"],
        "timestamp": ["created at", "detected at", "timestamp"],
        "host": ["hostname", "host"],
        "user": ["username", "user"],
        "category": ["status", "type"],
        "title": ["title"],
        "description": ["summary", "description"],
        "severity_raw": ["severity"],
    },
    severity_map=_SEVERITY_WORDS,
)

ADAPTERS: dict[str, AdapterSpec] = {
    a.name: a for a in (GENERIC, DEFENDER, CROWDSTRIKE, HUNTRESS)
}


def get_adapter(name: str) -> AdapterSpec:
    try:
        return ADAPTERS[name.lower()]
    except KeyError as exc:
        raise ValueError(
            f"Unknown source adapter '{name}'. Available: {', '.join(sorted(ADAPTERS))}"
        ) from exc
