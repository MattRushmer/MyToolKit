"""Shared data contracts used across the soc_copilot pipeline.

Every module (ingest, correlate, triage, recommend, report, economics) reads/
writes these types so the CLI and web app can share one core pipeline.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verdict(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN_POSITIVE = "benign_positive"  # real activity, expected/authorized - still worth a note
    NEEDS_INVESTIGATION = "needs_investigation"


class Priority(str, Enum):
    """PSA-style ticket priority, independent of Severity (severity is technical, priority is queue order)."""

    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


@dataclass(frozen=True)
class Client:
    """One MSP-managed tenant. criticality_tier nudges triage/priority (e.g. a client
    running a regulated workload gets bumped relative to an identical alert elsewhere)."""

    client_id: str
    name: str
    criticality_tier: str = "standard"  # "standard" | "high" | "crown_jewel"


@dataclass
class Alert:
    """One normalized alert, regardless of which dashboard it came from."""

    alert_id: str
    client_id: str
    source: str  # "defender" | "crowdstrike" | "huntress" | "generic"
    timestamp: datetime
    host: str = ""
    user: str = ""
    category: str = ""  # coarse bucket: "malware", "login", "phishing", "lateral_movement", ...
    title: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM  # normalized during ingest, drives correlation/heuristics
    severity_raw: str = ""  # the source product's own severity label, kept for the analyst
    raw: dict[str, Any] = field(default_factory=dict)  # original row, for the ticket note / audit trail


@dataclass
class Incident:
    """A cluster of alerts on the same client+host (or client+user) within a time window."""

    incident_id: str
    client_id: str
    host: str
    user: str
    alerts: list[Alert] = field(default_factory=list)

    @property
    def opened_at(self) -> datetime:
        return min(a.timestamp for a in self.alerts)

    @property
    def closed_at(self) -> datetime:
        return max(a.timestamp for a in self.alerts)

    @property
    def sources(self) -> list[str]:
        return sorted({a.source for a in self.alerts})

    @property
    def categories(self) -> list[str]:
        return sorted({a.category for a in self.alerts if a.category})


@dataclass
class AttackTechniqueTag:
    technique_id: str  # e.g. "T1059.001"
    technique_name: str | None = None
    recognized: bool = False  # matched against the bundled common-technique reference list


@dataclass
class TriageResult:
    """The verdict on one incident - either LLM-drafted or heuristic fallback (no API key)."""

    incident_id: str
    verdict: Verdict
    confidence: int  # 0-100
    severity: Severity
    suggested_priority: Priority
    summary: str = ""  # one line, for the queue view
    analyst_notes: str = ""  # a paragraph explaining the verdict, for the ticket note
    attack_techniques: list[AttackTechniqueTag] = field(default_factory=list)
    is_llm_generated: bool = False
    model_used: str = ""
    generation_notes: str = ""
    raw_llm_response: str = ""


@dataclass
class Recommendation:
    playbook_name: str
    matched_category: str
    steps: dict[str, list[str]] = field(default_factory=dict)  # phase ("contain"/"eradicate"/...) -> steps
    tailored_notes: str = ""  # LLM's incident-specific addition on top of the static playbook


@dataclass
class UsageCost:
    input_tokens: int = 0
    output_tokens: int = 0

    def cost_usd(self, cost_per_1m_input: float, cost_per_1m_output: float) -> float:
        return (self.input_tokens / 1_000_000) * cost_per_1m_input + (
            self.output_tokens / 1_000_000
        ) * cost_per_1m_output


@dataclass
class IncidentResult:
    """Everything produced for one incident - what the queue and detail views render."""

    incident: Incident
    triage: TriageResult
    recommendation: Recommendation
    ticket_note_markdown: str = ""
    usage: UsageCost = field(default_factory=UsageCost)


@dataclass
class PipelineResult:
    client: Client
    incidents: list[IncidentResult] = field(default_factory=list)
    total_alerts_ingested: int = 0
    created_at: datetime = field(default_factory=datetime.utcnow)

    @property
    def total_cost_usd(self) -> float:
        from soc_copilot.config import settings

        return sum(
            r.usage.cost_usd(settings.cost_per_1m_input, settings.cost_per_1m_output)
            for r in self.incidents
        )

    @property
    def needs_review_count(self) -> int:
        return sum(
            1
            for r in self.incidents
            if r.triage.verdict in (Verdict.TRUE_POSITIVE, Verdict.NEEDS_INVESTIGATION)
        )
