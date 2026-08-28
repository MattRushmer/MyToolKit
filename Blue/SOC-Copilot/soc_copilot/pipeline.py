"""Top-level orchestration: the one function both the CLI and the web app call.

ingest (per file) -> correlate into incidents -> triage each incident ->
recommend a playbook -> render a PSA-ready ticket note.

Each incident is triaged independently and a failure on one (triage.engine
already catches its own LLM-call failures, but this is a second layer) does
not lose every other incident in the batch - consistent with Detection
Forge's pipeline.py, which takes the same "an already-expensive partial
result beats a crashed batch" position.
"""
from __future__ import annotations

from pathlib import Path

from soc_copilot.config import settings
from soc_copilot.correlate.grouping import group_into_incidents
from soc_copilot.ingest.normalize import load_alerts
from soc_copilot.models import (
    Alert,
    Client,
    IncidentResult,
    PipelineResult,
    Priority,
    Recommendation,
    Severity,
    TriageResult,
    UsageCost,
    Verdict,
)
from soc_copilot.recommend.playbooks import build_recommendation
from soc_copilot.report.ticket import render_ticket_note
from soc_copilot.triage.engine import triage_incident

_PRIORITY_ORDER = [p.value for p in Priority]


def ingest_files(specs: list[tuple[Path, str]], client_id: str) -> tuple[list[Alert], list[str]]:
    """specs: list of (file_path, source_adapter_name), e.g. [(Path("a.csv"), "defender")]."""
    all_alerts: list[Alert] = []
    all_warnings: list[str] = []
    for path, source in specs:
        alerts, warnings = load_alerts(path, client_id, source)
        all_alerts.extend(alerts)
        all_warnings.extend(warnings)
    return all_alerts, all_warnings


def run_pipeline(
    alerts: list[Alert],
    client: Client,
    correlation_window_minutes: int | None = None,
) -> PipelineResult:
    window = correlation_window_minutes if correlation_window_minutes is not None else settings.correlation_window_minutes
    incidents = group_into_incidents(alerts, window)

    incident_results: list[IncidentResult] = []
    for incident in incidents:
        try:
            triage, usage = triage_incident(incident, client)
            recommendation = build_recommendation(incident, triage)
            ticket = render_ticket_note(incident, triage, recommendation, client, usage)
        except Exception as exc:
            # Fail closed: an incident we couldn't fully process is surfaced as
            # needing manual review, not silently dropped from the queue.
            triage = TriageResult(
                incident_id=incident.incident_id,
                verdict=Verdict.NEEDS_INVESTIGATION,
                confidence=0,
                severity=Severity.HIGH,
                suggested_priority=Priority.P2,
                summary=f"Pipeline stage crashed while processing this incident: {exc}",
                analyst_notes=f"Automated processing failed unexpectedly ({exc}). Review the raw alerts below manually.",
            )
            recommendation = Recommendation(playbook_name="Manual Review Required", matched_category="error")
            usage = UsageCost()
            try:
                ticket = render_ticket_note(incident, triage, recommendation, client, usage)
            except Exception as render_exc:
                # This fallback path must not itself be able to raise - if it
                # did, the exception would propagate out of the loop and take
                # every remaining incident in the batch down with it, which is
                # exactly what this try/except exists to prevent.
                ticket = (
                    f"# Manual review required - {incident.incident_id}\n\n"
                    f"Automated ticket rendering also failed ({render_exc}) after the original "
                    f"processing failure ({exc}). Alerts in this incident: "
                    + ", ".join(f"{a.source}:{a.alert_id}" for a in incident.alerts)
                )
        incident_results.append(
            IncidentResult(incident=incident, triage=triage, recommendation=recommendation, ticket_note_markdown=ticket, usage=usage)
        )

    incident_results.sort(
        key=lambda r: (_PRIORITY_ORDER.index(r.triage.suggested_priority.value), -r.triage.confidence, r.incident.opened_at)
    )
    return PipelineResult(client=client, incidents=incident_results, total_alerts_ingested=len(alerts))
