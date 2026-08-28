from datetime import datetime, timezone

from soc_copilot.models import (
    Alert,
    AttackTechniqueTag,
    Client,
    Incident,
    Priority,
    Recommendation,
    Severity,
    TriageResult,
    UsageCost,
    Verdict,
)
from soc_copilot.report.ticket import render_ticket_note

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _incident():
    alert = Alert(
        alert_id="a1",
        client_id="acme-dental",
        source="defender",
        timestamp=T0,
        host="ACME-WKS-07",
        user="jsmith",
        title="Suspicious PowerShell",
        description="powershell -enc ...",
        severity=Severity.HIGH,
        severity_raw="High",
    )
    return Incident(incident_id="inc-1", client_id="acme-dental", host="ACME-WKS-07", user="jsmith", alerts=[alert])


def test_ticket_note_includes_core_fields():
    incident = _incident()
    client = Client(client_id="acme-dental", name="Acme Dental Group")
    triage = TriageResult(
        incident_id="inc-1",
        verdict=Verdict.TRUE_POSITIVE,
        confidence=88,
        severity=Severity.HIGH,
        suggested_priority=Priority.P1,
        summary="Encoded PowerShell command",
        analyst_notes="Looks like a real compromise attempt.",
        attack_techniques=[AttackTechniqueTag(technique_id="T1059.001", technique_name="PowerShell", recognized=True)],
        is_llm_generated=True,
        model_used="claude-sonnet-4-5",
    )
    recommendation = Recommendation(playbook_name="Malware Execution", matched_category="malware_execution", steps={"contain": ["Isolate the host."]})
    note = render_ticket_note(incident, triage, recommendation, client, UsageCost(input_tokens=500, output_tokens=200))

    assert "[P1]" in note
    assert "Acme Dental Group" in note
    assert "ACME-WKS-07" in note
    assert "true_positive" in note
    assert "T1059.001" in note
    assert "Isolate the host." in note
    assert "Triage cost" in note


def test_ticket_note_flags_heuristic_origin():
    incident = _incident()
    client = Client(client_id="acme-dental", name="Acme Dental Group")
    triage = TriageResult(
        incident_id="inc-1",
        verdict=Verdict.NEEDS_INVESTIGATION,
        confidence=35,
        severity=Severity.MEDIUM,
        suggested_priority=Priority.P2,
        is_llm_generated=False,
        model_used="heuristic-v1",
    )
    recommendation = Recommendation(playbook_name="Generic", matched_category="generic", steps={"contain": ["Review manually."]})
    note = render_ticket_note(incident, triage, recommendation, client, UsageCost())
    assert "heuristic fallback" in note
    assert "no ANTHROPIC_API_KEY" in note
