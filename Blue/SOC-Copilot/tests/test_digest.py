from datetime import datetime, timezone

from soc_copilot.models import (
    Alert,
    Client,
    Incident,
    IncidentResult,
    PipelineResult,
    Priority,
    Recommendation,
    Severity,
    TriageResult,
    UsageCost,
    Verdict,
)
from soc_copilot.report.digest import render_client_digest

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _result_with_summary(summary: str) -> PipelineResult:
    alert = Alert(alert_id="a1", client_id="c1", source="generic", timestamp=T0, host="H1", title=summary)
    incident = Incident(incident_id="i1", client_id="c1", host="H1", user="", alerts=[alert])
    triage = TriageResult(
        incident_id="i1",
        verdict=Verdict.NEEDS_INVESTIGATION,
        confidence=50,
        severity=Severity.MEDIUM,
        suggested_priority=Priority.P2,
        summary=summary,
    )
    recommendation = Recommendation(playbook_name="Generic", matched_category="generic")
    return PipelineResult(
        client=Client(client_id="c1", name="Client One"),
        incidents=[IncidentResult(incident=incident, triage=triage, recommendation=recommendation, usage=UsageCost())],
        total_alerts_ingested=1,
    )


def test_literal_pipe_in_summary_does_not_break_the_markdown_table():
    result = _result_with_summary("explorer.exe | powershell.exe spawned a child process")
    digest = render_client_digest(result)
    table_row = next(line for line in digest.splitlines() if "explorer.exe" in line)
    # Escaped pipes plus the 5 real column separators = 7 total "|" on the row.
    assert table_row.count("|") == 7
    assert "\\|" in table_row


def test_digest_without_special_characters_renders_normally():
    result = _result_with_summary("Suspicious PowerShell execution")
    digest = render_client_digest(result)
    assert "Client One" in digest
    assert "Suspicious PowerShell execution" in digest
