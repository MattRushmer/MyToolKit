from pathlib import Path

from soc_copilot.economics.cost import cost_summary
from soc_copilot.models import Client
from soc_copilot.pipeline import ingest_files, run_pipeline
from soc_copilot.report.digest import render_client_digest

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def test_end_to_end_heuristic_pipeline_produces_ticket_ready_incidents():
    # No ANTHROPIC_API_KEY in the test environment/.env, so this exercises the
    # heuristic fallback path end to end - see soc_copilot/triage/heuristics.py.
    from soc_copilot.config import settings

    assert not settings.has_llm_key, "this test asserts heuristic-fallback behavior; unset ANTHROPIC_API_KEY to run it"

    specs = [
        (SAMPLES / "acme-dental_defender_alerts.csv", "defender"),
        (SAMPLES / "acme-dental_huntress_alerts.csv", "huntress"),
    ]
    alerts, warnings = ingest_files(specs, "acme-dental")
    assert warnings == []
    assert len(alerts) == 6

    client = Client(client_id="acme-dental", name="Acme Dental Group")
    result = run_pipeline(alerts, client)

    assert result.total_alerts_ingested == 6
    assert len(result.incidents) == 4  # ACME-WKS-07 (x3 merged), ACME-VPN, ACME-WKS-12, ACME-WKS-19

    ransomware_incident = next(r for r in result.incidents if r.incident.host == "ACME-WKS-07")
    assert len(ransomware_incident.incident.alerts) == 3
    assert ransomware_incident.triage.severity.value == "critical"
    assert ransomware_incident.recommendation.matched_category == "ransomware"
    assert "Isolate the affected host" in ransomware_incident.ticket_note_markdown

    # Queue must be sorted with the most urgent incident first.
    assert result.incidents[0].triage.suggested_priority.value == "P1"

    summary = cost_summary(result)
    assert summary["incidents_heuristic_only"] == 4
    assert summary["total_cost_usd"] == 0.0

    digest = render_client_digest(result)
    assert "Acme Dental Group" in digest
    assert "ACME-WKS-07" in digest


def test_multi_client_isolation_via_globex_sample():
    specs = [(SAMPLES / "globex-logistics_crowdstrike_detections.json", "crowdstrike")]
    alerts, warnings = ingest_files(specs, "globex-logistics")
    assert warnings == []
    client = Client(client_id="globex-logistics", name="Globex Logistics", criticality_tier="high")
    result = run_pipeline(alerts, client)
    assert len(result.incidents) == 3  # GLX-DC01 (x2 merged), GLX-WKS-04, GLX-WKS-11
    dc_incident = next(r for r in result.incidents if r.incident.host == "GLX-DC01")
    assert dc_incident.recommendation.matched_category == "credential_access"
