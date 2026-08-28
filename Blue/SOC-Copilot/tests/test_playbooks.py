from datetime import datetime, timezone

from soc_copilot.models import Alert, Incident, Priority, Severity, TriageResult, Verdict
from soc_copilot.recommend.playbooks import PLAYBOOKS, build_recommendation, classify_category

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _incident(title, description="", category=""):
    alert = Alert(alert_id="a1", client_id="c1", source="generic", timestamp=T0, host="H1", title=title, description=description, category=category)
    return Incident(incident_id="inc-1", client_id="c1", host="H1", user="", alerts=[alert])


def test_classify_ransomware():
    assert classify_category(_incident("Ransomware canary file triggered")) == "ransomware"


def test_classify_credential_access():
    assert classify_category(_incident("LSASS memory dump detected")) == "credential_access"


def test_classify_phishing():
    assert classify_category(_incident("Malicious macro executed")) == "phishing"


def test_classify_falls_back_to_generic():
    assert classify_category(_incident("Something unrelated happened")) == "generic"


def test_every_playbook_has_all_four_phases():
    for name, playbook in PLAYBOOKS.items():
        for phase in ("contain", "eradicate", "recover", "communicate"):
            assert phase in playbook, f"{name} missing {phase}"
            assert len(playbook[phase]) > 0


def test_build_recommendation_uses_llm_tailored_notes_when_available():
    incident = _incident("Ransomware canary file triggered")
    triage = TriageResult(
        incident_id="inc-1",
        verdict=Verdict.TRUE_POSITIVE,
        confidence=90,
        severity=Severity.CRITICAL,
        suggested_priority=Priority.P1,
        is_llm_generated=True,
        generation_notes="Isolate host X specifically before anything else.",
    )
    rec = build_recommendation(incident, triage)
    assert rec.matched_category == "ransomware"
    assert rec.tailored_notes == "Isolate host X specifically before anything else."


def test_build_recommendation_notes_heuristic_fallback():
    incident = _incident("Port scan detected")
    triage = TriageResult(
        incident_id="inc-1",
        verdict=Verdict.NEEDS_INVESTIGATION,
        confidence=35,
        severity=Severity.LOW,
        suggested_priority=Priority.P3,
        is_llm_generated=False,
    )
    rec = build_recommendation(incident, triage)
    assert rec.matched_category == "discovery_recon"
    assert "heuristic fallback" in rec.tailored_notes
