from datetime import datetime, timezone

from soc_copilot.models import Alert, Incident, Priority, Severity
from soc_copilot.triage.heuristics import heuristic_triage, pre_score

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _incident(title, description="", severity=Severity.INFORMATIONAL, host="H1"):
    alert = Alert(alert_id="a1", client_id="c1", source="generic", timestamp=T0, host=host, title=title, description=description, severity=severity)
    return Incident(incident_id="i1", client_id="c1", host=host, user="", alerts=[alert])


def test_high_confidence_keyword_forces_a_severity_floor_even_at_low_vendor_severity():
    """A vendor-tagged INFORMATIONAL alert mentioning mimikatz/lsass must not
    stay at MEDIUM just because the base severity was low - the +15 additive
    bonus alone couldn't clear the HIGH/P1 threshold (5 base + 10 + 10 + 15 = 40)."""
    incident = _incident("LSASS memory access", "mimikatz-like behavior detected", severity=Severity.INFORMATIONAL)
    score = pre_score(incident)
    assert score >= 75.0
    triage = heuristic_triage(incident)
    assert triage.severity == Severity.HIGH
    assert triage.suggested_priority == Priority.P1


def test_routine_low_severity_incident_without_high_confidence_keywords_stays_low():
    incident = _incident("Antivirus definition update failed", severity=Severity.LOW)
    triage = heuristic_triage(incident)
    assert triage.severity == Severity.LOW


def test_heuristic_never_clears_an_alert():
    from soc_copilot.models import Verdict

    incident = _incident("Something routine", severity=Severity.INFORMATIONAL)
    triage = heuristic_triage(incident)
    assert triage.verdict == Verdict.NEEDS_INVESTIGATION
