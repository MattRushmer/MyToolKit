from datetime import datetime, timezone

from soc_copilot import config
from soc_copilot.config import Settings
from soc_copilot.llm.anthropic_client import LLMTriageDraft
from soc_copilot.models import Alert, Client, Incident, Verdict
from soc_copilot.triage import engine


def test_malformed_llm_draft_falls_back_to_heuristics(monkeypatch):
    incident = Incident(
        incident_id="inc-1",
        client_id="client-a",
        host="HOST-A",
        user="",
        alerts=[Alert("alert-1", "client-a", "generic", datetime(2026, 1, 1, tzinfo=timezone.utc), host="HOST-A")],
    )
    malformed_draft = LLMTriageDraft(
        verdict="not-a-verdict",
        confidence=50,
        severity="medium",
        suggested_priority="P2",
        summary="bad draft",
        analyst_notes="bad draft",
        attack_techniques=[],
        tailored_recommendation="",
        model_used="test",
        input_tokens=1,
        output_tokens=1,
        raw_response="{}",
    )
    monkeypatch.setattr(config, "settings", Settings(anthropic_api_key="test-key"))
    monkeypatch.setattr(engine, "draft_triage", lambda prompt: malformed_draft)

    result, usage = engine.triage_incident(incident, Client("client-a", "Client A"))

    assert result.verdict == Verdict.NEEDS_INVESTIGATION
    assert "malformed triage draft" in result.analyst_notes
    # The API call still completed and was billed even though the response
    # violated the tool schema post-hoc - that real usage must not be
    # discarded, or cost tracking silently undercounts actual spend.
    assert usage.input_tokens == 1
    assert usage.output_tokens == 1


def test_llm_call_failure_before_any_response_bills_nothing(monkeypatch):
    incident = Incident(
        incident_id="inc-2",
        client_id="client-a",
        host="HOST-A",
        user="",
        alerts=[Alert("alert-1", "client-a", "generic", datetime(2026, 1, 1, tzinfo=timezone.utc), host="HOST-A")],
    )

    def _boom(prompt):
        raise RuntimeError("network blip")

    monkeypatch.setattr(config, "settings", Settings(anthropic_api_key="test-key"))
    monkeypatch.setattr(engine, "draft_triage", _boom)

    result, usage = engine.triage_incident(incident, Client("client-a", "Client A"))

    assert result.verdict == Verdict.NEEDS_INVESTIGATION
    assert "LLM triage failed" in result.analyst_notes
    assert usage.input_tokens == 0
    assert usage.output_tokens == 0


def test_non_enum_draft_field_falls_back_without_crashing(monkeypatch):
    """A draft with a non-string/non-numeric field (e.g. confidence=None) used
    to raise TypeError, which the old (ValueError, KeyError) catch missed
    entirely - it would propagate up to pipeline.py's generic crash handler
    instead of the more specific, usage-preserving malformed-draft fallback."""
    incident = Incident(
        incident_id="inc-3",
        client_id="client-a",
        host="HOST-A",
        user="",
        alerts=[Alert("alert-1", "client-a", "generic", datetime(2026, 1, 1, tzinfo=timezone.utc), host="HOST-A")],
    )
    bad_draft = LLMTriageDraft(
        verdict="true_positive",
        confidence=None,  # type: ignore[arg-type]
        severity="medium",
        suggested_priority="P2",
        summary="x",
        analyst_notes="x",
        attack_techniques=[],
        tailored_recommendation="",
        model_used="test",
        input_tokens=7,
        output_tokens=3,
        raw_response="{}",
    )
    monkeypatch.setattr(config, "settings", Settings(anthropic_api_key="test-key"))
    monkeypatch.setattr(engine, "draft_triage", lambda prompt: bad_draft)

    result, usage = engine.triage_incident(incident, Client("client-a", "Client A"))

    assert result.verdict == Verdict.NEEDS_INVESTIGATION
    assert "malformed triage draft" in result.analyst_notes
    assert usage.input_tokens == 7
    assert usage.output_tokens == 3
