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
    assert "LLM triage failed" in result.analyst_notes
    assert usage.input_tokens == 0
