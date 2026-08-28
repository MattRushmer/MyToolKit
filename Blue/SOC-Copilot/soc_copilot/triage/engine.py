"""Per-incident triage: LLM verdict when configured, heuristic fallback otherwise.

Mirrors Detection Forge's fail-visible philosophy: an LLM call that raises
(rate limit, network blip, malformed tool response) does not crash the whole
batch and lose every other incident's results - it degrades that one incident
to the heuristic verdict with the failure reason attached, so the analyst
still gets a queue instead of a stack trace.
"""
from __future__ import annotations

from soc_copilot.llm.anthropic_client import LLMNotConfiguredError, draft_triage
from soc_copilot.llm.prompts import build_triage_prompt
from soc_copilot.models import (
    AttackTechniqueTag,
    Client,
    Incident,
    Priority,
    Severity,
    TriageResult,
    UsageCost,
    Verdict,
)
from soc_copilot.triage.attack_reference import lookup
from soc_copilot.triage.heuristics import heuristic_triage


def triage_incident(incident: Incident, client: Client) -> tuple[TriageResult, UsageCost]:
    from soc_copilot.config import settings

    if not settings.has_llm_key:
        return heuristic_triage(incident), UsageCost()

    try:
        prompt = build_triage_prompt(incident, client)
        draft = draft_triage(prompt)
    except LLMNotConfiguredError:
        return heuristic_triage(incident), UsageCost()
    except Exception as exc:
        # The API call itself never completed, so nothing was billed - usage
        # stays at zero.
        fallback = heuristic_triage(incident)
        fallback.analyst_notes = (
            f"LLM triage failed ({exc}); falling back to heuristic scoring below. "
            "Treat this incident as needing manual review regardless of the heuristic verdict.\n\n"
            + fallback.analyst_notes
        )
        return fallback, UsageCost()

    # The API call succeeded and was billed - capture that usage now, before
    # any post-hoc validation, so a malformed-but-billed response still gets
    # counted in cost tracking even if we fall back below.
    usage = UsageCost(input_tokens=draft.input_tokens, output_tokens=draft.output_tokens)
    try:
        techniques = []
        for tid in draft.attack_techniques:
            recognized, name = lookup(tid)
            techniques.append(AttackTechniqueTag(technique_id=tid, technique_name=name, recognized=recognized))

        result = TriageResult(
            incident_id=incident.incident_id,
            verdict=Verdict(draft.verdict),
            confidence=max(0, min(100, draft.confidence)),
            severity=Severity(draft.severity),
            suggested_priority=Priority(draft.suggested_priority),
            summary=draft.summary,
            analyst_notes=draft.analyst_notes,
            attack_techniques=techniques,
            is_llm_generated=True,
            model_used=draft.model_used,
            generation_notes=draft.tailored_recommendation,
            raw_llm_response=draft.raw_response,
        )
        return result, usage
    except Exception as exc:
        # The model returned a malformed draft field (for example an invalid
        # enum, a missing attribute, or a non-numeric confidence). Degrade to
        # heuristic, but keep the real usage since the call was still billed.
        fallback = heuristic_triage(incident)
        fallback.analyst_notes = (
            f"LLM returned a malformed triage draft ({exc}); falling back to heuristic scoring "
            "below. The API call still counted against usage/cost tracking. Treat this incident "
            "as needing manual review regardless of the heuristic verdict.\n\n" + fallback.analyst_notes
        )
        return fallback, usage
