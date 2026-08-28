"""Actual LLM spend tracking - what running triage really costs, per incident and per run.

This is the other half of the "priced for a shoestring budget" pitch: an MSP
owner can't manage a per-alert AI cost they can't see. Every triage call
returns real token counts from the Anthropic API response (soc_copilot/llm/
anthropic_client.py), so this is measured spend, not a guess.
"""
from __future__ import annotations

from soc_copilot.config import settings
from soc_copilot.models import PipelineResult


def cost_summary(result: PipelineResult) -> dict[str, float | int]:
    total_input = sum(r.usage.input_tokens for r in result.incidents)
    total_output = sum(r.usage.output_tokens for r in result.incidents)
    total_cost = result.total_cost_usd
    llm_incidents = sum(1 for r in result.incidents if r.triage.is_llm_generated)
    return {
        "incidents_triaged": len(result.incidents),
        "incidents_llm_triaged": llm_incidents,
        "incidents_heuristic_only": len(result.incidents) - llm_incidents,
        "total_input_tokens": total_input,
        "total_output_tokens": total_output,
        "total_cost_usd": round(total_cost, 4),
        "avg_cost_per_incident_usd": round(total_cost / len(result.incidents), 4) if result.incidents else 0.0,
        "cost_per_1m_input": settings.cost_per_1m_input,
        "cost_per_1m_output": settings.cost_per_1m_output,
    }
