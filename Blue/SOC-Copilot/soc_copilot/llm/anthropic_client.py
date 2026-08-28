"""Thin wrapper around the Anthropic Messages API, forcing structured tool output."""
from __future__ import annotations

from dataclasses import dataclass

from soc_copilot.config import settings
from soc_copilot.llm.prompts import EMIT_TRIAGE_TOOL, SYSTEM_PROMPT


class LLMNotConfiguredError(RuntimeError):
    """Raised when no ANTHROPIC_API_KEY is available."""


@dataclass
class LLMTriageDraft:
    verdict: str
    confidence: int
    severity: str
    suggested_priority: str
    summary: str
    analyst_notes: str
    attack_techniques: list[str]
    tailored_recommendation: str
    model_used: str
    input_tokens: int
    output_tokens: int
    raw_response: str


def draft_triage(prompt: str) -> LLMTriageDraft:
    if not settings.has_llm_key:
        raise LLMNotConfiguredError(
            "ANTHROPIC_API_KEY is not set. Export it (or add it to a .env file in the "
            "project root) before running triage. See README.md."
        )

    import anthropic

    client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
    response = client.messages.create(
        model=settings.anthropic_model,
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        tools=[EMIT_TRIAGE_TOOL],
        tool_choice={"type": "tool", "name": "emit_triage"},
        messages=[{"role": "user", "content": prompt}],
    )

    tool_use_block = next((block for block in response.content if block.type == "tool_use"), None)
    if tool_use_block is None:
        raise RuntimeError("Model did not return a tool_use block for emit_triage")

    tool_input = tool_use_block.input
    usage = getattr(response, "usage", None)
    return LLMTriageDraft(
        verdict=tool_input["verdict"],
        confidence=int(tool_input["confidence"]),
        severity=tool_input["severity"],
        suggested_priority=tool_input["suggested_priority"],
        summary=tool_input["summary"],
        analyst_notes=tool_input["analyst_notes"],
        attack_techniques=list(tool_input.get("attack_techniques", [])),
        tailored_recommendation=tool_input.get("tailored_recommendation", ""),
        model_used=settings.anthropic_model,
        input_tokens=getattr(usage, "input_tokens", 0) or 0,
        output_tokens=getattr(usage, "output_tokens", 0) or 0,
        raw_response=str(response.model_dump() if hasattr(response, "model_dump") else response),
    )
