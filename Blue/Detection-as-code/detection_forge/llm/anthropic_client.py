"""Thin wrapper around the Anthropic Messages API, forcing structured tool output."""
from __future__ import annotations

from dataclasses import dataclass

from detection_forge.config import settings
from detection_forge.llm.prompts import EMIT_SIGMA_RULE_TOOL, SYSTEM_PROMPT


class LLMNotConfiguredError(RuntimeError):
    """Raised when no ANTHROPIC_API_KEY is available."""


@dataclass
class LLMDraft:
    rule_yaml: str
    generation_notes: str
    model_used: str
    raw_response: str


def draft_sigma_rule(prompt: str) -> LLMDraft:
    if not settings.has_llm_key:
        raise LLMNotConfiguredError(
            "ANTHROPIC_API_KEY is not set. Export it (or add it to a .env file in the "
            "project root) before running generation. See README.md."
        )

    import anthropic

    client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
    response = client.messages.create(
        model=settings.anthropic_model,
        max_tokens=4096,
        system=SYSTEM_PROMPT,
        tools=[EMIT_SIGMA_RULE_TOOL],
        tool_choice={"type": "tool", "name": "emit_sigma_rule"},
        messages=[{"role": "user", "content": prompt}],
    )

    tool_use_block = next(
        (block for block in response.content if block.type == "tool_use"), None
    )
    if tool_use_block is None:
        raise RuntimeError("Model did not return a tool_use block for emit_sigma_rule")

    tool_input = tool_use_block.input
    return LLMDraft(
        rule_yaml=tool_input["rule_yaml"],
        generation_notes=tool_input.get("generation_notes", ""),
        model_used=settings.anthropic_model,
        raw_response=str(response.model_dump() if hasattr(response, "model_dump") else response),
    )
