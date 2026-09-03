"""Thin wrapper around the Anthropic Messages API, forcing structured tool output."""
from __future__ import annotations

from dataclasses import dataclass

from agentwarden.config import settings
from agentwarden.llm.prompts import EMIT_VERDICT_TOOL, SYSTEM_PROMPT, build_task_review_prompt


class LLMNotConfiguredError(RuntimeError):
    """Raised when no ANTHROPIC_API_KEY is available."""


@dataclass(frozen=True)
class TaskReviewVerdict:
    looks_malicious: bool
    confidence: int
    reasoning: str


def review_task(blast_radius_summary: str, events_summary: str) -> TaskReviewVerdict:
    if not settings.has_llm_key:
        raise LLMNotConfiguredError(
            "ANTHROPIC_API_KEY is not set. Export it (or add it to a .env file in the "
            "project root) to enable the LLM second-opinion review. See README.md."
        )

    import anthropic

    client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
    response = client.messages.create(
        model=settings.anthropic_model,
        max_tokens=512,
        system=SYSTEM_PROMPT,
        tools=[EMIT_VERDICT_TOOL],
        tool_choice={"type": "tool", "name": "emit_verdict"},
        messages=[{"role": "user", "content": build_task_review_prompt(blast_radius_summary, events_summary)}],
    )

    tool_use_block = next((block for block in response.content if block.type == "tool_use"), None)
    if tool_use_block is None:
        raise RuntimeError("Model did not return a tool_use block for emit_verdict")

    tool_input = tool_use_block.input
    return TaskReviewVerdict(
        looks_malicious=bool(tool_input["looks_malicious"]),
        confidence=int(tool_input["confidence"]),
        reasoning=str(tool_input["reasoning"]),
    )
