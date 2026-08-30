"""Thin wrapper around the Anthropic Messages API, forcing structured tool output."""
from __future__ import annotations

from dataclasses import dataclass

from mcp_sentinel.config import settings
from mcp_sentinel.llm.prompts import EMIT_VERDICT_TOOL, SYSTEM_PROMPT, build_judge_prompt


class LLMNotConfiguredError(RuntimeError):
    """Raised when no ANTHROPIC_API_KEY is available."""


@dataclass(frozen=True)
class InjectionVerdict:
    is_suspicious: bool
    confidence: int
    reasoning: str


def judge_response(tool_name: str, response_text: str) -> InjectionVerdict:
    if not settings.has_llm_key:
        raise LLMNotConfiguredError(
            "ANTHROPIC_API_KEY is not set. Export it (or add it to a .env file in the "
            "project root) to enable LLM-assisted probe analysis. See README.md."
        )

    import anthropic

    client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
    response = client.messages.create(
        model=settings.anthropic_model,
        max_tokens=512,
        system=SYSTEM_PROMPT,
        tools=[EMIT_VERDICT_TOOL],
        tool_choice={"type": "tool", "name": "emit_verdict"},
        messages=[{"role": "user", "content": build_judge_prompt(tool_name, response_text)}],
    )

    tool_use_block = next((block for block in response.content if block.type == "tool_use"), None)
    if tool_use_block is None:
        raise RuntimeError("Model did not return a tool_use block for emit_verdict")

    tool_input = tool_use_block.input
    return InjectionVerdict(
        is_suspicious=bool(tool_input["is_suspicious"]),
        confidence=int(tool_input["confidence"]),
        reasoning=str(tool_input["reasoning"]),
    )
