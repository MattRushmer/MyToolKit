"""Thin wrapper around the Anthropic Messages API, forcing structured tool output."""
from __future__ import annotations

from dataclasses import dataclass

from vibecheck.config import settings
from vibecheck.llm.prompts import EMIT_VERDICT_TOOL, SYSTEM_PROMPT, build_judge_prompt


class LLMNotConfiguredError(RuntimeError):
    """Raised when no ANTHROPIC_API_KEY is available."""


@dataclass(frozen=True)
class AuthJudgeVerdict:
    is_real_vulnerability: bool
    confidence: int
    reasoning: str


def judge_auth_finding(finding_title: str, finding_description: str, code_context: str) -> AuthJudgeVerdict:
    if not settings.has_llm_key:
        raise LLMNotConfiguredError(
            "ANTHROPIC_API_KEY is not set. Export it (or add it to a .env file in the "
            "project root) to enable the LLM second-opinion pass on auth findings. See README.md."
        )

    import anthropic

    client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
    response = client.messages.create(
        model=settings.anthropic_model,
        max_tokens=512,
        system=SYSTEM_PROMPT,
        tools=[EMIT_VERDICT_TOOL],
        tool_choice={"type": "tool", "name": "emit_verdict"},
        messages=[{"role": "user", "content": build_judge_prompt(finding_title, finding_description, code_context)}],
    )

    tool_use_block = next((block for block in response.content if block.type == "tool_use"), None)
    if tool_use_block is None:
        raise RuntimeError("Model did not return a tool_use block for emit_verdict")

    tool_input = tool_use_block.input
    return AuthJudgeVerdict(
        is_real_vulnerability=bool(tool_input["is_real_vulnerability"]),
        confidence=int(tool_input["confidence"]),
        reasoning=str(tool_input["reasoning"]),
    )
