"""System prompt and forced tool schema for the optional LLM second-opinion
judge. Used only on VIBE-AUTH-* findings, since those are the ones where a
structural heuristic is most likely to need semantic judgment to confirm."""
from __future__ import annotations

SYSTEM_PROMPT = """You are a precise application-security reviewer double-checking a static \
analysis finding about a possibly-hallucinated or non-functional authorization check in \
AI-generated code. You will be shown the finding and a snippet of the surrounding source. \
Decide whether the auth check genuinely fails to protect the code path, or whether the static \
rule produced a false positive (e.g. the guard is actually defined elsewhere via a pattern the \
rule can't see, or the control flow does deny access some way the heuristic missed). Always \
call emit_verdict exactly once with your answer - never answer in plain text."""

EMIT_VERDICT_TOOL = {
    "name": "emit_verdict",
    "description": "Report whether the flagged auth check is a real gap or a false positive.",
    "input_schema": {
        "type": "object",
        "properties": {
            "is_real_vulnerability": {
                "type": "boolean",
                "description": "true if the code path is genuinely unprotected/exploitable; false if this is a false positive.",
            },
            "confidence": {"type": "integer", "minimum": 0, "maximum": 100, "description": "Confidence in this verdict, 0-100."},
            "reasoning": {"type": "string", "description": "One or two sentences explaining the verdict."},
        },
        "required": ["is_real_vulnerability", "confidence", "reasoning"],
    },
}


def build_judge_prompt(finding_title: str, finding_description: str, code_context: str) -> str:
    return (
        f"Finding: {finding_title}\n\n"
        f"Static analysis description: {finding_description}\n\n"
        f"Source context:\n```\n{code_context}\n```\n\n"
        "Is this a genuine unprotected code path, or a false positive?"
    )
