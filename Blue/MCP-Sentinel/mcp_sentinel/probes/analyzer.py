"""Analyze a tool's live call response for injected instructions.

Heuristic pattern matching (rules/text_patterns.py, shared with the static
tool-poisoning scan) runs unconditionally. If ANTHROPIC_API_KEY is configured,
an LLM judge (llm/client.py) also reviews the response and can catch
injection attempts that don't match any known phrasing - matching the
fail-visible-fallback pattern used elsewhere in this toolkit's LLM
integrations: a missing key degrades to heuristics only, it never blocks
the scan.
"""
from __future__ import annotations

from mcp_sentinel.config import settings
from mcp_sentinel.models import Finding, RiskCategory, Severity
from mcp_sentinel.rules.catalog import OWASP_CONTEXT_INJECTION, OWASP_INTENT_FLOW_SUBVERSION
from mcp_sentinel.rules.text_patterns import detect_injection_patterns


def analyze_tool_response(server_id: str, tool_name: str, response_text: str) -> list[Finding]:
    if not response_text:
        return []

    label = f"Tool '{tool_name}' response"
    findings = [
        Finding(
            finding_id=f"probe-{hit.rule}:{server_id}:{tool_name}",
            severity=hit.severity,
            category=RiskCategory.PROMPT_INJECTION,
            title=hit.title,
            description=hit.description + " This was found in the tool's actual response to a live probe call, not just its advertised description.",
            server_id=server_id,
            tool_name=tool_name,
            evidence=hit.evidence,
            recommendation="Do not trust this tool's output in an agent context until the server operator explains the content. If it fetches third-party/upstream data, that upstream may be compromised.",
            references=(OWASP_CONTEXT_INJECTION, OWASP_INTENT_FLOW_SUBVERSION),
        )
        for hit in detect_injection_patterns(response_text, subject_label=label)
    ]

    if settings.has_llm_key:
        findings.extend(_llm_judge_findings(server_id, tool_name, response_text))

    return findings


def _llm_judge_findings(server_id: str, tool_name: str, response_text: str) -> list[Finding]:
    from mcp_sentinel.llm.client import LLMNotConfiguredError, judge_response

    try:
        verdict = judge_response(tool_name, response_text)
    except LLMNotConfiguredError:
        return []
    except Exception:  # noqa: BLE001 - an LLM-side failure must degrade, not break the scan
        return []

    if not verdict.is_suspicious:
        return []

    return [
        Finding(
            finding_id=f"probe-llm-judge:{server_id}:{tool_name}",
            severity=Severity.HIGH if verdict.confidence >= 70 else Severity.MEDIUM,
            category=RiskCategory.PROMPT_INJECTION,
            title=f"LLM judge flagged tool '{tool_name}' response as a likely injection attempt",
            description=verdict.reasoning,
            server_id=server_id,
            tool_name=tool_name,
            evidence={"confidence": verdict.confidence, "response_snippet": response_text[:300]},
            recommendation="Manually review the full response; treat this tool's output as untrusted in the meantime.",
            references=(OWASP_CONTEXT_INJECTION, OWASP_INTENT_FLOW_SUBVERSION),
        )
    ]
