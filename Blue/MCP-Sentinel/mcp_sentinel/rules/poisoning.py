"""Static tool-poisoning detection: hidden instructions, invisible characters,
and cross-tool manipulation planted inside tool/resource/prompt descriptions.

The MCP tool description field is, from the agent's point of view, part of its
own context - a server can write anything there and a host will feed it to the
model as if it were trustworthy documentation. This module looks for the
known shapes that abuse that trust. Detection lives in rules/text_patterns.py,
shared with probes/analyzer.py which runs the same checks against a tool's
*live response* instead of its description.
"""
from __future__ import annotations

from mcp_sentinel.models import Finding, PromptInfo, ResourceInfo, RiskCategory, ServerInventory, ToolInfo
from mcp_sentinel.rules.catalog import OWASP_TOOL_POISONING
from mcp_sentinel.rules.text_patterns import detect_injection_patterns


def _scan_text(server_id: str, subject_kind: str, subject_name: str, text: str) -> list[Finding]:
    label = f"{subject_kind.capitalize()} '{subject_name}' description"
    hits = detect_injection_patterns(text, subject_label=label)
    return [
        Finding(
            finding_id=f"poison-{hit.rule}:{server_id}:{subject_kind}:{subject_name}",
            severity=hit.severity,
            category=RiskCategory.TOOL_POISONING,
            title=hit.title,
            description=hit.description,
            server_id=server_id,
            tool_name=subject_name if subject_kind == "tool" else None,
            evidence={**hit.evidence, "subject_kind": subject_kind, "subject_name": subject_name},
            recommendation="Treat this server as untrusted until the maintainer explains the content; do not grant it to agents in the meantime.",
            references=(OWASP_TOOL_POISONING,),
        )
        for hit in hits
    ]


def check_tool_poisoning(server_id: str, tool: ToolInfo) -> list[Finding]:
    return _scan_text(server_id, "tool", tool.name, tool.description)


def check_resource_poisoning(server_id: str, resource: ResourceInfo) -> list[Finding]:
    return _scan_text(server_id, "resource", resource.name or resource.uri, resource.description)


def check_prompt_poisoning(server_id: str, prompt: PromptInfo) -> list[Finding]:
    return _scan_text(server_id, "prompt", prompt.name, prompt.description)


def check_server_poisoning(inventory: ServerInventory) -> list[Finding]:
    findings: list[Finding] = []
    for tool in inventory.tools:
        findings.extend(check_tool_poisoning(inventory.config.server_id, tool))
    for resource in inventory.resources:
        findings.extend(check_resource_poisoning(inventory.config.server_id, resource))
    for prompt in inventory.prompts:
        findings.extend(check_prompt_poisoning(inventory.config.server_id, prompt))
    return findings
