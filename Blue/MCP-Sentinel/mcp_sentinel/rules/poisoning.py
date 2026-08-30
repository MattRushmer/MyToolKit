"""Static tool-poisoning detection: hidden instructions, invisible characters,
and cross-tool manipulation planted inside tool/resource/prompt descriptions.

The MCP tool description field is, from the agent's point of view, part of its
own context - a server can write anything there and a host will feed it to the
model as if it were trustworthy documentation. This module looks for the
known shapes that abuse that trust.
"""
from __future__ import annotations

import re

from mcp_sentinel.models import Finding, PromptInfo, ResourceInfo, RiskCategory, ServerInventory, Severity, ToolInfo
from mcp_sentinel.rules.catalog import OWASP_TOOL_POISONING

_INJECTION_PHRASES = re.compile(
    r"(ignore (all|any|the)?\s*(previous|prior|above)\s*instructions?"
    r"|disregard (previous|prior|the)\s*(system\s*)?prompt"
    r"|do not (tell|inform|mention to)\s*the user"
    r"|without (asking|telling|informing)\s*the user"
    r"|new instructions?:"
    r"|you must (now|always)"
    r"|<system>|\[system\]|</?instructions?>"
    r"|before (calling|using|responding).{0,40}(also|first|silently)\s*call"
    r"|this tool must be called before)",
    re.IGNORECASE,
)

_HIDDEN_MARKUP = re.compile(r"<!--.*?-->|<span[^>]*display:\s*none[^>]*>", re.IGNORECASE | re.DOTALL)
_ZERO_WIDTH_CHARS = re.compile(r"[​‌‍⁠﻿]")
_LONG_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")

_MAX_REASONABLE_DESCRIPTION_LEN = 2000


def _scan_text(server_id: str, subject_kind: str, subject_name: str, text: str) -> list[Finding]:
    if not text:
        return []
    findings: list[Finding] = []

    phrase_hits = _INJECTION_PHRASES.findall(text)
    if phrase_hits:
        findings.append(
            _finding(
                server_id, subject_kind, subject_name, "phrase",
                f"{subject_kind.capitalize()} '{subject_name}' description contains instruction-injection phrasing",
                f"Text matched known prompt-injection phrasing (e.g. 'ignore previous instructions', "
                f"'without asking the user'). An agent that trusts {subject_kind} metadata as documentation "
                "may follow it as a command instead.",
                Severity.CRITICAL,
                {"snippet": _snippet(text)},
            )
        )

    if _HIDDEN_MARKUP.search(text):
        findings.append(
            _finding(
                server_id, subject_kind, subject_name, "hidden-markup",
                f"{subject_kind.capitalize()} '{subject_name}' description contains hidden/invisible markup",
                "HTML comments or display:none spans hide content from a human reading a UI rendering of this "
                "description while a model still receives the full raw text.",
                Severity.HIGH,
                {"snippet": _snippet(text)},
            )
        )

    if _ZERO_WIDTH_CHARS.search(text):
        findings.append(
            _finding(
                server_id, subject_kind, subject_name, "zero-width-chars",
                f"{subject_kind.capitalize()} '{subject_name}' description contains zero-width/invisible Unicode characters",
                "Zero-width characters render as nothing but are still tokenized and can be used to hide "
                "text from human review or to break up filtered keywords.",
                Severity.HIGH,
                {"snippet": _snippet(text)},
            )
        )

    if _LONG_BASE64_BLOB.search(text):
        findings.append(
            _finding(
                server_id, subject_kind, subject_name, "base64-blob",
                f"{subject_kind.capitalize()} '{subject_name}' description contains a large encoded blob",
                "A long base64-like run inside a description is unusual for human-facing documentation and "
                "may smuggle encoded instructions or data past naive keyword filters.",
                Severity.MEDIUM,
                {"snippet": _snippet(text)},
            )
        )

    if len(text) > _MAX_REASONABLE_DESCRIPTION_LEN:
        findings.append(
            _finding(
                server_id, subject_kind, subject_name, "oversized-description",
                f"{subject_kind.capitalize()} '{subject_name}' description is unusually long ({len(text)} chars)",
                "An oversized description is a common way to bury injected instructions in text a human "
                "reviewer is unlikely to read in full.",
                Severity.LOW,
                {"length": len(text)},
            )
        )

    return findings


def _finding(server_id: str, kind: str, name: str, rule: str, title: str, description: str, severity: Severity, evidence: dict) -> Finding:
    return Finding(
        finding_id=f"poison-{rule}:{server_id}:{kind}:{name}",
        severity=severity,
        category=RiskCategory.TOOL_POISONING,
        title=title,
        description=description,
        server_id=server_id,
        tool_name=name if kind == "tool" else None,
        evidence={**evidence, "subject_kind": kind, "subject_name": name},
        recommendation="Treat this server as untrusted until the maintainer explains the content; do not grant it to agents in the meantime.",
        references=(OWASP_TOOL_POISONING,),
    )


def _snippet(text: str, length: int = 200) -> str:
    return text[:length] + ("…" if len(text) > length else "")


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
