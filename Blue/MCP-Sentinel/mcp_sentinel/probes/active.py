"""Active probing: safely invoke a server's read-only tools and analyze their
real responses for injected content (see probes/analyzer.py).

Safety model (deliberately conservative - this is the one part of the
scanner that touches a live server with a real call, not just reads its
metadata):
  - Only tools explicitly declaring readOnlyHint=true are ever invoked. A
    tool with no annotation, or destructiveHint=true, is skipped, full stop.
    There is no override flag for this - if you need to test a tool that
    doesn't declare itself read-only, invoke it manually.
  - Even a readOnlyHint=true tool is skipped if its own name/description
    still matches exec/shell/subprocess language (rules.privilege's
    has_exec_indicators) - an annotation can lie, and this is the probe
    module's own defense-in-depth against a poisoned/mislabeled tool.
  - Required arguments are filled with mundane, hardcoded values (see
    payloads.py). A tool is skipped entirely, rather than guessed at, if any
    required argument can't be confidently constructed (e.g. a required
    object/array parameter).
  - A tool call that errors on our synthetic input is not itself a finding -
    we only analyze successful responses.
"""
from __future__ import annotations

import logging

from mcp.client import Client

from mcp_sentinel.models import Finding, ServerInventory, ToolInfo
from mcp_sentinel.probes.analyzer import analyze_tool_response
from mcp_sentinel.probes.payloads import build_probe_arguments
from mcp_sentinel.rules.privilege import has_exec_indicators

logger = logging.getLogger(__name__)

# A probed tool is calling out to an explicitly untrusted/hostile server by
# design - cap how much of its response we ever hold in memory or run regexes
# (and, if configured, an LLM call) over, so a malicious server can't inflate
# scanner memory/CPU use by returning an arbitrarily large result.
_MAX_RESPONSE_CHARS = 50_000


def is_safe_to_probe(tool: ToolInfo) -> bool:
    return tool.annotations.read_only_hint is True and not has_exec_indicators(tool)


def _extract_text(result) -> str:  # noqa: ANN001 - CallToolResult from mcp_types, kept loosely typed to avoid a hard SDK-internal import here
    parts: list[str] = []
    total = 0
    for block in getattr(result, "content", None) or []:
        text = getattr(block, "text", None)
        if text:
            parts.append(text)
            total += len(text)
            if total >= _MAX_RESPONSE_CHARS:
                break
    return "\n".join(parts)[:_MAX_RESPONSE_CHARS]


async def run_active_probes(client: Client, inventory: ServerInventory, *, read_timeout_seconds: float = 15.0) -> list[Finding]:
    findings: list[Finding] = []
    server_id = inventory.config.server_id

    for tool in inventory.tools:
        if not is_safe_to_probe(tool):
            continue

        args = build_probe_arguments(tool.input_schema)
        if args is None:
            continue

        try:
            result = await client.call_tool(tool.name, args, read_timeout_seconds=read_timeout_seconds)
        except Exception:  # noqa: BLE001 - a probe call erroring on our synthetic input isn't a finding, just skip it (see module docstring)
            logger.debug("probe call to %s on %s failed; skipping", tool.name, server_id, exc_info=True)
            continue

        if getattr(result, "is_error", False):
            continue

        text = _extract_text(result)
        findings.extend(analyze_tool_response(server_id, tool.name, text))

    return findings
