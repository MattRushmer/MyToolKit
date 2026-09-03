"""Every denial the mediator produces goes through here, so a host sees the
exact same CallToolResult shape (isError=True, one TextContent block)
regardless of *why* the call was denied - the reason lives in the audit
log, not in a bespoke error format per denial path."""
from __future__ import annotations

from mcp_types import CallToolResult, TextContent


def deny_result(message: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=f"AgentWarden denied this call: {message}")], is_error=True)


def unknown_tool_result(tool_name: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=f"Unknown tool: {tool_name}")], is_error=True)
