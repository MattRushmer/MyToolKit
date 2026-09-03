"""Targeted test for the M1 fix in agentwarden/proxy/mediator.py: a call that
policy ALLOWED but whose upstream dispatch itself then failed used to be
audited with event_type=GRANT_ISSUED - indistinguishable from a normal
successful grant issuance to anyone filtering/grouping the audit log by
event_type. It must get its own EventType.TOOL_CALL_ERROR instead. Before
this fix there was no dedicated test file for proxy/mediator.py at all."""
from __future__ import annotations

from mcp.client import Client
from mcp.client._memory import InMemoryTransport
from mcp.server.mcpserver import MCPServer

from agentwarden.clock import SystemClock
from agentwarden.ids import new_id
from agentwarden.models import ArgumentConstraint, EventType, PolicyRule
from agentwarden.proxy.server import AgentWardenProxy
from agentwarden.proxy.upstream import UpstreamConfig, UpstreamPool
from agentwarden.store import audit as audit_store


def _build_upstream() -> MCPServer:
    server = MCPServer("flaky-fixture")

    @server.tool()
    def flaky_tool() -> str:
        return "ok"

    return server


async def _build_proxy_allowing_flaky_tool(store):
    pool = UpstreamPool([UpstreamConfig(upstream_id="flaky-mcp", transport="memory", memory_server=_build_upstream())])
    await pool.start()

    rule = PolicyRule(
        rule_id="r1", identity_id="id-a", tool_name="flaky_tool", upstream_server_id="flaky-mcp",
        source="explicit", ttl_seconds=60, argument_constraints={},
    )
    proxy = AgentWardenProxy(
        identity_id="id-a", identity_label="test", listener_source="test", transport_label="memory",
        policy_rules_by_identity={"id-a": [rule]}, enforcement_modes={"id-a": "enforce"},
        upstream_pool=pool, store=store, clock=SystemClock(), new_id=new_id, instance_id="inst-1",
        blast_radius_ceiling=10,
    )
    await proxy.start()
    return proxy, pool


async def test_failed_upstream_dispatch_is_audited_as_tool_call_error_not_grant_issued(store, monkeypatch):
    """A real 'the tool itself returned isError=true' response doesn't raise
    at the UpstreamPool.call_tool() layer at all (MCP surfaces that as a
    normal CallToolResult, not a client-side exception) - the branch this
    test targets is specifically for a *transport/dispatch*-level failure
    (upstream connection dropped, timeout, ...), which is why the upstream
    pool's call is monkeypatched to raise directly rather than relying on a
    tool that raises Python-side."""
    proxy, pool = await _build_proxy_allowing_flaky_tool(store)

    async def _broken_call_tool(upstream_id, tool_name, arguments):
        raise RuntimeError("upstream is down")

    monkeypatch.setattr(pool, "call_tool", _broken_call_tool)

    try:
        async with Client(server=InMemoryTransport(proxy.mcp_server)) as client:
            result = await client.call_tool("flaky_tool", {}, meta={"dev.agentwarden/sessionId": "s1"})
    finally:
        await pool.stop()

    assert result.is_error
    assert "upstream call failed" in result.content[0].text.lower()

    events = await audit_store.list_events(store)
    event_types = {e.event_type for e in events}
    assert EventType.TOOL_CALL_ERROR in event_types
    assert EventType.GRANT_ISSUED not in event_types
