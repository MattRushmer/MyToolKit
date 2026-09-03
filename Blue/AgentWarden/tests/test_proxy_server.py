"""Targeted tests for the H3 fix in agentwarden/proxy/server.py: client-
supplied session_id/parentSessionId/taskId used to be used verbatim as SQLite
primary keys with no charset validation, which meant (a) a crafted value
containing backticks/newlines could break out of the Markdown report's code
spans, and (b) two concurrent requests racing to claim the same never-before-
seen id could both pass the "does this exist yet" check before either INSERT
committed, surfacing as an unhandled sqlite3.IntegrityError instead of a
clean deny. Before this fix there was no dedicated test file for
agentwarden/proxy/ at all (a gap called out by both the code-quality and
Python-specific reviews this file accompanies)."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from agentwarden.clock import SystemClock
from agentwarden.ids import new_id
from agentwarden.models import AgentSession, EventType, SessionStatus
from agentwarden.proxy.server import META_SESSION_KEY, AgentWardenProxy, _is_valid_claimed_id
from agentwarden.proxy.upstream import UpstreamPool
from agentwarden.store import audit as audit_store
from agentwarden.store import sessions as sessions_store
from mcp.client import Client
from mcp.client._memory import InMemoryTransport


@pytest.mark.parametrize("value", ["abc123", "a-b_c", "A" * 64])
def test_valid_claimed_ids_accepted(value):
    assert _is_valid_claimed_id(value) is True


@pytest.mark.parametrize("value", ["", "a" * 65, "has space", "back`tick", "new\nline", "../traversal", None, 123])
def test_invalid_claimed_ids_rejected(value):
    assert _is_valid_claimed_id(value) is False


async def _build_bare_proxy(store) -> AgentWardenProxy:
    """A minimal, started proxy with zero upstreams - enough to exercise
    `_handle_call_tool`'s validation and session-resolution logic without
    needing a real upstream MCP server wired up."""
    proxy = AgentWardenProxy(
        identity_id="id-a", identity_label="test", listener_source="test", transport_label="memory",
        policy_rules_by_identity={}, enforcement_modes={}, upstream_pool=UpstreamPool([]), store=store,
        clock=SystemClock(), new_id=new_id, instance_id="inst-1", blast_radius_ceiling=3,
    )
    await proxy.start()
    return proxy


async def test_invalid_session_id_in_meta_is_denied_cleanly_not_crashed(store):
    proxy = await _build_bare_proxy(store)
    async with Client(server=InMemoryTransport(proxy.mcp_server)) as client:
        result = await client.call_tool("write_file", {}, meta={META_SESSION_KEY: "has a space"})
    assert result.is_error
    assert "invalid" in result.content[0].text.lower()


async def test_invalid_parent_session_id_in_meta_is_denied_cleanly(store):
    proxy = await _build_bare_proxy(store)
    async with Client(server=InMemoryTransport(proxy.mcp_server)) as client:
        result = await client.call_tool("write_file", {}, meta={
            "dev.agentwarden/sessionId": "valid-id",
            "dev.agentwarden/parentSessionId": "bad`parent",
        })
    assert result.is_error
    assert "invalid" in result.content[0].text.lower()


async def test_valid_session_id_reaches_normal_unknown_tool_denial(store):
    """Sanity check that the charset gate doesn't reject legitimate ids -
    the call should proceed past validation and fail for the *expected*
    reason (no upstream registered for this tool), not the id check."""
    proxy = await _build_bare_proxy(store)
    async with Client(server=InMemoryTransport(proxy.mcp_server)) as client:
        result = await client.call_tool("write_file", {}, meta={META_SESSION_KEY: "valid-session-1"})
    assert result.is_error
    assert "unknown tool" in result.content[0].text.lower()


async def test_create_session_integrity_error_is_caught_not_raised(store):
    """Deterministic reproduction of the race's failure mode: a row for this
    exact session_id already exists (here, because it was closed by a prior
    connection - a genuine concurrent-race winner would look the same to this
    code path: an INSERT that hits the same primary key). Before the fix,
    `create_session`'s sqlite3.IntegrityError propagated straight out of
    `_resolve_or_create_session` uncaught."""
    await sessions_store.create_session(store, AgentSession(
        session_id="dup-id", identity_id="id-a", transport="memory", task_id="dup-id", root_session_id="dup-id",
        instance_id="other-instance", started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        last_activity_at=datetime(2026, 1, 1, tzinfo=timezone.utc), status=SessionStatus.CLOSED,
    ))

    proxy = await _build_bare_proxy(store)
    async with Client(server=InMemoryTransport(proxy.mcp_server)) as client:
        result = await client.call_tool("write_file", {}, meta={META_SESSION_KEY: "dup-id"})
    # Must not raise past the mediator; falls through to the ordinary
    # "unknown tool" denial once a session is resolved without crashing.
    assert result.is_error
    assert "unknown tool" in result.content[0].text.lower()

    # The race must still be visible in the audit trail, not silently
    # swallowed - a verification-pass finding on the first version of this fix.
    events = await audit_store.list_events(store)
    assert any(e.event_type is EventType.CONCURRENT_SESSION_ANOMALY for e in events)
