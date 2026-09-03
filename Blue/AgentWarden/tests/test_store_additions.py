"""Targeted tests for the fixes made during the September 2026 review pass:
Task.blast_radius_ceiling persistence (H5), sessions_store.list_all_sessions
(M2), and calls_store.list_distinct_upstreams_for_task (M11)."""
from __future__ import annotations

from datetime import datetime, timezone

from agentwarden.models import CallOutcome, SessionStatus, Task, TaskStatus, ToolCallRecord
from agentwarden.store import calls as calls_store
from agentwarden.store import sessions as sessions_store


def _now():
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


async def test_task_blast_radius_ceiling_round_trips(store):
    await sessions_store.create_task(store, Task(
        task_id="t1", root_session_id="s1", identity_id="id-a", status=TaskStatus.OPEN,
        opened_at=_now(), blast_radius_ceiling=7,
    ))
    task = await sessions_store.get_task(store, "t1")
    assert task is not None
    assert task.blast_radius_ceiling == 7


async def test_task_blast_radius_ceiling_defaults_to_zero(store):
    await sessions_store.create_task(store, Task(task_id="t1", root_session_id="s1", identity_id="id-a"))
    task = await sessions_store.get_task(store, "t1")
    assert task.blast_radius_ceiling == 0


async def test_list_all_sessions_returns_active_and_closed(store):
    from agentwarden.models import AgentSession

    await sessions_store.create_session(store, AgentSession(
        session_id="s1", identity_id="id-a", transport="memory", task_id="t1", root_session_id="s1",
        instance_id="inst-1", started_at=_now(), last_activity_at=_now(), status=SessionStatus.ACTIVE,
    ))
    await sessions_store.create_session(store, AgentSession(
        session_id="s2", identity_id="id-a", transport="memory", task_id="t1", root_session_id="s1",
        instance_id="inst-1", started_at=_now(), last_activity_at=_now(), status=SessionStatus.CLOSED,
    ))

    all_sessions = await sessions_store.list_all_sessions(store)
    active_only = await sessions_store.list_active_sessions(store)

    assert {s.session_id for s in all_sessions} == {"s1", "s2"}
    assert {s.session_id for s in active_only} == {"s1"}


async def test_list_distinct_upstreams_for_task(store):
    for i, upstream in enumerate(["fs-mcp", "fs-mcp", "github-mcp"]):
        await calls_store.record_call(store, ToolCallRecord(
            call_id=f"c{i}", session_id="s1", task_id="t1", upstream_server_id=upstream, tool_name="tool",
            arguments_digest="x", redacted_arguments={}, outcome=CallOutcome.ALLOWED,
            matched_rule_id=None, grant_id=None, started_at=_now(),
        ))

    distinct = await calls_store.list_distinct_upstreams_for_task(store, "t1")
    assert distinct == {"fs-mcp", "github-mcp"}


async def test_list_distinct_upstreams_for_task_empty_when_no_calls(store):
    distinct = await calls_store.list_distinct_upstreams_for_task(store, "no-such-task")
    assert distinct == set()
