from __future__ import annotations

from agentwarden.broker.delegation import resolve_delegation
from agentwarden.clock import SystemClock
from agentwarden.models import AgentSession, SessionStatus, Task, TaskStatus
from agentwarden.store import sessions as sessions_store


async def _make_session(store, session_id, identity_id="id-a", task_id=None, parent=None, status=SessionStatus.ACTIVE):
    task_id = task_id or session_id
    await sessions_store.create_session(store, AgentSession(
        session_id=session_id, identity_id=identity_id, transport="memory", task_id=task_id,
        root_session_id=task_id, instance_id="inst", parent_session_id=parent, status=status,
    ))


async def test_no_parent_claimed_creates_new_root_task(store):
    resolution = await resolve_delegation(store, new_session_id="s1", identity_id="id-a", claimed_parent_session_id=None, claimed_task_id=None, clock=SystemClock())
    assert resolution.is_new_task
    assert resolution.task_id == "s1"
    assert resolution.rejection_reason is None


async def test_accepted_parent_forces_child_task_id(store):
    await _make_session(store, "root")
    resolution = await resolve_delegation(store, new_session_id="child", identity_id="id-a", claimed_parent_session_id="root", claimed_task_id="child-wants-its-own-task", clock=SystemClock())
    assert resolution.rejection_reason is None
    assert resolution.task_id == "root"  # forced, not "child-wants-its-own-task"
    assert resolution.accepted_parent_session_id == "root"


async def test_rejects_missing_parent(store):
    resolution = await resolve_delegation(store, new_session_id="child", identity_id="id-a", claimed_parent_session_id="ghost", claimed_task_id=None, clock=SystemClock())
    assert resolution.rejection_reason is not None
    assert resolution.accepted_parent_session_id is None
    assert resolution.task_id == "child"  # falls back to independent root


async def test_rejects_inactive_parent(store):
    await _make_session(store, "root", status=SessionStatus.CLOSED)
    resolution = await resolve_delegation(store, new_session_id="child", identity_id="id-a", claimed_parent_session_id="root", claimed_task_id=None, clock=SystemClock())
    assert resolution.rejection_reason is not None
    assert "not active" in resolution.rejection_reason


async def test_rejects_cross_identity_parent(store):
    await _make_session(store, "root", identity_id="id-a")
    resolution = await resolve_delegation(store, new_session_id="child", identity_id="id-b", claimed_parent_session_id="root", claimed_task_id=None, clock=SystemClock())
    assert resolution.rejection_reason is not None
    assert "different identity" in resolution.rejection_reason


async def test_phantom_task_join_without_parent_is_rejected_and_flagged(store):
    await sessions_store.create_task(store, Task(task_id="existing-task", root_session_id="root", identity_id="id-a", status=TaskStatus.OPEN))
    resolution = await resolve_delegation(store, new_session_id="intruder", identity_id="id-a", claimed_parent_session_id=None, claimed_task_id="existing-task", clock=SystemClock())
    assert resolution.is_concurrent_anomaly
    assert resolution.task_id == "intruder"  # gets its own task, claim ignored
    assert resolution.rejection_reason is not None


async def test_claiming_a_brand_new_task_id_with_no_existing_row_is_fine(store):
    resolution = await resolve_delegation(store, new_session_id="s1", identity_id="id-a", claimed_parent_session_id=None, claimed_task_id="s1-custom-task", clock=SystemClock())
    assert resolution.rejection_reason is None
    assert resolution.task_id == "s1-custom-task"
