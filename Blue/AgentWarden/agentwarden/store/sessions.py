"""CRUD for Identity, Task, AgentSession, and SessionEdge."""
from __future__ import annotations

import sqlite3

from agentwarden.models import (
    AgentSession,
    Identity,
    SessionEdge,
    SessionStatus,
    Task,
    TaskStatus,
)
from agentwarden.store._codec import dt_to_str, opt_dt_to_str, opt_str_to_dt, str_to_dt
from agentwarden.store.connection import Store


def _session_from_row(row: sqlite3.Row) -> AgentSession:
    return AgentSession(
        session_id=row["session_id"],
        identity_id=row["identity_id"],
        transport=row["transport"],
        task_id=row["task_id"],
        root_session_id=row["root_session_id"],
        instance_id=row["instance_id"],
        parent_session_id=row["parent_session_id"],
        started_at=str_to_dt(row["started_at"]),
        last_activity_at=str_to_dt(row["last_activity_at"]),
        ended_at=opt_str_to_dt(row["ended_at"]),
        closed_reason=row["closed_reason"],
        status=SessionStatus(row["status"]),
    )


def _task_from_row(row: sqlite3.Row) -> Task:
    return Task(
        task_id=row["task_id"],
        root_session_id=row["root_session_id"],
        identity_id=row["identity_id"],
        status=TaskStatus(row["status"]),
        opened_at=str_to_dt(row["opened_at"]),
        closed_at=opt_str_to_dt(row["closed_at"]),
    )


async def upsert_identity(store: Store, identity: Identity) -> None:
    def _run(conn: sqlite3.Connection) -> None:
        conn.execute(
            "INSERT INTO identities (identity_id, label, source, bound_at) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(identity_id) DO UPDATE SET label=excluded.label, source=excluded.source",
            (identity.identity_id, identity.label, identity.source, dt_to_str(identity.bound_at)),
        )
        conn.commit()

    await store.run(_run)


async def create_task(store: Store, task: Task) -> None:
    def _run(conn: sqlite3.Connection) -> None:
        conn.execute(
            "INSERT INTO tasks (task_id, root_session_id, identity_id, status, opened_at, closed_at) VALUES (?, ?, ?, ?, ?, ?)",
            (task.task_id, task.root_session_id, task.identity_id, task.status.value, dt_to_str(task.opened_at), opt_dt_to_str(task.closed_at)),
        )
        conn.commit()

    await store.run(_run)


async def get_task(store: Store, task_id: str) -> Task | None:
    def _run(conn: sqlite3.Connection) -> Task | None:
        row = conn.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
        return _task_from_row(row) if row else None

    return await store.run(_run)


async def close_task(store: Store, task_id: str, closed_at: str) -> None:
    def _run(conn: sqlite3.Connection) -> None:
        conn.execute("UPDATE tasks SET status = ?, closed_at = ? WHERE task_id = ?", (TaskStatus.CLOSED.value, closed_at, task_id))
        conn.commit()

    await store.run(_run)


async def create_session(store: Store, session: AgentSession) -> None:
    def _run(conn: sqlite3.Connection) -> None:
        conn.execute(
            "INSERT INTO sessions (session_id, identity_id, transport, task_id, root_session_id, instance_id, "
            "parent_session_id, started_at, last_activity_at, ended_at, closed_reason, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                session.session_id, session.identity_id, session.transport, session.task_id, session.root_session_id,
                session.instance_id, session.parent_session_id, dt_to_str(session.started_at), dt_to_str(session.last_activity_at),
                opt_dt_to_str(session.ended_at), session.closed_reason, session.status.value,
            ),
        )
        conn.commit()

    await store.run(_run)


async def get_session(store: Store, session_id: str) -> AgentSession | None:
    def _run(conn: sqlite3.Connection) -> AgentSession | None:
        row = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
        return _session_from_row(row) if row else None

    return await store.run(_run)


async def touch_session(store: Store, session_id: str, at: str) -> None:
    def _run(conn: sqlite3.Connection) -> None:
        conn.execute("UPDATE sessions SET last_activity_at = ? WHERE session_id = ?", (at, session_id))
        conn.commit()

    await store.run(_run)


async def close_session(store: Store, session_id: str, ended_at: str, reason: str) -> None:
    def _run(conn: sqlite3.Connection) -> None:
        conn.execute(
            "UPDATE sessions SET status = ?, ended_at = ?, closed_reason = ? WHERE session_id = ?",
            (SessionStatus.CLOSED.value, ended_at, reason, session_id),
        )
        conn.commit()

    await store.run(_run)


async def list_active_sessions(store: Store) -> list[AgentSession]:
    def _run(conn: sqlite3.Connection) -> list[AgentSession]:
        rows = conn.execute("SELECT * FROM sessions WHERE status = ?", (SessionStatus.ACTIVE.value,)).fetchall()
        return [_session_from_row(r) for r in rows]

    return await store.run(_run)


async def list_child_sessions(store: Store, parent_session_id: str) -> list[AgentSession]:
    def _run(conn: sqlite3.Connection) -> list[AgentSession]:
        rows = conn.execute("SELECT * FROM sessions WHERE parent_session_id = ?", (parent_session_id,)).fetchall()
        return [_session_from_row(r) for r in rows]

    return await store.run(_run)


async def reconcile_stale_sessions(store: Store, current_instance_id: str, ended_at: str) -> int:
    """Startup reconciliation: a process crash/kill never writes `ended_at`,
    so a prior instance's sessions stay 'active' forever and would spuriously
    trip CONCURRENT_SESSION_ANOMALY on this run. Close every active session
    that isn't owned by this instance."""

    def _run(conn: sqlite3.Connection) -> int:
        cur = conn.execute(
            "UPDATE sessions SET status = ?, ended_at = ?, closed_reason = ? WHERE status = ? AND instance_id != ?",
            (SessionStatus.CLOSED.value, ended_at, "stale: reconciled at startup of a new instance", SessionStatus.ACTIVE.value, current_instance_id),
        )
        conn.commit()
        return cur.rowcount

    return await store.run(_run)


async def count_active_sessions_for_task(store: Store, task_id: str) -> int:
    def _run(conn: sqlite3.Connection) -> int:
        (count,) = conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE task_id = ? AND status = ?", (task_id, SessionStatus.ACTIVE.value)
        ).fetchone()
        return count

    return await store.run(_run)


async def record_session_edge(store: Store, edge: SessionEdge) -> None:
    def _run(conn: sqlite3.Connection) -> None:
        conn.execute(
            "INSERT INTO session_edges (child_session_id, parent_session_id, declared_at, accepted, rejection_reason) "
            "VALUES (?, ?, ?, ?, ?) ON CONFLICT(child_session_id) DO UPDATE SET "
            "parent_session_id=excluded.parent_session_id, declared_at=excluded.declared_at, "
            "accepted=excluded.accepted, rejection_reason=excluded.rejection_reason",
            (edge.child_session_id, edge.parent_session_id, dt_to_str(edge.declared_at), int(edge.accepted), edge.rejection_reason),
        )
        conn.commit()

    await store.run(_run)
