"""CRUD for ToolCallRecord.

Every session that accepts a delegation link shares its parent's `task_id`
(see broker/delegation.py), so a task's whole session subtree's calls are
already flat-queryable by `task_id` alone - no session-graph traversal is
needed to answer "what did this task touch", which is exactly what
analysis/blast_radius.py wants (see that module's docstring for why the
graph is only needed for the anomaly checks, not the reachable-set query)."""
from __future__ import annotations

import sqlite3

from agentwarden.models import CallOutcome, ToolCallRecord
from agentwarden.store._codec import dt_to_str, from_json, opt_dt_to_str, opt_str_to_dt, str_to_dt, to_json
from agentwarden.store.connection import Store


def _call_from_row(row: sqlite3.Row) -> ToolCallRecord:
    return ToolCallRecord(
        call_id=row["call_id"],
        session_id=row["session_id"],
        task_id=row["task_id"],
        upstream_server_id=row["upstream_server_id"],
        tool_name=row["tool_name"],
        arguments_digest=row["arguments_digest"],
        redacted_arguments=from_json(row["redacted_arguments_json"]),  # type: ignore[arg-type]
        outcome=CallOutcome(row["outcome"]),
        matched_rule_id=row["matched_rule_id"],
        grant_id=row["grant_id"],
        started_at=str_to_dt(row["started_at"]),
        completed_at=opt_str_to_dt(row["completed_at"]),
        latency_ms=row["latency_ms"],
    )


async def record_call(store: Store, record: ToolCallRecord) -> None:
    def _run(conn: sqlite3.Connection) -> None:
        conn.execute(
            "INSERT INTO calls (call_id, session_id, task_id, upstream_server_id, tool_name, arguments_digest, "
            "redacted_arguments_json, outcome, matched_rule_id, grant_id, started_at, completed_at, latency_ms) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record.call_id, record.session_id, record.task_id, record.upstream_server_id, record.tool_name,
                record.arguments_digest, to_json(record.redacted_arguments), record.outcome.value,
                record.matched_rule_id, record.grant_id, dt_to_str(record.started_at),
                opt_dt_to_str(record.completed_at), record.latency_ms,
            ),
        )
        conn.commit()

    await store.run(_run)


async def list_calls_for_task(store: Store, task_id: str) -> list[ToolCallRecord]:
    def _run(conn: sqlite3.Connection) -> list[ToolCallRecord]:
        rows = conn.execute("SELECT * FROM calls WHERE task_id = ? ORDER BY started_at", (task_id,)).fetchall()
        return [_call_from_row(r) for r in rows]

    return await store.run(_run)


async def list_calls_for_session(store: Store, session_id: str) -> list[ToolCallRecord]:
    def _run(conn: sqlite3.Connection) -> list[ToolCallRecord]:
        rows = conn.execute("SELECT * FROM calls WHERE session_id = ? ORDER BY started_at", (session_id,)).fetchall()
        return [_call_from_row(r) for r in rows]

    return await store.run(_run)


async def count_calls_for_session_tool(store: Store, session_id: str, tool_name: str, upstream_server_id: str) -> int:
    """Per-session count (as distinct from per-task) - used alongside the
    per-task check so a forged `task_id` (see broker/delegation.py) can't
    reset a rate-limit budget by claiming a fresh task while replaying the
    same session."""

    def _run(conn: sqlite3.Connection) -> int:
        (count,) = conn.execute(
            "SELECT COUNT(*) FROM calls WHERE session_id = ? AND tool_name = ? AND upstream_server_id = ? AND outcome = ?",
            (session_id, tool_name, upstream_server_id, CallOutcome.ALLOWED.value),
        ).fetchone()
        return count

    return await store.run(_run)
