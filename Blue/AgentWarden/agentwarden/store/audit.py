"""Append-only AuditEvent log with a sha256 hash chain.

Not a legal/cryptographic tamper-*proof* (the DB file is still editable by
anyone with filesystem access, and there's no external anchor for the chain
head), but tamper-*evident*: rewriting or deleting a historical row breaks
every subsequent link, which `verify_chain()` detects. `seq` (SQLite's
AUTOINCREMENT rowid) is the real ordering key - timestamps alone aren't
reliable under concurrent asyncio writers, though writes are in fact fully
serialized by Store's lock, which is also what makes "read the last hash,
then insert" race-free without a separate transaction.
"""
from __future__ import annotations

import dataclasses
import hashlib
import sqlite3

from agentwarden.models import AuditEvent, EventType, Severity
from agentwarden.store._codec import dt_to_str, from_json, str_to_dt, to_json
from agentwarden.store.connection import Store

_GENESIS_HASH = "0" * 64


def _canonical(event: AuditEvent, prev_hash: str) -> str:
    return "|".join([
        prev_hash, event.event_id, event.timestamp.isoformat(), event.session_id, event.task_id, event.identity_id,
        event.event_type.value, event.severity.value, event.call_id or "", event.grant_id or "",
        event.tool_name or "", event.upstream_server_id or "", to_json(event.detail),
    ])


def _event_from_row(row: sqlite3.Row) -> AuditEvent:
    return AuditEvent(
        event_id=row["event_id"],
        seq=row["seq"],
        timestamp=str_to_dt(row["timestamp"]),
        session_id=row["session_id"],
        task_id=row["task_id"],
        identity_id=row["identity_id"],
        event_type=EventType(row["event_type"]),
        severity=Severity(row["severity"]),
        call_id=row["call_id"],
        grant_id=row["grant_id"],
        tool_name=row["tool_name"],
        upstream_server_id=row["upstream_server_id"],
        detail=from_json(row["detail_json"]),  # type: ignore[arg-type]
        prev_hash=row["prev_hash"],
        event_hash=row["event_hash"],
    )


async def append_event(store: Store, event: AuditEvent) -> AuditEvent:
    """`event.seq`/`prev_hash`/`event_hash` on the input are ignored - they're
    assigned here, atomically with respect to every other store access, and
    the fully-populated event is returned."""

    def _run(conn: sqlite3.Connection) -> AuditEvent:
        last = conn.execute("SELECT event_hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
        prev_hash = last["event_hash"] if last else _GENESIS_HASH
        event_hash = hashlib.sha256(_canonical(event, prev_hash).encode("utf-8")).hexdigest()

        cur = conn.execute(
            "INSERT INTO audit_events (event_id, timestamp, session_id, task_id, identity_id, event_type, severity, "
            "call_id, grant_id, tool_name, upstream_server_id, detail_json, prev_hash, event_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event.event_id, dt_to_str(event.timestamp), event.session_id, event.task_id, event.identity_id,
                event.event_type.value, event.severity.value, event.call_id, event.grant_id, event.tool_name,
                event.upstream_server_id, to_json(event.detail), prev_hash, event_hash,
            ),
        )
        conn.commit()
        return dataclasses.replace(event, seq=cur.lastrowid, prev_hash=prev_hash, event_hash=event_hash)

    return await store.run(_run)


async def list_events(
    store: Store, *, session_id: str | None = None, min_severity: Severity | None = None, since_seq: int = 0,
) -> list[AuditEvent]:
    from agentwarden.models import severity_rank

    def _run(conn: sqlite3.Connection) -> list[AuditEvent]:
        clauses = ["seq > ?"]
        params: list[object] = [since_seq]
        if session_id is not None:
            clauses.append("session_id = ?")
            params.append(session_id)
        rows = conn.execute(f"SELECT * FROM audit_events WHERE {' AND '.join(clauses)} ORDER BY seq", params).fetchall()
        events = [_event_from_row(r) for r in rows]
        if min_severity is not None:
            events = [e for e in events if severity_rank(e.severity) <= severity_rank(min_severity)]
        return events

    return await store.run(_run)


async def verify_chain(store: Store) -> tuple[bool, int | None]:
    """Returns (intact, first_broken_seq). Recomputes every link from scratch
    and compares - O(n) in the number of events, fine at CLI-invocation scale."""

    def _run(conn: sqlite3.Connection) -> tuple[bool, int | None]:
        rows = conn.execute("SELECT * FROM audit_events ORDER BY seq").fetchall()
        prev_hash = _GENESIS_HASH
        for row in rows:
            event = _event_from_row(row)
            expected = hashlib.sha256(_canonical(event, prev_hash).encode("utf-8")).hexdigest()
            if row["prev_hash"] != prev_hash or row["event_hash"] != expected:
                return False, row["seq"]
            prev_hash = row["event_hash"]
        return True, None

    return await store.run(_run)


class EventBuilder:
    """Small convenience so mediator/detector callers don't repeat
    `AuditEvent(event_id=new_id("evt"), seq=0, timestamp=clock.now(), ...)`
    boilerplate at every call site - `seq`/`prev_hash`/`event_hash` are
    placeholder values overwritten by append_event()."""

    def __init__(self, new_id, clock):
        self._new_id = new_id
        self._clock = clock

    def build(
        self, *, session_id: str, task_id: str, identity_id: str, event_type: EventType, severity: Severity,
        call_id: str | None = None, grant_id: str | None = None, tool_name: str | None = None,
        upstream_server_id: str | None = None, detail: dict | None = None,
    ) -> AuditEvent:
        return AuditEvent(
            event_id=self._new_id("evt"), seq=0, timestamp=self._clock.now(), session_id=session_id, task_id=task_id,
            identity_id=identity_id, event_type=event_type, severity=severity, call_id=call_id, grant_id=grant_id,
            tool_name=tool_name, upstream_server_id=upstream_server_id, detail=detail or {},
        )
