"""CRUD + lifecycle transitions for CredentialGrant.

`max_uses` on a grant is always 1 in v1 (the data model supports more for a
future "N retries of the same grant" policy feature, but no policy field
exposes it yet - see models.py's CredentialGrant docstring). The rate limit
that matters today, `max_uses_per_task`, counts *distinct grants minted* for
(task_id, tool_name, upstream) - mint() enforces it atomically.

Every function here runs its body inside one `Store.run()` call, which holds
the store's single process-wide lock for the duration - that's what makes
mint()'s "count existing grants, then insert" sequence atomic with respect
to every other concurrent mint, without needing a SQL-level transaction
trick: no other store access (a read or a write, from any task) can
interleave between the COUNT and the INSERT below.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta

from agentwarden.models import CredentialGrant, GrantStatus
from agentwarden.store._codec import dt_to_str, from_json, str_to_dt, to_json
from agentwarden.store.connection import Store


def _grant_from_row(row: sqlite3.Row) -> CredentialGrant:
    return CredentialGrant(
        grant_id=row["grant_id"],
        session_id=row["session_id"],
        task_id=row["task_id"],
        tool_name=row["tool_name"],
        upstream_server_id=row["upstream_server_id"],
        rule_id=row["rule_id"],
        scope=from_json(row["scope_json"]),  # type: ignore[arg-type]
        issued_at=str_to_dt(row["issued_at"]),
        expires_at=str_to_dt(row["expires_at"]),
        max_uses=row["max_uses"],
        use_count=row["use_count"],
        status=GrantStatus(row["status"]),
    )


class RateLimitExceeded(Exception):
    """Raised by mint() instead of returning None, so a caller can't forget
    to check for a falsy return and accidentally proceed as if a grant were issued."""


async def mint(
    store: Store, *, grant_id: str, session_id: str, task_id: str, tool_name: str, upstream_server_id: str,
    rule_id: str, scope: dict, issued_at: datetime, ttl_seconds: int, max_uses_per_task: int | None,
) -> CredentialGrant:
    expires_at = issued_at + timedelta(seconds=ttl_seconds)

    def _run(conn: sqlite3.Connection) -> CredentialGrant:
        if max_uses_per_task is not None:
            (count,) = conn.execute(
                "SELECT COUNT(*) FROM grants WHERE task_id = ? AND tool_name = ? AND upstream_server_id = ? AND status != ?",
                (task_id, tool_name, upstream_server_id, GrantStatus.REVOKED.value),
            ).fetchone()
            if count >= max_uses_per_task:
                raise RateLimitExceeded(f"{count} grant(s) already minted for task '{task_id}' tool '{tool_name}' (limit {max_uses_per_task})")

        conn.execute(
            "INSERT INTO grants (grant_id, session_id, task_id, tool_name, upstream_server_id, rule_id, scope_json, "
            "issued_at, expires_at, max_uses, use_count, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)",
            (
                grant_id, session_id, task_id, tool_name, upstream_server_id, rule_id, to_json(scope),
                dt_to_str(issued_at), dt_to_str(expires_at), 1, GrantStatus.ACTIVE.value,
            ),
        )
        conn.commit()
        return CredentialGrant(
            grant_id=grant_id, session_id=session_id, task_id=task_id, tool_name=tool_name,
            upstream_server_id=upstream_server_id, rule_id=rule_id, scope=scope, issued_at=issued_at,
            expires_at=expires_at, max_uses=1, use_count=0, status=GrantStatus.ACTIVE,
        )

    return await store.run(_run)


async def get_grant(store: Store, grant_id: str) -> CredentialGrant | None:
    def _run(conn: sqlite3.Connection) -> CredentialGrant | None:
        row = conn.execute("SELECT * FROM grants WHERE grant_id = ?", (grant_id,)).fetchone()
        return _grant_from_row(row) if row else None

    return await store.run(_run)


async def cas_to_in_flight(store: Store, grant_id: str) -> bool:
    """True if this call won the race to dispatch `grant_id` - i.e. the
    grant was ACTIVE and is now IN_FLIGHT. False means someone else already
    claimed it, or it's expired/revoked/consumed; the caller must not dispatch."""

    def _run(conn: sqlite3.Connection) -> bool:
        cur = conn.execute(
            "UPDATE grants SET status = ? WHERE grant_id = ? AND status = ?",
            (GrantStatus.IN_FLIGHT.value, grant_id, GrantStatus.ACTIVE.value),
        )
        conn.commit()
        return cur.rowcount == 1

    return await store.run(_run)


async def record_dispatch_outcome(store: Store, grant_id: str, *, succeeded: bool) -> None:
    """A succeeded dispatch consumes the grant (use_count -> 1, status ->
    CONSUMED, since max_uses is always 1 in v1). A failed dispatch (the
    upstream call itself errored) returns the grant to ACTIVE so it isn't
    burned on a transient upstream failure - the same call can be retried
    with the same grant until it expires."""

    def _run(conn: sqlite3.Connection) -> None:
        if succeeded:
            conn.execute(
                "UPDATE grants SET status = ?, use_count = use_count + 1 WHERE grant_id = ?",
                (GrantStatus.CONSUMED.value, grant_id),
            )
        else:
            conn.execute("UPDATE grants SET status = ? WHERE grant_id = ?", (GrantStatus.ACTIVE.value, grant_id))
        conn.commit()

    await store.run(_run)


async def expire_due_grants(store: Store, now: datetime) -> int:
    """Skips IN_FLIGHT by construction (only ACTIVE -> EXPIRED), so a grant
    expiring mid-dispatch never gets yanked out from under an in-progress call."""

    def _run(conn: sqlite3.Connection) -> int:
        cur = conn.execute(
            "UPDATE grants SET status = ? WHERE status = ? AND expires_at < ?",
            (GrantStatus.EXPIRED.value, GrantStatus.ACTIVE.value, dt_to_str(now)),
        )
        conn.commit()
        return cur.rowcount

    return await store.run(_run)


async def revoke_grant(store: Store, grant_id: str) -> bool:
    def _run(conn: sqlite3.Connection) -> bool:
        cur = conn.execute(
            "UPDATE grants SET status = ? WHERE grant_id = ? AND status IN (?, ?)",
            (GrantStatus.REVOKED.value, grant_id, GrantStatus.ACTIVE.value, GrantStatus.IN_FLIGHT.value),
        )
        conn.commit()
        return cur.rowcount == 1

    return await store.run(_run)


async def revoke_session_grants(store: Store, session_id: str) -> int:
    def _run(conn: sqlite3.Connection) -> int:
        cur = conn.execute(
            "UPDATE grants SET status = ? WHERE session_id = ? AND status IN (?, ?)",
            (GrantStatus.REVOKED.value, session_id, GrantStatus.ACTIVE.value, GrantStatus.IN_FLIGHT.value),
        )
        conn.commit()
        return cur.rowcount

    return await store.run(_run)


async def list_grants_for_session(store: Store, session_id: str) -> list[CredentialGrant]:
    def _run(conn: sqlite3.Connection) -> list[CredentialGrant]:
        rows = conn.execute("SELECT * FROM grants WHERE session_id = ? ORDER BY issued_at", (session_id,)).fetchall()
        return [_grant_from_row(r) for r in rows]

    return await store.run(_run)


async def list_grants_for_task(store: Store, task_id: str) -> list[CredentialGrant]:
    def _run(conn: sqlite3.Connection) -> list[CredentialGrant]:
        rows = conn.execute("SELECT * FROM grants WHERE task_id = ? ORDER BY issued_at", (task_id,)).fetchall()
        return [_grant_from_row(r) for r in rows]

    return await store.run(_run)
