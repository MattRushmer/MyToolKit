"""Background maintenance: expire due grants, close idle sessions, and close
a task once every session in it has closed.

Session closing is idle-timeout-based rather than tied to an exact "the
client disconnected" signal - see proxy/server.py's module docstring for
why: this SDK version exposes no stable per-connection object a middleware
can hook a close callback onto. An idle-timeout sweep is a reasonable,
honestly-documented substitute (see README's Known limitations), and it's
also what makes a crashed/killed client's session eventually stop counting
toward CONCURRENT_SESSION_ANOMALY/blast-radius on the next process's
`reconcile_stale_sessions` in the meantime.
"""
from __future__ import annotations

import logging

import anyio

from agentwarden.models import EventType, Severity
from agentwarden.store import grants as grants_store
from agentwarden.store import sessions as sessions_store
from agentwarden.store.audit import EventBuilder, append_event
from agentwarden.store.connection import Store

_LOGGER = logging.getLogger(__name__)


async def sweep_once(store: Store, clock, new_id, idle_timeout_seconds: float) -> dict[str, int]:
    now = clock.now()
    expired_grants = await grants_store.expire_due_grants(store, now)

    closed_sessions = 0
    closed_tasks = 0
    builder = EventBuilder(new_id, clock)
    for session in await sessions_store.list_active_sessions(store):
        idle_for = (now - session.last_activity_at).total_seconds()
        if idle_for < idle_timeout_seconds:
            continue

        await sessions_store.close_session(store, session.session_id, now.isoformat(), f"idle for {idle_for:.0f}s")
        await append_event(store, builder.build(
            session_id=session.session_id, task_id=session.task_id, identity_id=session.identity_id,
            event_type=EventType.SESSION_CLOSED, severity=Severity.INFO, detail={"reason": "idle_timeout", "idle_seconds": idle_for},
        ))
        await grants_store.revoke_session_grants(store, session.session_id)
        closed_sessions += 1

        remaining = await sessions_store.count_active_sessions_for_task(store, session.task_id)
        if remaining == 0:
            task = await sessions_store.get_task(store, session.task_id)
            if task is not None and task.status.value == "open":
                await sessions_store.close_task(store, task.task_id, now.isoformat())
                await append_event(store, builder.build(
                    session_id=session.session_id, task_id=task.task_id, identity_id=session.identity_id,
                    event_type=EventType.TASK_CLOSED, severity=Severity.INFO, detail={"reason": "all sessions closed"},
                ))
                closed_tasks += 1

    return {"expired_grants": expired_grants, "closed_sessions": closed_sessions, "closed_tasks": closed_tasks}


async def run_sweeper_loop(store: Store, clock, new_id, *, interval_seconds: float = 15.0, idle_timeout_seconds: float = 300.0) -> None:
    """Runs forever - the caller (cli/main.py's `serve` command) starts this
    as a background task alongside the proxy and cancels it on shutdown."""
    while True:
        try:
            result = await sweep_once(store, clock, new_id, idle_timeout_seconds)
            if any(result.values()):
                _LOGGER.info("sweep: %s", result)
        except Exception:  # noqa: BLE001 - one bad sweep must not kill the loop or take the whole proxy down with it
            _LOGGER.exception("sweeper iteration failed")
        await anyio.sleep(interval_seconds)
