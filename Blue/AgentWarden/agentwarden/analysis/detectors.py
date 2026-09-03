"""Per-call inline detectors: state in, signal out. Called from
proxy/mediator.py at the point in the pipeline each one is meaningful -
kept here (not inlined into the mediator) so each is independently
unit-testable against a store without spinning up the proxy at all.

CONCURRENT_SESSION_ANOMALY and the (structurally-almost-unreachable)
EXPIRED_GRANT_REUSE aren't here: the former is a session-*open*-time check
already produced by broker/delegation.py's DelegationResolution.
is_concurrent_anomaly, and the latter only has a real trigger condition at
the grant-dispatch CAS in proxy/mediator.py (a grant's credential never
leaves the broker for an agent to literally "replay", so its only genuine
occurrence is a narrow expiry-vs-dispatch race - see that module).
"""
from __future__ import annotations

from agentwarden.models import TaskStatus
from agentwarden.store import calls as calls_store
from agentwarden.store import sessions as sessions_store
from agentwarden.store.connection import Store


async def would_exceed_blast_radius(store: Store, task_id: str, ceiling: int, candidate_upstream_server_id: str) -> tuple[bool, set[str]]:
    """Checked *before* policy evaluation for every call attempt (allowed or
    not): touching a new distinct upstream is itself the signal, independent
    of whether that specific call would otherwise have been allowed - see
    analysis/blast_radius.py's docstring on why the reachable set includes
    denied attempts. Returns (would_exceed, current_distinct_upstreams) so
    the caller can build a detailed AuditEvent.detail without a second query."""
    calls = await calls_store.list_calls_for_task(store, task_id)
    current_upstreams = {c.upstream_server_id for c in calls}
    projected = current_upstreams | {candidate_upstream_server_id}
    return len(projected) > ceiling, current_upstreams


async def is_task_closed(store: Store, task_id: str) -> bool:
    task = await sessions_store.get_task(store, task_id)
    return task is not None and task.status is TaskStatus.CLOSED
