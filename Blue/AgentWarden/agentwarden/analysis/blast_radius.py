"""Blast-radius computation.

Every session that joins a task (via an *accepted* delegation - see
broker/delegation.py) shares that task's `task_id`, so a task's whole
delegation subtree's calls are already flat-queryable by `task_id` alone.
No session-graph traversal is needed for the reachable-set itself; the graph
(session parent/child links) is only walked here to build a human-readable
path for the report, and separately by broker/delegation.py to validate a
claim and by analysis/detectors.py to check CONCURRENT_SESSION_ANOMALY.

The reachable set is *every attempted* `(upstream_server_id, tool_name)`
pair for the task, not just the ones that were actually granted - a denied
attempt is still exposure evidence (an agent that tried to reach payments-mcp
and was blocked still tells you something about what that task's blast
radius would have been under a looser policy), and this is also what makes
BLAST_RADIUS_EXCEEDED able to fire on a denied call, not only on successful
grants - see the architect-review fix note in models.py.
"""
from __future__ import annotations

from agentwarden.models import AgentSession, BlastRadiusReport
from agentwarden.store import calls as calls_store
from agentwarden.store import sessions as sessions_store
from agentwarden.store.connection import Store


async def _session_path_to_root(store: Store, session_id: str, cache: dict[str, AgentSession | None]) -> list[str]:
    path: list[str] = [session_id]
    current_id: str | None = session_id
    while True:
        if current_id not in cache:
            cache[current_id] = await sessions_store.get_session(store, current_id) if current_id else None
        current = cache.get(current_id)
        if current is None or current.parent_session_id is None:
            break
        current_id = current.parent_session_id
        path.append(current_id)
    return list(reversed(path))


async def compute_blast_radius(store: Store, task_id: str, ceiling: int, clock) -> BlastRadiusReport:
    task = await sessions_store.get_task(store, task_id)
    root_session_id = task.root_session_id if task is not None else task_id

    calls = await calls_store.list_calls_for_task(store, task_id)

    reachable: set[tuple[str, str]] = set()
    path_by_pair: dict[tuple[str, str], list[str]] = {}
    session_cache: dict[str, AgentSession | None] = {}
    seen_sessions: set[str] = set()

    for call in calls:
        pair = (call.upstream_server_id, call.tool_name)
        reachable.add(pair)
        seen_sessions.add(call.session_id)
        if pair not in path_by_pair:
            path_by_pair[pair] = await _session_path_to_root(store, call.session_id, session_cache)

    return BlastRadiusReport(
        root_session_id=root_session_id,
        task_id=task_id,
        computed_at=clock.now(),
        ceiling=ceiling,
        reachable=reachable,
        path_by_pair=path_by_pair,
        sessions_visited=len(seen_sessions),
    )
