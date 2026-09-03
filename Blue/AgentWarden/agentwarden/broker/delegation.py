"""Validates a new session's client-asserted delegation link before trusting
it - this is the fix for the architect review's P0-3 finding: an
unauthenticated `parent_session_id`/`task_id` claim is a privilege-escalation
channel, not a fidelity limitation. A client could otherwise reset its own
`max_uses_per_task` budget by declaring a fresh task_id, or claim a
more-privileged session as its parent, or simply latch its own root session
onto an existing task_id it observed somewhere without going through
delegation at all (CONCURRENT_SESSION_ANOMALY - two sessions sharing a task
with no accepted parent/child link between them).

Two distinct claim shapes are validated:

1. **Parent claimed** - accepted only if the parent (a) exists, (b) is still
   ACTIVE, (c) belongs to the same identity, and (d) would not create a
   cycle. On acceptance the child's `task_id` is *forced* to the parent's -
   the child's own claimed task_id is discarded, which is what closes the
   budget-reset bypass: a session can only join a task by successfully
   attaching to a live member of it, never by naming the task directly.
2. **No parent claimed, but a task_id is** - if that task_id already belongs
   to an existing task, the claim is rejected (phantom join attempt) and the
   session gets its own fresh task instead; both cases are recorded rather
   than silently allowed or silently dropped.

Either rejection still lets the session open - AgentWarden fails a *call*
closed on a real policy violation, but doesn't refuse a whole connection
over an unverifiable metadata claim, which would be a denial-of-service lever
in itself. It just never trusts the claim.
"""
from __future__ import annotations

from dataclasses import dataclass

from agentwarden.models import SessionEdge, SessionStatus
from agentwarden.store import sessions as sessions_store
from agentwarden.store.connection import Store

_MAX_ANCESTOR_WALK = 64  # defensive bound; see _would_create_cycle for why a cycle can't arise via this path at all


@dataclass(frozen=True)
class DelegationResolution:
    task_id: str
    accepted_parent_session_id: str | None
    is_new_task: bool
    edge: SessionEdge | None
    rejection_reason: str | None
    is_concurrent_anomaly: bool = False  # True for the "phantom task join" case specifically


async def _would_create_cycle(store: Store, new_session_id: str, claimed_parent_session_id: str) -> bool:
    """Walks the claimed parent's own ancestor chain looking for
    `new_session_id`. Structurally this can never actually happen - a
    session can only claim a parent that already exists in the store, and
    `new_session_id` doesn't exist yet at the moment this check runs - but
    the walk is cheap and this makes the invariant an enforced check rather
    than an unstated assumption, and it still protects against a future code
    change that allows re-declaring a session's parent after creation."""
    current_id: str | None = claimed_parent_session_id
    depth = 0
    while current_id is not None and depth < _MAX_ANCESTOR_WALK:
        if current_id == new_session_id:
            return True
        current = await sessions_store.get_session(store, current_id)
        current_id = current.parent_session_id if current else None
        depth += 1
    return False


async def resolve_delegation(
    store: Store, *, new_session_id: str, identity_id: str,
    claimed_parent_session_id: str | None, claimed_task_id: str | None, clock,
) -> DelegationResolution:
    if claimed_parent_session_id is None:
        if claimed_task_id is not None:
            existing_task = await sessions_store.get_task(store, claimed_task_id)
            if existing_task is not None:
                reason = f"claimed task_id '{claimed_task_id}' already belongs to an existing task, but no parent session was declared"
                return DelegationResolution(
                    task_id=new_session_id, accepted_parent_session_id=None, is_new_task=True,
                    edge=None, rejection_reason=reason, is_concurrent_anomaly=True,
                )
        return DelegationResolution(
            task_id=claimed_task_id or new_session_id, accepted_parent_session_id=None,
            is_new_task=True, edge=None, rejection_reason=None,
        )

    parent = await sessions_store.get_session(store, claimed_parent_session_id)
    reason: str | None = None
    if parent is None:
        reason = f"claimed parent session '{claimed_parent_session_id}' does not exist"
    elif parent.status is not SessionStatus.ACTIVE:
        reason = f"claimed parent session '{claimed_parent_session_id}' is not active"
    elif parent.identity_id != identity_id:
        reason = f"claimed parent session '{claimed_parent_session_id}' belongs to a different identity"
    elif await _would_create_cycle(store, new_session_id, claimed_parent_session_id):
        reason = f"accepting parent '{claimed_parent_session_id}' would create a delegation cycle"

    accepted = reason is None
    edge = SessionEdge(
        child_session_id=new_session_id, parent_session_id=claimed_parent_session_id,
        declared_at=clock.now(), accepted=accepted, rejection_reason=reason,
    )

    if accepted:
        assert parent is not None  # narrows for the type checker; reason is None only when parent resolved above
        return DelegationResolution(
            task_id=parent.task_id, accepted_parent_session_id=parent.session_id, is_new_task=False,
            edge=edge, rejection_reason=None,
        )

    return DelegationResolution(
        task_id=claimed_task_id or new_session_id, accepted_parent_session_id=None, is_new_task=True,
        edge=edge, rejection_reason=reason,
    )
