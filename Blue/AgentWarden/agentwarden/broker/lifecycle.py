"""Ties policy/engine.py's pure decision to the store's atomic rate-check +
mint - the layer policy/engine.py's own docstring defers rate limiting to.

Two independent rate checks run before a grant is minted, both scoped to
`max_uses_per_task`: one against this *session's* own allowed-call history,
one against the whole *task's* minted-grant history (store/grants.py's
mint()). Both are required - the session check exists specifically so a
forged `task_id` (rejected by broker/delegation.py, but still theoretically
raced against a not-yet-rejected session) can't reset a budget by having the
same session claim a fresh task; the task check is what actually stops a
sub-agent spawned via an *accepted* delegation from consuming its parent's
task-wide budget past the limit.
"""
from __future__ import annotations

from dataclasses import dataclass

from agentwarden.models import CallOutcome, CredentialGrant, Decision, PolicyRule
from agentwarden.store import calls as calls_store
from agentwarden.store import grants as grants_store
from agentwarden.store.connection import Store


@dataclass(frozen=True)
class MintOutcome:
    decision: Decision
    grant: CredentialGrant | None


async def check_and_mint(
    store: Store, *, decision: Decision, session_id: str, task_id: str, tool_name: str, upstream_server_id: str,
    clock, new_id,
) -> MintOutcome:
    if decision.outcome is not CallOutcome.ALLOWED:
        return MintOutcome(decision=decision, grant=None)

    rule: PolicyRule | None = decision.matched_rule
    assert rule is not None  # ALLOWED is only ever returned with a matched (non-deny) rule - see policy/engine.py

    if rule.max_uses_per_task is not None:
        session_count = await calls_store.count_calls_for_session_tool(store, session_id, tool_name, upstream_server_id)
        if session_count >= rule.max_uses_per_task:
            rate_decision = Decision(
                outcome=CallOutcome.RATE_EXCEEDED, matched_rule=rule,
                reason=f"session '{session_id}' already made {session_count} allowed call(s) to {tool_name}@{upstream_server_id} (limit {rule.max_uses_per_task})",
                redacted_arguments=decision.redacted_arguments,
            )
            return MintOutcome(decision=rate_decision, grant=None)

    try:
        grant = await grants_store.mint(
            store, grant_id=new_id("grant"), session_id=session_id, task_id=task_id, tool_name=tool_name,
            upstream_server_id=upstream_server_id, rule_id=rule.rule_id, scope=decision.redacted_arguments,
            issued_at=clock.now(), ttl_seconds=rule.ttl_seconds, max_uses_per_task=rule.max_uses_per_task,
        )
    except grants_store.RateLimitExceeded as exc:
        rate_decision = Decision(outcome=CallOutcome.RATE_EXCEEDED, matched_rule=rule, reason=str(exc), redacted_arguments=decision.redacted_arguments)
        return MintOutcome(decision=rate_decision, grant=None)

    return MintOutcome(decision=decision, grant=grant)
