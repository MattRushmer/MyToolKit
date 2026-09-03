"""The `tools/call` interception pipeline: blast-radius check -> policy
evaluation -> rate-check+mint -> dispatch -> audit. Kept orchestration-only
(each step's real logic lives in policy/engine.py, broker/lifecycle.py,
analysis/detectors.py) so this file stays readable as *the* place that
answers "in what order does AgentWarden decide whether to let a call
through" without also being where any of those decisions are computed.

One important honesty note for the README: AgentWarden does not mint a
literally distinct upstream secret per call. `proxy/upstream.py`'s
UpstreamPool holds one already-authenticated connection per upstream,
opened once at startup with the real credential AgentWarden owns. A
CredentialGrant models an *authorization decision* - this call, this scope,
this TTL - layered on top of that always-live connection, not a fresh
secret minted and handed out per use. That's a legitimate and common
brokering pattern (much closer to a scoped session token than a fresh API
key), but it's a materially different claim than "a new secret every call",
and the README should never imply the stronger one.

Pipeline order and why:
1. POST_TASK_ACTIVITY - cheapest check, and a closed task should have zero
   further blast radius regardless of anything else.
2. BLAST_RADIUS_EXCEEDED - checked before policy, because touching a new
   distinct upstream is itself the signal, independent of whether policy
   would separately have allowed or denied this specific call (see
   analysis/detectors.py).
3. Policy evaluation (POLICY_DENIED / SCOPE_VIOLATION / ALLOWED).
4. Rate-check + mint (RATE_EXCEEDED can still turn an ALLOWED decision into
   a denial at this stage - see broker/lifecycle.py).
5. Dispatch: CAS the grant ACTIVE->IN_FLIGHT immediately before the upstream
   call (closes the reuse race), call upstream, record the outcome, release
   or consume the grant.

`enforcement_mode` ("enforce" | "monitor", per-identity) only affects step 3
onward: a "monitor" identity's denied/rate-limited/blast-radius-exceeded
call is still dispatched to upstream for real (nothing is actually blocked),
but the call/audit record still carries the outcome that *would* have
applied under enforce mode, with `detail["monitor_mode"] = true` - this is
what makes a monitor-mode rollout report "here's what enforce mode would
have blocked" instead of silently doing nothing.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

import anyio

from agentwarden.analysis import detectors
from agentwarden.broker import lifecycle
from agentwarden.broker.redaction import digest_arguments
from agentwarden.clock import Clock
from agentwarden.models import (
    AgentSession,
    CallOutcome,
    CredentialGrant,
    EventType,
    PolicyRule,
    Severity,
    ToolCallRecord,
)
from agentwarden.policy import engine as policy_engine
from agentwarden.proxy import errors
from agentwarden.proxy.upstream import UpstreamPool
from agentwarden.store import calls as calls_store
from agentwarden.store import grants as grants_store
from agentwarden.store import sessions as sessions_store
from agentwarden.store.audit import EventBuilder, append_event
from agentwarden.store.connection import Store

_OUTCOME_EVENT_TYPE = {
    CallOutcome.POLICY_DENIED: EventType.POLICY_DENIED,
    CallOutcome.SCOPE_VIOLATION: EventType.SCOPE_VIOLATION,
    CallOutcome.RATE_EXCEEDED: EventType.RATE_EXCEEDED,
    CallOutcome.BLAST_RADIUS_EXCEEDED: EventType.BLAST_RADIUS_EXCEEDED,
    CallOutcome.POST_TASK_ACTIVITY: EventType.POST_TASK_ACTIVITY,
}
_OUTCOME_SEVERITY = {
    CallOutcome.POLICY_DENIED: Severity.MEDIUM,
    CallOutcome.SCOPE_VIOLATION: Severity.HIGH,
    CallOutcome.RATE_EXCEEDED: Severity.HIGH,
    CallOutcome.BLAST_RADIUS_EXCEEDED: Severity.CRITICAL,
    CallOutcome.POST_TASK_ACTIVITY: Severity.CRITICAL,
}


@dataclass
class MediatorDeps:
    store: Store
    upstream_pool: UpstreamPool
    tool_registry: dict[str, tuple[str, Any]]  # tool_name -> (upstream_id, Tool)
    policy_rules_by_identity: dict[str, list[PolicyRule]]
    enforcement_modes: dict[str, str]
    blast_radius_ceiling: int
    clock: Clock
    new_id: Callable[[str], str]


async def _finalize(
    deps: MediatorDeps, *, call_id: str, session: AgentSession, task_id: str, upstream_server_id: str,
    tool_name: str, arguments: dict[str, Any], redacted_arguments: dict[str, Any], outcome: CallOutcome,
    matched_rule_id: str | None, grant_id: str | None, started_at, event_type: EventType, severity: Severity,
    detail: dict[str, Any],
) -> None:
    """Records the ToolCallRecord + AuditEvent for one attempt. Shielded from
    cancellation: if the inbound request is cancelled after this point, the
    record of what actually happened must still land - losing it would be
    the worst failure mode for an audit tool."""
    with anyio.CancelScope(shield=True):
        completed_at = deps.clock.now()
        record = ToolCallRecord(
            call_id=call_id, session_id=session.session_id, task_id=task_id, upstream_server_id=upstream_server_id,
            tool_name=tool_name, arguments_digest=digest_arguments(arguments), redacted_arguments=redacted_arguments,
            outcome=outcome, matched_rule_id=matched_rule_id, grant_id=grant_id, started_at=started_at,
            completed_at=completed_at, latency_ms=(completed_at - started_at).total_seconds() * 1000,
        )
        await calls_store.record_call(deps.store, record)

        builder = EventBuilder(deps.new_id, deps.clock)
        event = builder.build(
            session_id=session.session_id, task_id=task_id, identity_id=session.identity_id, event_type=event_type,
            severity=severity, call_id=call_id, grant_id=grant_id, tool_name=tool_name,
            upstream_server_id=upstream_server_id or None, detail=detail,
        )
        await append_event(deps.store, event)


async def _deny(
    deps: MediatorDeps, *, call_id: str, session: AgentSession, task_id: str, upstream_server_id: str,
    tool_name: str, arguments: dict[str, Any], redacted_arguments: dict[str, Any], started_at, outcome: CallOutcome,
    matched_rule_id: str | None, reason: str, extra_detail: dict[str, Any], enforcement_mode: str,
) -> Any:
    event_type = _OUTCOME_EVENT_TYPE[outcome]
    severity = _OUTCOME_SEVERITY[outcome]
    monitor_mode = enforcement_mode == "monitor"
    detail = {"reason": reason, "monitor_mode": monitor_mode, **extra_detail}

    if monitor_mode and upstream_server_id:
        try:
            result = await deps.upstream_pool.call_tool(upstream_server_id, tool_name, arguments)
        except Exception as exc:  # noqa: BLE001 - upstream failure under monitor-mode passthrough must not crash the mediator
            result = errors.deny_result(f"upstream call failed under monitor-mode passthrough: {exc}")
        await _finalize(
            deps, call_id=call_id, session=session, task_id=task_id, upstream_server_id=upstream_server_id,
            tool_name=tool_name, arguments=arguments, redacted_arguments=redacted_arguments, outcome=outcome,
            matched_rule_id=matched_rule_id, grant_id=None, started_at=started_at, event_type=event_type,
            severity=severity, detail=detail,
        )
        return result

    await _finalize(
        deps, call_id=call_id, session=session, task_id=task_id, upstream_server_id=upstream_server_id,
        tool_name=tool_name, arguments=arguments, redacted_arguments=redacted_arguments, outcome=outcome,
        matched_rule_id=matched_rule_id, grant_id=None, started_at=started_at, event_type=event_type,
        severity=severity, detail=detail,
    )
    return errors.deny_result(reason)


async def _dispatch_allowed(
    deps: MediatorDeps, *, call_id: str, session: AgentSession, task_id: str, upstream_server_id: str,
    tool_name: str, arguments: dict[str, Any], redacted_arguments: dict[str, Any], matched_rule_id: str,
    grant: CredentialGrant, started_at,
) -> Any:
    won_cas = await grants_store.cas_to_in_flight(deps.store, grant.grant_id)
    if not won_cas:
        # Structurally rare - see analysis/detectors.py's module docstring: this is the
        # one genuine trigger for EXPIRED_GRANT_REUSE, a narrow race between mint()
        # (ACTIVE) and this CAS where the sweeper (or a revoke) got there first.
        await _finalize(
            deps, call_id=call_id, session=session, task_id=task_id, upstream_server_id=upstream_server_id,
            tool_name=tool_name, arguments=arguments, redacted_arguments=redacted_arguments,
            outcome=CallOutcome.ERROR, matched_rule_id=matched_rule_id, grant_id=grant.grant_id, started_at=started_at,
            event_type=EventType.EXPIRED_GRANT_REUSE, severity=Severity.CRITICAL,
            detail={"reason": "grant was no longer ACTIVE at dispatch time"},
        )
        return errors.deny_result("credential grant expired or was revoked between issuance and dispatch")

    try:
        result = await deps.upstream_pool.call_tool(upstream_server_id, tool_name, arguments)
        succeeded = True
    except Exception as exc:  # noqa: BLE001 - an upstream tool failure must return a normal error, not crash the mediator
        result = errors.deny_result(f"upstream call failed: {exc}")
        succeeded = False

    with anyio.CancelScope(shield=True):
        await grants_store.record_dispatch_outcome(deps.store, grant.grant_id, succeeded=succeeded)

    await _finalize(
        deps, call_id=call_id, session=session, task_id=task_id, upstream_server_id=upstream_server_id,
        tool_name=tool_name, arguments=arguments, redacted_arguments=redacted_arguments,
        outcome=CallOutcome.ALLOWED if succeeded else CallOutcome.ERROR, matched_rule_id=matched_rule_id,
        grant_id=grant.grant_id, started_at=started_at,
        event_type=EventType.TOOL_CALL_ALLOWED if succeeded else EventType.GRANT_ISSUED, severity=Severity.INFO,
        detail={"grant_id": grant.grant_id},
    )
    return result


async def mediate_tool_call(deps: MediatorDeps, *, session: AgentSession, task_id: str, tool_name: str, arguments: dict[str, Any]) -> Any:
    started_at = deps.clock.now()
    call_id = deps.new_id("call")
    enforcement_mode = deps.enforcement_modes.get(session.identity_id, "enforce")
    await sessions_store.touch_session(deps.store, session.session_id, deps.clock.now().isoformat())

    lookup = deps.tool_registry.get(tool_name)
    if lookup is None:
        return await _deny(
            deps, call_id=call_id, session=session, task_id=task_id, upstream_server_id="", tool_name=tool_name,
            arguments=arguments, redacted_arguments={}, started_at=started_at, outcome=CallOutcome.POLICY_DENIED,
            matched_rule_id=None, reason=f"unknown tool '{tool_name}'", extra_detail={}, enforcement_mode=enforcement_mode,
        )
    upstream_server_id, _tool = lookup

    if await detectors.is_task_closed(deps.store, task_id):
        return await _deny(
            deps, call_id=call_id, session=session, task_id=task_id, upstream_server_id=upstream_server_id,
            tool_name=tool_name, arguments=arguments, redacted_arguments={}, started_at=started_at,
            outcome=CallOutcome.POST_TASK_ACTIVITY, matched_rule_id=None,
            reason=f"task '{task_id}' is already closed", extra_detail={}, enforcement_mode=enforcement_mode,
        )

    would_exceed, current_upstreams = await detectors.would_exceed_blast_radius(deps.store, task_id, deps.blast_radius_ceiling, upstream_server_id)
    if would_exceed:
        return await _deny(
            deps, call_id=call_id, session=session, task_id=task_id, upstream_server_id=upstream_server_id,
            tool_name=tool_name, arguments=arguments, redacted_arguments={}, started_at=started_at,
            outcome=CallOutcome.BLAST_RADIUS_EXCEEDED, matched_rule_id=None,
            reason=f"task '{task_id}' would reach {len(current_upstreams | {upstream_server_id})} distinct upstream(s), ceiling is {deps.blast_radius_ceiling}",
            extra_detail={"current_upstreams": sorted(current_upstreams)}, enforcement_mode=enforcement_mode,
        )

    rules = deps.policy_rules_by_identity.get(session.identity_id, [])
    decision = policy_engine.evaluate(rules, tool_name, upstream_server_id, arguments)
    matched_rule_id = decision.matched_rule.rule_id if decision.matched_rule else None
    grant: CredentialGrant | None = None

    if decision.outcome is CallOutcome.ALLOWED:
        mint_outcome = await lifecycle.check_and_mint(
            deps.store, decision=decision, session_id=session.session_id, task_id=task_id, tool_name=tool_name,
            upstream_server_id=upstream_server_id, clock=deps.clock, new_id=deps.new_id,
        )
        decision = mint_outcome.decision
        grant = mint_outcome.grant
        matched_rule_id = decision.matched_rule.rule_id if decision.matched_rule else matched_rule_id

    if decision.outcome is not CallOutcome.ALLOWED:
        return await _deny(
            deps, call_id=call_id, session=session, task_id=task_id, upstream_server_id=upstream_server_id,
            tool_name=tool_name, arguments=arguments, redacted_arguments=decision.redacted_arguments, started_at=started_at,
            outcome=decision.outcome, matched_rule_id=matched_rule_id, reason=decision.reason, extra_detail={},
            enforcement_mode=enforcement_mode,
        )

    assert grant is not None  # ALLOWED only reaches here once check_and_mint has successfully minted
    return await _dispatch_allowed(
        deps, call_id=call_id, session=session, task_id=task_id, upstream_server_id=upstream_server_id,
        tool_name=tool_name, arguments=arguments, redacted_arguments=decision.redacted_arguments,
        matched_rule_id=matched_rule_id or grant.rule_id, grant=grant, started_at=started_at,
    )
