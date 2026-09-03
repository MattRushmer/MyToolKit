from __future__ import annotations

from datetime import datetime, timezone

from agentwarden.broker.lifecycle import check_and_mint
from agentwarden.broker.redaction import digest_arguments
from agentwarden.ids import new_id
from agentwarden.models import CallOutcome, Decision, PolicyRule
from agentwarden.store import calls as calls_store
from agentwarden.store import grants as grants_store


class _FixedClock:
    def now(self):
        return datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_digest_is_stable_and_does_not_leak_raw_value():
    secret_value = {"content": "super secret file contents"}
    digest = digest_arguments(secret_value)
    assert "super secret" not in digest
    assert digest == digest_arguments(secret_value)  # stable
    assert digest != digest_arguments({"content": "different"})


async def test_check_and_mint_denies_when_task_rate_limit_reached(store):
    rule = PolicyRule(rule_id="r1", identity_id="id-a", tool_name="create_pr", upstream_server_id="github-mcp", source="explicit", ttl_seconds=60, max_uses_per_task=1)
    decision = Decision(outcome=CallOutcome.ALLOWED, matched_rule=rule, reason="allowed")

    first = await check_and_mint(store, decision=decision, session_id="s1", task_id="t1", tool_name="create_pr", upstream_server_id="github-mcp", clock=_FixedClock(), new_id=new_id)
    assert first.decision.outcome is CallOutcome.ALLOWED
    assert first.grant is not None

    second = await check_and_mint(store, decision=decision, session_id="s1", task_id="t1", tool_name="create_pr", upstream_server_id="github-mcp", clock=_FixedClock(), new_id=new_id)
    assert second.decision.outcome is CallOutcome.RATE_EXCEEDED
    assert second.grant is None


async def test_check_and_mint_denies_via_session_count_even_with_high_task_limit(store):
    """Session-scoped count closes the P0-3 gap: even if task-level counting
    were somehow bypassed, the session's own allowed-call history still caps it."""
    rule = PolicyRule(rule_id="r1", identity_id="id-a", tool_name="create_pr", upstream_server_id="github-mcp", source="explicit", ttl_seconds=60, max_uses_per_task=1)
    decision = Decision(outcome=CallOutcome.ALLOWED, matched_rule=rule, reason="allowed")

    from agentwarden.models import CallOutcome as CO
    from agentwarden.models import ToolCallRecord
    await calls_store.record_call(store, ToolCallRecord(
        call_id="c1", session_id="s1", task_id="t1", upstream_server_id="github-mcp", tool_name="create_pr",
        arguments_digest="x", redacted_arguments={}, outcome=CO.ALLOWED, matched_rule_id="r1", grant_id="g1",
        started_at=_FixedClock().now(),
    ))

    outcome = await check_and_mint(store, decision=decision, session_id="s1", task_id="t1", tool_name="create_pr", upstream_server_id="github-mcp", clock=_FixedClock(), new_id=new_id)
    assert outcome.decision.outcome is CallOutcome.RATE_EXCEEDED


async def test_grant_cas_only_succeeds_once(store):
    grant = await grants_store.mint(store, grant_id="g1", session_id="s1", task_id="t1", tool_name="write_file", upstream_server_id="fs-mcp", rule_id="r1", scope={}, issued_at=_FixedClock().now(), ttl_seconds=60, max_uses_per_task=None)
    first = await grants_store.cas_to_in_flight(store, grant.grant_id)
    second = await grants_store.cas_to_in_flight(store, grant.grant_id)
    assert first is True
    assert second is False
