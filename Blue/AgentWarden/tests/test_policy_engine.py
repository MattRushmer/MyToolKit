from __future__ import annotations

from agentwarden.models import ArgumentConstraint, CallOutcome, PolicyRule
from agentwarden.policy.engine import evaluate

CATCH_ALL_DENY = PolicyRule(rule_id="catch-all", identity_id="x", tool_name="*", upstream_server_id="*", source="default-catch-all", deny=True)


def _rule(**kwargs) -> PolicyRule:
    base = dict(rule_id="r1", identity_id="x", tool_name="write_file", upstream_server_id="fs-mcp", source="explicit", ttl_seconds=60)
    base.update(kwargs)
    return PolicyRule(**base)


def test_allows_matching_rule_with_no_constraints():
    decision = evaluate([_rule(), CATCH_ALL_DENY], "write_file", "fs-mcp", {"path": "/anywhere"})
    assert decision.outcome is CallOutcome.ALLOWED


def test_denies_unmatched_call_via_catch_all():
    decision = evaluate([_rule(), CATCH_ALL_DENY], "delete_file", "fs-mcp", {})
    assert decision.outcome is CallOutcome.POLICY_DENIED
    assert decision.matched_rule.source == "default-catch-all"


def test_explicit_deny_rule_is_policy_denied_not_scope_violation():
    deny_rule = _rule(tool_name="merge_pr", deny=True)
    decision = evaluate([deny_rule, CATCH_ALL_DENY], "merge_pr", "fs-mcp", {"anything": 1})
    assert decision.outcome is CallOutcome.POLICY_DENIED
    assert decision.matched_rule.rule_id == "r1"


def test_prefix_constraint_pass_and_fail():
    rule = _rule(argument_constraints={"path": ArgumentConstraint(prefix="/workspace/")})
    ok = evaluate([rule, CATCH_ALL_DENY], "write_file", "fs-mcp", {"path": "/workspace/a.txt"})
    bad = evaluate([rule, CATCH_ALL_DENY], "write_file", "fs-mcp", {"path": "/etc/passwd"})
    assert ok.outcome is CallOutcome.ALLOWED
    assert bad.outcome is CallOutcome.SCOPE_VIOLATION


def test_path_within_blocks_traversal_past_prefix():
    rule = _rule(argument_constraints={"path": ArgumentConstraint(path_within="/workspace")})
    escaping = evaluate([rule, CATCH_ALL_DENY], "write_file", "fs-mcp", {"path": "/workspace/../../etc/passwd"})
    assert escaping.outcome is CallOutcome.SCOPE_VIOLATION


def test_missing_constrained_field_fails_closed():
    rule = _rule(argument_constraints={"path": ArgumentConstraint(prefix="/workspace/")})
    decision = evaluate([rule, CATCH_ALL_DENY], "write_file", "fs-mcp", {})
    assert decision.outcome is CallOutcome.SCOPE_VIOLATION


def test_in_constraint():
    rule = _rule(tool_name="create_pr", argument_constraints={"repo": ArgumentConstraint(in_=("org/allowed",))})
    ok = evaluate([rule, CATCH_ALL_DENY], "create_pr", "fs-mcp", {"repo": "org/allowed"})
    bad = evaluate([rule, CATCH_ALL_DENY], "create_pr", "fs-mcp", {"repo": "org/other"})
    assert ok.outcome is CallOutcome.ALLOWED
    assert bad.outcome is CallOutcome.SCOPE_VIOLATION


def test_lt_constraint_rejects_non_numeric():
    rule = _rule(tool_name="pay", argument_constraints={"amount": ArgumentConstraint(lt=100)})
    decision = evaluate([rule, CATCH_ALL_DENY], "pay", "fs-mcp", {"amount": "not a number"})
    assert decision.outcome is CallOutcome.SCOPE_VIOLATION


def test_deny_rule_takes_priority_over_allow_when_ordered_first():
    deny = _rule(deny=True)
    allow = _rule(rule_id="r2")
    decision = evaluate([deny, allow, CATCH_ALL_DENY], "write_file", "fs-mcp", {})
    assert decision.outcome is CallOutcome.POLICY_DENIED
