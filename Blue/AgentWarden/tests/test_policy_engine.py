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


def test_prefix_constraint_rejects_traversal_regardless_of_field_name():
    """H1 follow-up: policy/schema.py's load-time check only catches fields
    literally named like path/file/dir/folder - a field named e.g.
    'location' using 'prefix' got zero traversal protection from that
    heuristic. The predicate itself must reject '..' segments regardless of
    what the field is called."""
    rule = _rule(argument_constraints={"location": ArgumentConstraint(prefix="/workspace/")})
    escaping = evaluate([rule, CATCH_ALL_DENY], "write_file", "fs-mcp", {"location": "/workspace/../../etc/passwd"})
    assert escaping.outcome is CallOutcome.SCOPE_VIOLATION

    escaping_backslash = evaluate([rule, CATCH_ALL_DENY], "write_file", "fs-mcp", {"location": "/workspace/..\\..\\etc\\passwd"})
    assert escaping_backslash.outcome is CallOutcome.SCOPE_VIOLATION


def test_prefix_constraint_still_matches_legitimate_non_traversal_value():
    rule = _rule(argument_constraints={"location": ArgumentConstraint(prefix="/workspace/")})
    ok = evaluate([rule, CATCH_ALL_DENY], "write_file", "fs-mcp", {"location": "/workspace/notes.md"})
    assert ok.outcome is CallOutcome.ALLOWED


def test_path_within_blocks_backslash_traversal_on_windows_style_path():
    """H2: posixpath.normpath never treats '\\' as a separator, so a value
    like '/workspace/..\\..\\..\\Windows\\System32\\...' used to sail through
    startswith('/workspace') unnormalized - but an upstream tool running on
    Windows (or any API that accepts '\\') would still resolve those '..'
    segments for real, defeating the one containment guarantee path_within
    exists to provide."""
    rule = _rule(argument_constraints={"path": ArgumentConstraint(path_within="/workspace")})
    escaping = evaluate([rule, CATCH_ALL_DENY], "write_file", "fs-mcp", {"path": "/workspace/..\\..\\..\\etc\\passwd"})
    assert escaping.outcome is CallOutcome.SCOPE_VIOLATION


def test_gt_constraint_pass_and_fail():
    rule = _rule(tool_name="pay", argument_constraints={"amount": ArgumentConstraint(gt=10)})
    ok = evaluate([rule, CATCH_ALL_DENY], "pay", "fs-mcp", {"amount": 20})
    bad = evaluate([rule, CATCH_ALL_DENY], "pay", "fs-mcp", {"amount": 5})
    assert ok.outcome is CallOutcome.ALLOWED
    assert bad.outcome is CallOutcome.SCOPE_VIOLATION


def test_eq_constraint_pass_and_fail():
    rule = _rule(tool_name="toggle", argument_constraints={"enabled": ArgumentConstraint(eq=True)})
    ok = evaluate([rule, CATCH_ALL_DENY], "toggle", "fs-mcp", {"enabled": True})
    bad = evaluate([rule, CATCH_ALL_DENY], "toggle", "fs-mcp", {"enabled": False})
    assert ok.outcome is CallOutcome.ALLOWED
    assert bad.outcome is CallOutcome.SCOPE_VIOLATION


def test_strict_rule_denies_unconstrained_extra_argument():
    """M4: argument_constraints is a named-field allow-list, not a schema -
    without strict=True, an argument the policy author never named sails
    through untouched. strict=True must fail-closed on it instead."""
    rule = _rule(strict=True, argument_constraints={"path": ArgumentConstraint(path_within="/workspace")})
    bad = evaluate([rule, CATCH_ALL_DENY], "write_file", "fs-mcp", {"path": "/workspace/a.txt", "symlink_target": "/etc/passwd"})
    assert bad.outcome is CallOutcome.SCOPE_VIOLATION


def test_strict_rule_allows_when_no_extra_arguments():
    rule = _rule(strict=True, argument_constraints={"path": ArgumentConstraint(path_within="/workspace")})
    ok = evaluate([rule, CATCH_ALL_DENY], "write_file", "fs-mcp", {"path": "/workspace/a.txt"})
    assert ok.outcome is CallOutcome.ALLOWED


def test_non_strict_rule_allows_unconstrained_extra_argument():
    rule = _rule(argument_constraints={"path": ArgumentConstraint(path_within="/workspace")})
    ok = evaluate([rule, CATCH_ALL_DENY], "write_file", "fs-mcp", {"path": "/workspace/a.txt", "mode": "overwrite"})
    assert ok.outcome is CallOutcome.ALLOWED


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
