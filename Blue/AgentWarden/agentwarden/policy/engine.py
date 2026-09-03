"""Pure policy evaluation: (identity, tool, upstream, arguments) -> Decision.

Deliberately stateless - no store access, no rate-limit counting. Rate
limiting needs an atomic check-then-mint against the store (see
broker/lifecycle.py's mint(), which calls evaluate() first and then applies
the max_uses_per_task check as part of the same guarded INSERT, closing the
TOCTOU window a separate pure check here could not close). Keeping this
module pure makes it trivially unit-testable and keeps "is this call allowed
in principle" cleanly separate from "does the store's current state let it
through right now".
"""
from __future__ import annotations

import posixpath

from agentwarden.models import ArgumentConstraint, CallOutcome, Decision, PolicyRule


def _normalize_posix_path(value: str) -> str:
    # Lexical only - no filesystem access, no symlink resolution (the real
    # containment guarantee is the upstream tool's own; this is a policy-layer
    # sanity check, documented as advisory in README's Known limitations).
    # Backslashes are normalized to `/` first: `posixpath.normpath` never
    # treats `\` as a separator, so `..\..\..\etc` would otherwise sail
    # through untouched and still pass a `startswith(boundary)` check here,
    # while an upstream tool running on Windows (or handed the path via any
    # API that accepts `\`) would still resolve those `..` segments for real.
    return posixpath.normpath(value.replace("\\", "/"))


def _is_path_within(value: str, boundary: str) -> bool:
    norm_value = _normalize_posix_path(value)
    norm_boundary = _normalize_posix_path(boundary)
    return norm_value == norm_boundary or norm_value.startswith(norm_boundary.rstrip("/") + "/")


def _has_traversal_segment(value: str) -> bool:
    """True if `value` contains a literal '..' path segment, `/`- or
    `\\`-delimited. Used to make `prefix` traversal-safe independent of
    policy/schema.py's field-name heuristic (H1 follow-up): that heuristic
    only catches fields named like `path`/`file`/`dir`/`folder` - a field
    named `location`/`target`/`cwd`/`workspace` using `prefix` on a path-ish
    value got zero protection from it. Checking the value itself, not the
    field name, closes the hole regardless of what the field happens to be
    called. `prefix`'s legitimate non-path uses (e.g. a repo-name prefix like
    "my-org/") have no legitimate reason to ever contain a '..' segment, so
    this costs nothing for the cases `prefix` actually exists for."""
    return ".." in value.replace("\\", "/").split("/")


def _evaluate_one_constraint(constraint: ArgumentConstraint, value: object) -> bool:
    if constraint.prefix is not None:
        return isinstance(value, str) and value.startswith(constraint.prefix) and not _has_traversal_segment(value)
    if constraint.path_within is not None:
        return isinstance(value, str) and _is_path_within(value, constraint.path_within)
    if constraint.in_ is not None:
        return value in constraint.in_
    if constraint.lt is not None:
        return isinstance(value, (int, float)) and not isinstance(value, bool) and value < constraint.lt
    if constraint.gt is not None:
        return isinstance(value, (int, float)) and not isinstance(value, bool) and value > constraint.gt
    return value == constraint.eq  # eq handles None/bool/str/int alike, incl. constraint.eq itself being None


def _check_constraints(rule: PolicyRule, arguments: dict[str, object]) -> tuple[bool, dict[str, object]]:
    """Returns (passed, redacted_arguments) - redacted_arguments carries only
    the fields the rule actually constrains, for ToolCallRecord.redacted_arguments
    (see broker/redaction.py for the full digest+redaction pipeline this feeds)."""
    redacted: dict[str, object] = {}
    for field_name, constraint in rule.argument_constraints.items():
        if field_name not in arguments:
            return False, redacted  # fail-closed: a constrained field that's simply absent does not pass
        value = arguments[field_name]
        redacted[field_name] = value
        if not _evaluate_one_constraint(constraint, value):
            return False, redacted
    if rule.strict:
        # argument_constraints is otherwise just a named-field allow-list: a
        # tool call carrying some extra argument the policy author never
        # anticipated sails through untouched (see policy/schema.py's module
        # docstring). `strict: true` closes that by fail-closed-rejecting any
        # argument not explicitly named in this rule's constraints.
        unexpected = sorted(set(arguments) - set(rule.argument_constraints))
        if unexpected:
            return False, redacted
    return True, redacted


def evaluate(rules: list[PolicyRule], tool_name: str, upstream_server_id: str, arguments: dict[str, object]) -> Decision:
    """`rules` must already be in the resolved order policy/schema.py produces
    (deny rules, then allow rules, then the identity's catch-all) - this
    function does not re-sort, so a caller passing an unordered list gets an
    unordered (and wrong) evaluation."""
    for rule in rules:
        tool_matches = rule.tool_name == "*" or rule.tool_name == tool_name
        upstream_matches = rule.upstream_server_id == "*" or rule.upstream_server_id == upstream_server_id
        if not (tool_matches and upstream_matches):
            continue

        if rule.deny:
            reason = f"denied by rule '{rule.rule_id}'" if rule.source == "explicit" else "denied by identity default (no matching allow rule)"
            return Decision(outcome=CallOutcome.POLICY_DENIED, matched_rule=rule, reason=reason)

        passed, redacted = _check_constraints(rule, arguments)
        if not passed:
            return Decision(
                outcome=CallOutcome.SCOPE_VIOLATION, matched_rule=rule,
                reason=f"arguments do not satisfy rule '{rule.rule_id}''s constraints",
                redacted_arguments=redacted,
            )
        return Decision(outcome=CallOutcome.ALLOWED, matched_rule=rule, reason=f"allowed by rule '{rule.rule_id}'", redacted_arguments=redacted)

    # Unreachable in practice: schema.py always appends a "*"/"*" catch-all
    # per identity, so the loop above always matches something. Kept as a
    # fail-closed backstop rather than an assert, in case a caller ever
    # builds a rule list by hand (e.g. a test) without going through schema.py.
    return Decision(outcome=CallOutcome.POLICY_DENIED, matched_rule=None, reason="no matching rule and no catch-all present (fail-closed)")
