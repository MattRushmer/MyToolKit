"""Offline Sigma matching using pySigma's postprocessed condition tree.

pySigma exposes no public event evaluator, so this walks its parsed
condition tree directly (undocumented-but-stable internal API: the same
sigma.conditions node types every pySigma backend already consumes to
generate queries). Value comparison always goes through pySigma's own typed
value objects (SigmaString.to_regex(), SigmaCIDRExpression, etc.) rather than
re-deriving wildcard/CIDR/comparison semantics by hand, since that's the part
most likely to silently diverge from the real Sigma spec.
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any

from detection_forge.backtest.log_loader import flatten_record, load_ndjson_logs
from detection_forge.models import BacktestResult, GeneratedRule, MatchedEvent

_MAX_STORED_MATCHES = 500
_MAX_EVAL_ERRORS_STORED = 20


def _value_matches(expected: Any, actual: Any) -> bool:
    from sigma.types import (
        SigmaBool,
        SigmaCIDRExpression,
        SigmaCompareExpression,
        SigmaNull,
        SigmaNumber,
        SigmaRegularExpression,
        SigmaString,
    )

    if isinstance(actual, list):
        return any(_value_matches(expected, item) for item in actual)

    if isinstance(expected, SigmaCIDRExpression):
        try:
            return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(expected.cidr, strict=False)
        except ValueError:
            return False

    if isinstance(expected, SigmaCompareExpression):
        try:
            actual_num, expected_num = float(actual), float(expected.number.number)
        except (TypeError, ValueError):
            return False
        from sigma.types import CompareOperators

        return {
            CompareOperators.LT: actual_num < expected_num,
            CompareOperators.LTE: actual_num <= expected_num,
            CompareOperators.GT: actual_num > expected_num,
            CompareOperators.GTE: actual_num >= expected_num,
            CompareOperators.NEQ: actual_num != expected_num,
        }.get(expected.op, False)

    if isinstance(expected, SigmaRegularExpression):
        flags = 0
        for flag in expected.flags:
            flags |= expected.sigma_to_python_flags[flag]
        return re.search(str(expected.regexp), str(actual), flags) is not None

    if isinstance(expected, SigmaString):
        # SigmaString.to_regex() is pySigma's own, spec-correct conversion of
        # Sigma wildcard syntax (*, ?) into a properly-escaped regex - it
        # correctly handles literal regex-metacharacters in the value (e.g. a
        # literal '[' in '[System.Reflection.Assembly]'), which a hand-built
        # fnmatch pattern from str(expected) does not: fnmatch interprets
        # '[...]' as a character class, and str(SigmaString) backslash-escapes
        # literal '*'/'?' in a way fnmatch has no concept of.
        from sigma.types import SigmaCasedString

        flags = 0 if isinstance(expected, SigmaCasedString) else re.IGNORECASE
        pattern = expected.to_regex().regexp.to_plain()
        try:
            return re.fullmatch(pattern, str(actual), flags) is not None
        except re.error:
            return False

    if isinstance(expected, (SigmaNumber, SigmaBool)):
        try:
            return actual == expected.to_plain()
        except Exception:
            return str(actual) == str(expected)

    if isinstance(expected, SigmaNull):
        return actual is None

    return str(actual) == str(expected)


def _field_present(event: dict[str, Any], field_name: str) -> bool:
    if field_name in event:
        return True
    suffix = f".{field_name}"
    return any(key.endswith(suffix) for key in event)


def _evaluate(tree: Any, event: dict[str, Any]) -> bool:
    from sigma.conditions import (
        ConditionAND,
        ConditionFieldEqualsValueExpression,
        ConditionNOT,
        ConditionOR,
        ConditionValueExpression,
    )
    from sigma.types import SigmaExists

    if isinstance(tree, ConditionAND):
        return all(_evaluate(arg, event) for arg in tree.args)
    if isinstance(tree, ConditionOR):
        return any(_evaluate(arg, event) for arg in tree.args)
    if isinstance(tree, ConditionNOT):
        return not any(_evaluate(arg, event) for arg in tree.args)
    if isinstance(tree, ConditionFieldEqualsValueExpression):
        if isinstance(tree.value, SigmaExists):
            present = _field_present(event, tree.field)
            return present if tree.value.exists else not present
        return tree.field in event and _value_matches(tree.value, event[tree.field])
    if isinstance(tree, ConditionValueExpression):
        return any(_value_matches(tree.value, value) for value in event.values())
    return False


def _fields(rule: Any) -> set[str]:
    output: set[str] = set()

    def walk(item: Any) -> None:
        if getattr(item, "field", None):
            output.add(item.field)
        for child in getattr(item, "detection_items", []):
            walk(child)

    for detection in rule.detection.detections.values():
        walk(detection)
    return output


def _selection_trees(parsed: Any) -> dict[str, Any]:
    """Precompute each named selection's own condition tree once (not per-event).

    Reusing SigmaDetections({name: detection}, name) inside the hot event
    loop would re-run pySigma's postprocess() - which mutates parent/source
    chain attributes on the *same* shared detection-item objects referenced
    by the rule's main condition tree - once per matched event, which is
    both wasted work and fragile given this is undocumented internal API.
    """
    from sigma.rule.detection import SigmaDetections

    return {
        name: SigmaDetections({name: detection}, [name]).parsed_condition[0].parsed
        for name, detection in parsed.detection.detections.items()
    }


def run_backtest(rule: GeneratedRule, log_paths: list[Path]) -> BacktestResult:
    result = BacktestResult(log_file=", ".join(Path(p).name for p in log_paths), total_events_scanned=0)
    events: list[tuple[int, dict[str, Any], dict[str, Any]]] = []
    seen: set[str] = set()

    for path_value in log_paths:
        path = Path(path_value)
        parsed_file = load_ndjson_logs(path)
        result.parse_errors.extend(f"{path.name}: {error}" for error in parsed_file.parse_errors)
        for record, line in zip(parsed_file.records, parsed_file.record_line_numbers):
            flat = flatten_record(record)
            events.append((line, record, flat))
            seen.update(flat)

    result.total_events_scanned = len(events)

    try:
        from sigma.rule import SigmaRule

        parsed = SigmaRule.from_yaml(rule.rule_yaml)
    except Exception as exc:
        result.parse_errors.append(f"rule: unable to parse Sigma rule ({exc})")
        return result

    result.unmapped_fields = sorted(field for field in _fields(parsed) if field not in seen)
    trees = [condition.parsed for condition in parsed.detection.parsed_condition]
    selection_trees = _selection_trees(parsed)

    eval_errors = 0
    for line, original, flat in events:
        try:
            is_match = any(_evaluate(tree, flat) for tree in trees)
            if not is_match:
                continue
            names = [name for name, tree in selection_trees.items() if _evaluate(tree, flat)]
        except Exception as exc:
            eval_errors += 1
            if eval_errors <= _MAX_EVAL_ERRORS_STORED:
                result.parse_errors.append(f"line {line}: unable to evaluate rule against this event ({exc})")
            continue

        if len(result.matched_events) < _MAX_STORED_MATCHES:
            result.matched_events.append(MatchedEvent(line_number=line, record=original, matched_selection_names=names))

    if eval_errors > _MAX_EVAL_ERRORS_STORED:
        result.parse_errors.append(f"... and {eval_errors - _MAX_EVAL_ERRORS_STORED} more per-event evaluation errors")

    return result
