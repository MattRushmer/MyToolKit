"""Offline Sigma matching using pySigma's postprocessed condition tree.

pySigma exposes no public event evaluator. We walk its parsed condition tree;
values are still parsed and modifier-expanded by pySigma before comparison.
"""
from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Any

from detection_forge.backtest import log_loader
from detection_forge.backtest.log_loader import flatten_record, load_ndjson_logs
from detection_forge.models import BacktestResult, GeneratedRule, MatchedEvent


def _value_matches(expected: Any, actual: Any) -> bool:
    from sigma.types import SigmaCasedString, SigmaRegularExpression, SigmaString
    if isinstance(actual, list):
        return any(_value_matches(expected, item) for item in actual)
    if isinstance(expected, SigmaRegularExpression):
        flags = 0
        for flag in expected.flags:
            flags |= expected.sigma_to_python_flags[flag]
        return re.search(str(expected.regexp), str(actual), flags) is not None
    if isinstance(expected, SigmaString):
        pattern, candidate = str(expected), str(actual)
        if not isinstance(expected, SigmaCasedString):
            pattern, candidate = pattern.casefold(), candidate.casefold()
        return fnmatch.fnmatchcase(candidate, pattern)
    try:
        return actual == expected.to_plain()
    except Exception:
        return str(actual) == str(expected)


def _evaluate(tree: Any, event: dict[str, Any]) -> bool:
    from sigma.conditions import ConditionAND, ConditionFieldEqualsValueExpression, ConditionNOT, ConditionOR, ConditionValueExpression
    if isinstance(tree, ConditionAND): return all(_evaluate(arg, event) for arg in tree.args)
    if isinstance(tree, ConditionOR): return any(_evaluate(arg, event) for arg in tree.args)
    if isinstance(tree, ConditionNOT): return not any(_evaluate(arg, event) for arg in tree.args)
    if isinstance(tree, ConditionFieldEqualsValueExpression): return tree.field in event and _value_matches(tree.value, event[tree.field])
    if isinstance(tree, ConditionValueExpression): return any(_value_matches(tree.value, value) for value in event.values())
    return False


def _fields(rule: Any) -> set[str]:
    output: set[str] = set()
    def walk(item: Any) -> None:
        if getattr(item, "field", None): output.add(item.field)
        for child in getattr(item, "detection_items", []): walk(child)
    for detection in rule.detection.detections.values(): walk(detection)
    return output


def run_backtest(rule: GeneratedRule, log_paths: list[Path]) -> BacktestResult:
    result = BacktestResult(log_file=", ".join(Path(p).name for p in log_paths), total_events_scanned=0)
    events: list[tuple[int, dict[str, Any], dict[str, Any]]] = []
    seen: set[str] = set()
    for path_value in log_paths:
        path = Path(path_value)
        records = load_ndjson_logs(path)
        result.parse_errors.extend(f"{path.name}: {error}" for error in log_loader.last_parse_errors)
        for index, record in enumerate(records):
            line = log_loader.last_record_line_numbers[index] if index < len(log_loader.last_record_line_numbers) else index + 1
            flat = flatten_record(record)
            events.append((line, record, flat)); seen.update(flat)
    result.total_events_scanned = len(events)
    try:
        from sigma.rule import SigmaRule
        from sigma.rule.detection import SigmaDetections
        parsed = SigmaRule.from_yaml(rule.rule_yaml)
        result.unmapped_fields = sorted(field for field in _fields(parsed) if field not in seen)
        trees = [condition.parsed for condition in parsed.detection.parsed_condition]
        for line, original, flat in events:
            if any(_evaluate(tree, flat) for tree in trees):
                names = [name for name, detection in parsed.detection.detections.items()
                         if _evaluate(SigmaDetections({"x": detection}, "x").parsed_condition[0].parsed, flat)]
                result.matched_events.append(MatchedEvent(line_number=line, record=original, matched_selection_names=names))
    except Exception as exc:
        result.parse_errors.append(f"rule: unable to parse/evaluate Sigma rule ({exc})")
    return result
