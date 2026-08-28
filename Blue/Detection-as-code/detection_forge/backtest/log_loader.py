"""Tolerant loaders for the JSON event samples used by the backtester.

Diagnostics (parse errors, source line numbers) are returned directly from
load_ndjson_logs() rather than stashed in module globals - this file is
called from detection_forge.backtest.matcher.run_backtest(), which the web
app now invokes concurrently across requests via starlette's threadpool
(see webapp/main.py), so any shared mutable module state here would be a
cross-request data race.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ParsedLogFile:
    records: list[dict[str, Any]] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)
    record_line_numbers: list[int] = field(default_factory=list)


def load_ndjson_logs(path: Path) -> ParsedLogFile:
    """Load a JSON array or NDJSON file, retaining useful parse diagnostics."""
    result = ParsedLogFile()
    try:
        text = path.read_text(encoding="utf-8-sig")
    except Exception as exc:
        result.parse_errors.append(f"line 0: unable to read file ({exc})")
        return result
    if not text.strip():
        return result

    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            for number, value in enumerate(parsed, 1):
                if isinstance(value, dict):
                    result.records.append(value)
                    result.record_line_numbers.append(number)
                else:
                    result.parse_errors.append(f"line {number}: JSON array item is not an object")
            return result
    except json.JSONDecodeError:
        pass  # fall through to line-by-line NDJSON parsing

    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError("JSON value is not an object")
            result.records.append(value)
            result.record_line_numbers.append(number)
        except Exception as exc:
            result.parse_errors.append(f"line {number}: {str(exc).splitlines()[0]}")
    return result


def flatten_record(record: dict[str, Any], sep: str = ".") -> dict[str, Any]:
    """Flatten nested event JSON and add safe bare-field aliases for Sigma rules."""
    flattened: dict[str, Any] = {}

    def visit(value: Any, key: str) -> None:
        if isinstance(value, dict):
            for child_key, child_value in value.items():
                visit(child_value, f"{key}{sep}{child_key}" if key else str(child_key))
        elif isinstance(value, list):
            if all(not isinstance(item, (dict, list)) for item in value):
                flattened[key] = " ".join(str(item) for item in value)
            else:
                for index, item in enumerate(value):
                    visit(item, f"{key}{sep}{index}")
        else:
            flattened[key] = value

    visit(record, "")
    top_level = set(record)
    for key, value in list(flattened.items()):
        bare = key.rsplit(sep, 1)[-1]
        if bare not in top_level:
            flattened.setdefault(bare, value)
    return flattened
