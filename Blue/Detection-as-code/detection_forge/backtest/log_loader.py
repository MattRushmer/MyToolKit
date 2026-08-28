"""Tolerant loaders for the JSON event samples used by the backtester."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


# Kept at module scope so callers which need diagnostics can read it without
# changing the small public return contract requested for load_ndjson_logs().
last_parse_errors: list[str] = []
last_record_line_numbers: list[int] = []


def load_ndjson_logs(path: Path) -> list[dict[str, Any]]:
    """Load a JSON array or NDJSON file, retaining useful parse diagnostics."""
    global last_parse_errors, last_record_line_numbers
    last_parse_errors = []
    last_record_line_numbers = []
    try:
        text = path.read_text(encoding="utf-8-sig")
    except Exception as exc:
        last_parse_errors.append(f"line 0: unable to read file ({exc})")
        return []
    if not text.strip():
        return []
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            records = []
            for number, value in enumerate(parsed, 1):
                if isinstance(value, dict):
                    records.append(value)
                    last_record_line_numbers.append(number)
                else:
                    last_parse_errors.append(f"line {number}: JSON array item is not an object")
            return records
    except json.JSONDecodeError:
        pass
    records = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError("JSON value is not an object")
            records.append(value)
            last_record_line_numbers.append(number)
        except Exception as exc:
            last_parse_errors.append(f"line {number}: {str(exc).splitlines()[0]}")
    return records


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
