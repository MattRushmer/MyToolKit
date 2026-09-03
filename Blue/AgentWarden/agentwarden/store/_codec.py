"""Shared (de)serialization helpers for the store modules - every table
stores timestamps as ISO-8601 text and structured fields as JSON text,
since sqlite3's native types don't cover datetime/dict/set."""
from __future__ import annotations

import json
from datetime import datetime


def dt_to_str(value: datetime) -> str:
    return value.isoformat()


def str_to_dt(value: str) -> datetime:
    return datetime.fromisoformat(value)


def opt_dt_to_str(value: datetime | None) -> str | None:
    return None if value is None else dt_to_str(value)


def opt_str_to_dt(value: str | None) -> datetime | None:
    return None if value is None else str_to_dt(value)


def to_json(value: object) -> str:
    return json.dumps(value, default=str)


def from_json(value: str) -> object:
    return json.loads(value)
