"""Turn a raw CSV/JSON export from whatever dashboard an MSP is looking at
today into a flat list of soc_copilot.models.Alert - the one shape every
downstream stage (correlate/triage/recommend/report) works with.

Deliberately not pandas: MSP alert exports are small (hundreds to low
thousands of rows per pull), and stdlib csv/json keeps the dependency list -
and the install size - down, which matters for a tool pitched as lean.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from soc_copilot.ingest.adapters import AdapterSpec, get_adapter
from soc_copilot.models import Alert, Severity

# Python's csv module defaults to a 128KB field-size limit, low enough that a
# single verbose (but entirely legitimate) EDR description field can exceed
# it and raise csv.Error mid-parse. Raised here, process-wide, to a value
# still well under the app's whole-file upload cap (webapp/main.py's
# _MAX_UPLOAD_BYTES), so a hostile single field can't grow unbounded either.
csv.field_size_limit(10 * 1024 * 1024)


class IngestError(Exception):
    """Raised for a whole-file problem (unreadable, unparseable). Per-row problems are skipped with a warning instead."""


def _find_value(row: dict[str, Any], candidates: list[str]) -> str:
    lowered = {str(k).strip().lower(): v for k, v in row.items()}
    for candidate in candidates:
        value = lowered.get(candidate.lower())
        if value not in (None, ""):
            return str(value)
    return ""


def map_severity(raw: str, adapter: AdapterSpec) -> Severity:
    raw = (raw or "").strip()
    if not raw:
        return Severity.MEDIUM  # unknown severity defaults to "worth a look", not silently dropped to low
    # CrowdStrike-style numeric severity (0-100): bucket it instead of failing the word lookup.
    try:
        numeric = float(raw)
        if not math.isfinite(numeric) or not 0 <= numeric <= 100:
            return Severity.MEDIUM
        if numeric >= 90:
            return Severity.CRITICAL
        if numeric >= 70:
            return Severity.HIGH
        if numeric >= 40:
            return Severity.MEDIUM
        if numeric >= 20:
            return Severity.LOW
        return Severity.INFORMATIONAL
    except ValueError:
        pass
    mapped = adapter.severity_map.get(raw.lower())
    if mapped:
        return Severity(mapped)
    return Severity.MEDIUM


def _parse_timestamp(raw: str) -> datetime:
    raw = raw.strip()
    if not raw:
        raise ValueError("empty timestamp")
    candidate = raw.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
        return parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %I:%M %p",
        "%m/%d/%Y",
        "%Y-%m-%d",
    ):
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise ValueError(f"unrecognized timestamp format: {raw!r}")


def _fallback_alert_id(client_id: str, source: str, row_fields: dict[str, str]) -> str:
    """Deterministic ID when the source row has none, so re-ingesting the same
    export doesn't create duplicate alerts downstream."""
    basis = "|".join([client_id, source, row_fields.get("title", ""), row_fields.get("host", ""), row_fields.get("timestamp", "")])
    return f"{source}-{hashlib.sha1(basis.encode('utf-8')).hexdigest()[:12]}"


def normalize_row(row: dict[str, Any], client_id: str, source: str, adapter: AdapterSpec) -> tuple[Alert | None, str | None]:
    """Returns (alert, None) on success or (None, warning_message) if the row can't be used."""
    fields = {name: _find_value(row, candidates) for name, candidates in adapter.field_map.items()}
    if not fields.get("timestamp"):
        return None, "row has no recognizable timestamp column; skipped"
    try:
        timestamp = _parse_timestamp(fields["timestamp"])
    except ValueError as exc:
        return None, f"skipped row: {exc}"
    alert_id = fields.get("alert_id") or _fallback_alert_id(client_id, source, fields)
    alert = Alert(
        alert_id=alert_id,
        client_id=client_id,
        source=source,
        timestamp=timestamp,
        host=fields.get("host", ""),
        user=fields.get("user", ""),
        category=(fields.get("category") or adapter.default_category or "uncategorized").lower(),
        title=fields.get("title") or "(untitled alert)",
        description=fields.get("description", ""),
        severity=map_severity(fields.get("severity_raw", ""), adapter),
        severity_raw=fields.get("severity_raw", ""),
        raw=dict(row),
    )
    return alert, None


def load_alerts_from_csv(path: Path, client_id: str, source: str = "generic") -> tuple[list[Alert], list[str]]:
    adapter = get_adapter(source)
    try:
        text = Path(path).read_text(encoding="utf-8-sig", errors="replace")
    except OSError as exc:
        raise IngestError(f"could not read {path}: {exc}") from exc
    # csv.DictReader(io.StringIO(...)), not text.splitlines(): splitlines() strips
    # line terminators before the csv module sees them, so a quoted field that
    # spans multiple physical lines (common in verbose EDR description columns)
    # gets its embedded newline silently deleted instead of preserved.
    reader = csv.DictReader(io.StringIO(text))
    alerts: list[Alert] = []
    warnings: list[str] = []
    row_iterator = enumerate(reader, start=2)  # header is line 1
    while True:
        try:
            i, row = next(row_iterator)
        except StopIteration:
            break
        except csv.Error as exc:
            # Malformed CSV structure (e.g. a field beyond even the raised
            # field_size_limit above, or an embedded NUL byte) - skip past it
            # rather than letting the whole file fail; the reader can keep
            # advancing since the underlying StringIO still has more input.
            warnings.append(f"{path.name}: skipped malformed row: {exc}")
            continue
        alert, warning = normalize_row(row, client_id, source, adapter)
        if warning:
            warnings.append(f"{path.name}:{i}: {warning}")
            continue
        alerts.append(alert)
    return alerts, warnings


def load_alerts_from_json(path: Path, client_id: str, source: str = "generic") -> tuple[list[Alert], list[str]]:
    adapter = get_adapter(source)
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise IngestError(f"could not read {path}: {exc}") from exc
    rows: list[dict[str, Any]] = []
    stripped = text.strip()
    if not stripped:
        return [], []
    warnings: list[str] = []
    if stripped.startswith("["):
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise IngestError(f"{path}: invalid JSON array: {exc}") from exc
        except (RecursionError, MemoryError) as exc:
            # A pathologically deep/large JSON document (e.g. tens of thousands of
            # nested arrays) - not malformed, just hostile input. Whole-file failure
            # is still the right call here (we can't safely partially parse one
            # top-level array), but this must not propagate as an unhandled 500.
            raise IngestError(f"{path}: JSON document too large/deeply nested to parse: {exc}") from exc
        rows = [r for r in parsed if isinstance(r, dict)]
    else:
        # NDJSON: one JSON object per line. A malformed/truncated line is a
        # per-row problem, not a whole-file one - per IngestError's own contract
        # above, skip it with a warning instead of discarding every other
        # (potentially valid) alert in the file.
        for i, line in enumerate(stripped.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                warnings.append(f"{path.name}:{i}: skipped line: invalid JSON: {exc}")
                continue
            except (RecursionError, MemoryError) as exc:
                # Same hostile-input guard as the JSON-array branch above -
                # a single pathologically nested line is a per-row problem,
                # not a whole-file one, so skip it rather than letting the
                # exception propagate as an unhandled 500.
                warnings.append(f"{path.name}:{i}: skipped line: too large/deeply nested to parse: {exc}")
                continue
            if isinstance(obj, dict):
                rows.append(obj)
    alerts: list[Alert] = []
    for i, row in enumerate(rows, start=1):
        alert, warning = normalize_row(row, client_id, source, adapter)
        if warning:
            warnings.append(f"{path.name}#{i}: {warning}")
            continue
        alerts.append(alert)
    return alerts, warnings


def load_alerts(path: Path, client_id: str, source: str = "generic") -> tuple[list[Alert], list[str]]:
    """Dispatch on file extension - the one entry point ingest callers use."""
    suffix = Path(path).suffix.lower()
    if suffix == ".csv":
        return load_alerts_from_csv(path, client_id, source)
    if suffix in (".json", ".ndjson", ".jsonl"):
        return load_alerts_from_json(path, client_id, source)
    raise IngestError(f"unsupported file type '{suffix}' for {path} (expected .csv, .json, .ndjson, or .jsonl)")
