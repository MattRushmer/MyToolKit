from datetime import datetime, timezone
from pathlib import Path

import pytest

from soc_copilot.ingest.adapters import get_adapter
from soc_copilot.ingest.normalize import IngestError, load_alerts, load_alerts_from_csv, load_alerts_from_json, map_severity
from soc_copilot.models import Severity

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def test_load_defender_csv_maps_known_columns():
    alerts, warnings = load_alerts_from_csv(SAMPLES / "acme-dental_defender_alerts.csv", "acme-dental", "defender")
    assert warnings == []
    assert len(alerts) == 4
    first = alerts[0]
    assert first.alert_id == "DFD-1001"
    assert first.host == "ACME-WKS-07"
    assert first.user == "jsmith"
    assert first.severity == Severity.HIGH
    assert first.timestamp == datetime(2026, 8, 20, 9, 14, 2, tzinfo=timezone.utc)


def test_load_crowdstrike_json_handles_numeric_severity():
    alerts, warnings = load_alerts_from_json(SAMPLES / "globex-logistics_crowdstrike_detections.json", "globex-logistics", "crowdstrike")
    assert warnings == []
    assert len(alerts) == 4
    macro_alert = next(a for a in alerts if a.alert_id == "CS-77330")
    assert macro_alert.severity_raw == "55"
    assert macro_alert.severity == Severity.MEDIUM  # 55 buckets to medium (40-69)


def test_load_huntress_csv():
    alerts, warnings = load_alerts_from_csv(SAMPLES / "acme-dental_huntress_alerts.csv", "acme-dental", "huntress")
    assert warnings == []
    assert len(alerts) == 2
    assert alerts[0].severity == Severity.CRITICAL


def test_dispatch_by_extension_csv_and_json():
    csv_alerts, _ = load_alerts(SAMPLES / "acme-dental_defender_alerts.csv", "acme-dental", "defender")
    json_alerts, _ = load_alerts(SAMPLES / "globex-logistics_crowdstrike_detections.json", "globex-logistics", "crowdstrike")
    assert len(csv_alerts) == 4
    assert len(json_alerts) == 4


def test_unsupported_extension_raises():
    with pytest.raises(IngestError):
        load_alerts(SAMPLES / "acme-dental_defender_alerts.csv".replace(".csv", ".txt"), "x", "generic")


def test_missing_file_raises_ingest_error():
    with pytest.raises(IngestError):
        load_alerts_from_csv(Path("does/not/exist.csv"), "acme-dental", "generic")


def test_missing_alert_id_gets_deterministic_fallback(tmp_path):
    csv_text = "Title,Severity,Host,Timestamp\nNo ID Alert,High,SOME-HOST,2026-01-01T00:00:00Z\n"
    path = tmp_path / "no_id.csv"
    path.write_text(csv_text, encoding="utf-8")
    alerts1, _ = load_alerts_from_csv(path, "client-a", "generic")
    alerts2, _ = load_alerts_from_csv(path, "client-a", "generic")
    assert alerts1[0].alert_id == alerts2[0].alert_id  # deterministic, not random
    assert alerts1[0].alert_id.startswith("generic-")


def test_row_missing_timestamp_is_skipped_with_warning(tmp_path):
    csv_text = "Title,Severity,Host\nNo Timestamp,High,SOME-HOST\n"
    path = tmp_path / "no_ts.csv"
    path.write_text(csv_text, encoding="utf-8")
    alerts, warnings = load_alerts_from_csv(path, "client-a", "generic")
    assert alerts == []
    assert len(warnings) == 1


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Critical", Severity.CRITICAL),
        ("high", Severity.HIGH),
        ("Moderate", Severity.MEDIUM),
        ("", Severity.MEDIUM),
        ("95", Severity.CRITICAL),
        ("10", Severity.INFORMATIONAL),
        ("NaN", Severity.MEDIUM),
        ("101", Severity.MEDIUM),
    ],
)
def test_map_severity(raw, expected):
    assert map_severity(raw, get_adapter("generic")) == expected


def test_timestamps_without_an_offset_are_normalized_to_utc(tmp_path):
    path = tmp_path / "naive_timestamp.csv"
    path.write_text("Timestamp,Title\n2026-01-01 09:00:00,Alert\n", encoding="utf-8")

    alerts, warnings = load_alerts_from_csv(path, "client-a")

    assert warnings == []
    assert alerts[0].timestamp == datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)


def test_csv_field_with_embedded_newline_is_preserved(tmp_path):
    path = tmp_path / "multiline.csv"
    path.write_text(
        'AlertId,Title,Description,Timestamp\n1,Alert One,"line one\nline two",2026-01-01T00:00:00Z\n',
        encoding="utf-8",
    )

    alerts, warnings = load_alerts_from_csv(path, "client-a")

    assert warnings == []
    assert alerts[0].description == "line one\nline two"


def test_malformed_ndjson_line_is_skipped_not_fatal(tmp_path):
    path = tmp_path / "mixed.ndjson"
    path.write_text(
        '{"AlertId":"1","Title":"ok1","Timestamp":"2026-01-01T00:00:00Z"}\n'
        "NOT VALID JSON\n"
        '{"AlertId":"2","Title":"ok2","Timestamp":"2026-01-02T00:00:00Z"}\n',
        encoding="utf-8",
    )

    alerts, warnings = load_alerts_from_json(path, "client-a")

    assert len(alerts) == 2
    assert len(warnings) == 1
    assert "invalid JSON" in warnings[0]


def test_pathologically_nested_ndjson_line_is_skipped_not_a_crash(tmp_path):
    """RecursionError from a single hostile line must not propagate uncaught -
    this is the NDJSON-branch sibling of the JSON-array RecursionError guard;
    a security review found the array branch was guarded but this one wasn't."""
    nested_line = '{"a":' * 3000 + "1" + "}" * 3000
    path = tmp_path / "hostile.ndjson"
    path.write_text(nested_line + "\n", encoding="utf-8")

    alerts, warnings = load_alerts_from_json(path, "client-a")

    assert alerts == []
    assert len(warnings) == 1
    assert "too large/deeply nested" in warnings[0]


def test_pathologically_nested_json_array_raises_controlled_ingest_error(tmp_path):
    nested = "[" * 3000 + "]" * 3000
    path = tmp_path / "hostile.json"
    path.write_text(nested, encoding="utf-8")

    with pytest.raises(IngestError, match="too large/deeply nested"):
        load_alerts_from_json(path, "client-a")


def test_field_beyond_default_csv_limit_no_longer_crashes(tmp_path):
    """Python's csv module defaults to a 128KB field-size limit - a single
    verbose (legitimate) EDR description field can exceed that. normalize.py
    raises the process-wide limit; this confirms a field past the *old*
    default still parses instead of raising csv.Error."""
    big_field = "A" * (200 * 1024)
    path = tmp_path / "big_field.csv"
    path.write_text(
        f"Timestamp,Title,Description\n2026-01-01T00:00:00Z,Ok Row,normal\n2026-01-02T00:00:00Z,Big Row,{big_field}\n",
        encoding="utf-8",
    )

    alerts, warnings = load_alerts_from_csv(path, "client-a")

    assert warnings == []
    assert len(alerts) == 2
    assert len(alerts[1].description) == len(big_field)
