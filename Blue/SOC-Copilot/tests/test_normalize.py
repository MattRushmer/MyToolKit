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
    ],
)
def test_map_severity(raw, expected):
    assert map_severity(raw, get_adapter("generic")) == expected
