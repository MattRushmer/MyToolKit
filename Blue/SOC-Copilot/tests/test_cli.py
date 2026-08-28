from pathlib import Path

from cli.main import _parse_alert_specs


def test_bare_windows_absolute_path_defaults_to_generic_source(tmp_path):
    """A drive-letter colon (C:\\...) must not be mistaken for the path:source
    separator when no explicit source is given - this is the tool's documented
    default-source shorthand and its primary usage pattern on Windows."""
    csv_path = tmp_path / "alerts.csv"
    csv_path.write_text("Timestamp,Title\n2026-01-01T00:00:00Z,Alert\n", encoding="utf-8")

    specs = _parse_alert_specs([str(csv_path)])

    assert len(specs) == 1
    assert specs[0] == (csv_path, "generic")


def test_explicit_source_after_windows_drive_letter_is_still_parsed(tmp_path):
    csv_path = tmp_path / "alerts.csv"
    csv_path.write_text("Timestamp,Title\n2026-01-01T00:00:00Z,Alert\n", encoding="utf-8")

    specs = _parse_alert_specs([f"{csv_path}:defender"])

    assert specs == [(csv_path, "defender")]


def test_relative_path_with_explicit_source(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    csv_path = Path("alerts.csv")
    csv_path.write_text("Timestamp,Title\n2026-01-01T00:00:00Z,Alert\n", encoding="utf-8")

    specs = _parse_alert_specs(["alerts.csv:huntress"])

    assert specs == [(Path("alerts.csv"), "huntress")]
