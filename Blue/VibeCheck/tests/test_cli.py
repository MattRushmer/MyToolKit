from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from cli.main import app

runner = CliRunner()


def test_scan_command_reports_findings_and_writes_json(demo_app_root: Path, tmp_path: Path):
    out_json = tmp_path / "report.json"
    result = runner.invoke(app, ["scan", str(demo_app_root), "--out-json", str(out_json)])
    assert result.exit_code == 0
    assert out_json.exists()
    payload = json.loads(out_json.read_text(encoding="utf-8"))
    assert len(payload["findings"]) > 0


def test_scan_command_fails_on_severity_threshold(demo_app_root: Path):
    result = runner.invoke(app, ["scan", str(demo_app_root), "--fail-on", "critical"])
    assert result.exit_code == 2


def test_scan_command_rejects_missing_directory(tmp_path: Path):
    result = runner.invoke(app, ["scan", str(tmp_path / "does-not-exist")])
    assert result.exit_code == 1


def test_check_setup_command_runs():
    result = runner.invoke(app, ["check-setup"])
    assert result.exit_code == 0
    assert "ANTHROPIC_API_KEY" in result.stdout
