import json
import sys

from test_client_connector import FIXTURE_SERVER
from typer.testing import CliRunner

from cli.main import app

runner = CliRunner()


def _write_config(tmp_path):
    config_path = tmp_path / "mcp.json"
    config_path.write_text(
        json.dumps({"mcpServers": {"vulnerable-demo": {"command": sys.executable, "args": [str(FIXTURE_SERVER)]}}}),
        encoding="utf-8",
    )
    return config_path


def test_check_setup_runs_without_error():
    result = runner.invoke(app, ["check-setup"])
    assert result.exit_code == 0
    assert "ANTHROPIC_API_KEY" in result.stdout


def test_list_configs_runs_without_error():
    result = runner.invoke(app, ["list-configs"])
    assert result.exit_code == 0
    assert "claude-desktop" in result.stdout


def test_scan_with_no_configs_found_exits_nonzero(tmp_path, monkeypatch):
    # existing_config_locations() also checks the real user-home/APPDATA agent-host
    # locations (Claude Desktop, Claude Code, Cursor, ...), which can genuinely exist
    # on a dev machine - isolate both so "no configs" is actually true here.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    monkeypatch.setenv("APPDATA", str(tmp_path / "AppData"))
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 1
    assert "No MCP client config files found" in result.stdout


def test_scan_with_nonexistent_explicit_config_errors_instead_of_reporting_clean(tmp_path):
    # A typo'd --config path must not be indistinguishable from "scanned zero
    # servers, all clean" (exit 0) - that would silently defeat --fail-on in CI.
    missing_path = tmp_path / "does-not-exist.json"
    result = runner.invoke(app, ["scan", "--config", str(missing_path)])
    assert result.exit_code == 1
    assert "Config file not found" in result.stdout
    # Rich can hard-wrap a long path across lines at the test runner's terminal
    # width, so compare with those wraps stripped out rather than as one substring.
    assert str(missing_path) in result.stdout.replace("\n", "")


def test_scan_against_explicit_config_reports_findings(tmp_path):
    config_path = _write_config(tmp_path)
    result = runner.invoke(app, ["scan", "--config", str(config_path), "--no-drift"])
    assert result.exit_code == 0
    assert "MCP Sentinel" in result.stdout
    assert "CRITICAL" in result.stdout or "HIGH" in result.stdout


def test_scan_writes_json_and_markdown_reports(tmp_path):
    config_path = _write_config(tmp_path)
    json_out = tmp_path / "report.json"
    md_out = tmp_path / "report.md"
    result = runner.invoke(
        app,
        ["scan", "--config", str(config_path), "--no-drift", "--out-json", str(json_out), "--out-markdown", str(md_out)],
    )
    assert result.exit_code == 0
    assert json_out.is_file()
    assert md_out.is_file()
    data = json.loads(json_out.read_text(encoding="utf-8"))
    assert data["summary"]["total_servers"] == 1


def test_scan_fail_on_severity_exits_nonzero(tmp_path):
    config_path = _write_config(tmp_path)
    result = runner.invoke(app, ["scan", "--config", str(config_path), "--no-drift", "--fail-on", "high"])
    assert result.exit_code == 2


def test_scan_fail_on_critical_only_when_no_critical_findings(tmp_path):
    # The fixture server has a CRITICAL poisoning finding, so even the strictest
    # threshold should still trip - this asserts the flag actually gates exit code.
    config_path = _write_config(tmp_path)
    result = runner.invoke(app, ["scan", "--config", str(config_path), "--no-drift", "--fail-on", "critical"])
    assert result.exit_code == 2
