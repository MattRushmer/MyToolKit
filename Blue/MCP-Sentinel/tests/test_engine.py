"""End-to-end engine tests against the real fixtures/vulnerable_mcp_server,
driven through a real on-disk config file exactly like a real scan would be.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from mcp_sentinel.discovery.config_locations import ConfigLocation
from mcp_sentinel.engine import ScanOptions, run_scan
from test_client_connector import FIXTURE_SERVER


def _write_config(tmp_path: Path) -> ConfigLocation:
    config_path = tmp_path / "mcp.json"
    config_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "vulnerable-demo": {
                        "command": sys.executable,
                        "args": [str(FIXTURE_SERVER)],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    return ConfigLocation("test-harness", config_path)


async def test_run_scan_finds_known_issues_statically(tmp_path):
    location = _write_config(tmp_path)
    options = ScanOptions(active_probes=False, check_drift=False, timeout_seconds=20)
    report, warnings = await run_scan([location], options)

    assert warnings == []
    assert report.total_servers == 1
    assert report.total_tools == 5
    assert report.active_probes_run is False

    finding_ids = {f.finding_id for f in report.findings}
    assert any(fid.startswith("priv-exec:") for fid in finding_ids)
    assert any(fid.startswith("priv-mismatch:") for fid in finding_ids)
    assert any(fid.startswith("poison-phrase:") for fid in finding_ids)
    # Active probing was off, so the live-response finding must not appear.
    assert not any(fid.startswith("probe-") for fid in finding_ids)


async def test_run_scan_with_active_probes_flags_fetch_url(tmp_path):
    location = _write_config(tmp_path)
    options = ScanOptions(active_probes=True, check_drift=False, timeout_seconds=20)
    report, _ = await run_scan([location], options)

    assert report.active_probes_run is True
    probe_findings = [f for f in report.findings if f.finding_id.startswith("probe-")]
    assert any(f.tool_name == "fetch_url" for f in probe_findings)


async def test_run_scan_persists_and_reuses_baseline(tmp_path):
    location = _write_config(tmp_path)
    state_dir = tmp_path / "state"
    options = ScanOptions(active_probes=False, check_drift=True, save_baseline=True, timeout_seconds=20, state_dir=state_dir)

    first_report, _ = await run_scan([location], options)
    assert not any(f.category.value == "config_drift" for f in first_report.findings)
    assert (state_dir / "baseline.json").is_file()

    second_report, _ = await run_scan([location], options)
    assert not any(f.category.value == "config_drift" for f in second_report.findings)


async def test_run_scan_reports_unreachable_server_without_crashing(tmp_path):
    config_path = tmp_path / "mcp.json"
    config_path.write_text(
        json.dumps({"mcpServers": {"broken": {"command": "this-binary-does-not-exist-xyz"}}}),
        encoding="utf-8",
    )
    location = ConfigLocation("test-harness", config_path)
    options = ScanOptions(active_probes=True, check_drift=True, timeout_seconds=5, state_dir=tmp_path / "state")

    report, warnings = await run_scan([location], options)
    assert warnings == []
    assert report.total_servers == 1
    assert any(f.category.value == "unreachable_server" for f in report.findings)


async def test_run_scan_surfaces_config_parse_warnings(tmp_path):
    config_path = tmp_path / "mcp.json"
    config_path.write_text("{not valid json", encoding="utf-8")
    location = ConfigLocation("test-harness", config_path)
    report, warnings = await run_scan([location], ScanOptions(check_drift=False))
    assert report.total_servers == 0
    assert any("invalid JSON" in w for w in warnings)
