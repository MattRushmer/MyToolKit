"""End-to-end regression test for the CRITICAL finding from the security
review: real credential values embedded in a server's stdio launch args or
HTTP url query string must never reach a serialized report, even though the
scanner needs those same real values to actually connect. Drives the real
engine against the real fixture server (extra args are harmless - the
fixture server doesn't parse argv) and inspects the actual JSON report text.
"""
from __future__ import annotations

import json
import sys

from mcp_sentinel.engine import ScanOptions, run_scan
from mcp_sentinel.report.json_report import report_to_json
from test_client_connector import FIXTURE_SERVER

REAL_SECRET = "sk_live_51H8x9zK2REALSECRETVALUE9999"


def _write_config_with_secret_arg(tmp_path):
    config_path = tmp_path / "mcp.json"
    config_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "vulnerable-demo": {
                        "command": sys.executable,
                        "args": [str(FIXTURE_SERVER), "--api-key", REAL_SECRET],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    return config_path


async def test_real_secret_in_stdio_args_never_reaches_json_report(tmp_path):
    from mcp_sentinel.discovery.config_locations import ConfigLocation

    config_path = _write_config_with_secret_arg(tmp_path)
    options = ScanOptions(active_probes=False, check_drift=False, timeout_seconds=20)
    report, warnings = await run_scan([ConfigLocation("test-harness", config_path)], options)

    assert warnings == []
    # The connection must still have actually worked using the real secret-
    # bearing args (the fixture server ignores argv, so a real MCP server
    # that *needed* --api-key to authenticate upstream would behave the same).
    assert report.total_servers == 1
    assert report.inventories[0].reachable, report.inventories[0].connection_error
    assert report.total_tools == 5

    report_json = report_to_json(report)
    assert REAL_SECRET not in report_json

    # The rule this config is meant to trip must still fire (redaction must
    # not silently swallow the finding along with the secret).
    data = json.loads(report_json)
    assert any(f["finding_id"].startswith("auth-secret-in-args:") for f in data["findings"])


async def test_real_secret_in_url_query_param_never_reaches_json_report(tmp_path):
    from mcp_sentinel.discovery.config_locations import ConfigLocation

    config_path = tmp_path / "mcp.json"
    config_path.write_text(
        json.dumps({"mcpServers": {"billing": {"url": f"https://mcp.example.com/mcp?token={REAL_SECRET}", "type": "http"}}}),
        encoding="utf-8",
    )
    options = ScanOptions(active_probes=False, check_drift=False, timeout_seconds=5)
    report, _ = await run_scan([ConfigLocation("test-harness", config_path)], options)

    report_json = report_to_json(report)
    assert REAL_SECRET not in report_json
