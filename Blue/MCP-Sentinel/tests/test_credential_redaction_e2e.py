"""End-to-end regression test for the CRITICAL finding from the security
review: credential values embedded in a server's stdio launch args or HTTP
url query string must never reach a serialized report, even though the
scanner needs those same values to actually connect. Drives the real engine
against the real fixture server (extra args are harmless - the fixture
server doesn't parse argv) and inspects the actual JSON report text.

FAKE_SECRET below is a synthetic, non-vendor-shaped placeholder (no `sk_live_`/
`AKIA`/etc. prefix) - deliberately, so it can never be mistaken for a real
credential by a human skimming a diff or by an automated secret scanner.
"""
from __future__ import annotations

import json
import sys

from mcp_sentinel.engine import ScanOptions, run_scan
from mcp_sentinel.report.json_report import report_to_json
from test_client_connector import FIXTURE_SERVER

FAKE_SECRET = "NOT-A-REAL-KEY-mcp-sentinel-fake-secret-for-tests-only"


def _write_config_with_secret_arg(tmp_path):
    config_path = tmp_path / "mcp.json"
    config_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "vulnerable-demo": {
                        "command": sys.executable,
                        "args": [str(FIXTURE_SERVER), "--api-key", FAKE_SECRET],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    return config_path


async def test_fake_secret_in_stdio_args_never_reaches_json_report(tmp_path):
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
    assert FAKE_SECRET not in report_json

    # The rule this config is meant to trip must still fire (redaction must
    # not silently swallow the finding along with the secret).
    data = json.loads(report_json)
    assert any(f["finding_id"].startswith("auth-secret-in-args:") for f in data["findings"])


async def test_inline_flag_equals_secret_never_reaches_json_report(tmp_path):
    # The --flag=value form (one array entry) is a distinct code path from
    # --flag value (two entries, covered above) - a round-2 review found the
    # first fix only redacted the two-entry form.
    from mcp_sentinel.discovery.config_locations import ConfigLocation

    config_path = tmp_path / "mcp.json"
    config_path.write_text(
        json.dumps({"mcpServers": {"vulnerable-demo": {"command": sys.executable, "args": [str(FIXTURE_SERVER), f"--api-key={FAKE_SECRET}"]}}}),
        encoding="utf-8",
    )
    options = ScanOptions(active_probes=False, check_drift=False, timeout_seconds=20)
    report, _ = await run_scan([ConfigLocation("test-harness", config_path)], options)

    assert report.inventories[0].reachable, report.inventories[0].connection_error
    report_json = report_to_json(report)
    assert FAKE_SECRET not in report_json
    data = json.loads(report_json)
    assert any(f["finding_id"].startswith("auth-secret-in-args:") for f in data["findings"])


async def test_fake_secret_in_url_query_param_never_reaches_json_report(tmp_path):
    # Points at a closed localhost port (immediate, fast ConnectionRefusedError)
    # rather than a real external domain: a round-2 review found the original
    # version of this test made a genuine outbound DNS/TCP/TLS attempt to
    # mcp.example.com, adding multi-second/timing-variable latency (and, once,
    # a 120s+ stall) with no benefit - the assertion only cares about
    # redaction, never about whether the connection actually succeeds.
    from mcp_sentinel.discovery.config_locations import ConfigLocation

    config_path = tmp_path / "mcp.json"
    config_path.write_text(
        json.dumps({"mcpServers": {"billing": {"url": f"http://127.0.0.1:1/mcp?token={FAKE_SECRET}", "type": "http"}}}),
        encoding="utf-8",
    )
    options = ScanOptions(active_probes=False, check_drift=False, timeout_seconds=5)
    report, _ = await run_scan([ConfigLocation("test-harness", config_path)], options)

    report_json = report_to_json(report)
    assert FAKE_SECRET not in report_json
