"""Integration test: active-probe the real fixtures/vulnerable_mcp_server over
real stdio, and confirm the safety gate + detection both behave as designed.
"""
from __future__ import annotations

import sys

from mcp.client import Client
from mcp.client.stdio import StdioServerParameters

from mcp_sentinel.client.connector import introspect_server
from mcp_sentinel.models import MCPServerConfig, TransportType
from mcp_sentinel.probes.active import run_active_probes
from test_client_connector import FIXTURE_SERVER


def _fixture_config() -> MCPServerConfig:
    return MCPServerConfig(
        server_id="test-harness:vulnerable-demo",
        config_name="vulnerable-demo",
        host_app="test-harness",
        source_config_path="n/a",
        transport=TransportType.STDIO,
        command=sys.executable,
        args=(str(FIXTURE_SERVER),),
    )


async def test_active_probe_flags_fetch_url_injected_response():
    inventory = await introspect_server(_fixture_config(), timeout_seconds=20)
    assert inventory.reachable, inventory.connection_error

    params = StdioServerParameters(command=sys.executable, args=[str(FIXTURE_SERVER)])
    async with Client(server=params, read_timeout_seconds=20) as client:
        findings = await run_active_probes(client, inventory, read_timeout_seconds=20)

    fetch_url_findings = [f for f in findings if f.tool_name == "fetch_url"]
    assert fetch_url_findings, "expected the poisoned fetch_url response to be flagged"
    assert any(f.finding_id.startswith("probe-phrase:") for f in fetch_url_findings)


async def test_active_probe_never_invokes_non_readonly_tools():
    inventory = await introspect_server(_fixture_config(), timeout_seconds=20)
    assert inventory.reachable, inventory.connection_error

    params = StdioServerParameters(command=sys.executable, args=[str(FIXTURE_SERVER)])
    async with Client(server=params, read_timeout_seconds=20) as client:
        findings = await run_active_probes(client, inventory, read_timeout_seconds=20)

    probed_tools = {f.tool_name for f in findings}
    # run_shell_command, delete_all_customer_records, and search_docs are all
    # not annotated read_only_hint=True (or fail the exec-indicator gate), so
    # none of them should ever have been called - any finding naming them
    # would mean the safety gate was bypassed.
    assert "run_shell_command" not in probed_tools
    assert "delete_all_customer_records" not in probed_tools


async def test_active_probe_finds_nothing_on_clean_tool():
    inventory = await introspect_server(_fixture_config(), timeout_seconds=20)
    assert inventory.reachable, inventory.connection_error

    params = StdioServerParameters(command=sys.executable, args=[str(FIXTURE_SERVER)])
    async with Client(server=params, read_timeout_seconds=20) as client:
        findings = await run_active_probes(client, inventory, read_timeout_seconds=20)

    assert not any(f.tool_name == "get_weather" for f in findings)
