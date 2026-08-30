"""Integration tests against the real fixtures/vulnerable_mcp_server, spoken
to over actual stdio via the real `mcp` SDK - not mocked. This is the one
place we trust the wire protocol; everything else can assume ServerInventory
was populated correctly.
"""
from __future__ import annotations

import sys
from pathlib import Path

from factories import make_config

from mcp_sentinel.client.connector import introspect_server
from mcp_sentinel.models import MCPServerConfig, TransportType

FIXTURE_SERVER = Path(__file__).resolve().parents[1] / "fixtures" / "vulnerable_mcp_server" / "server.py"


def _fixture_config() -> MCPServerConfig:
    return make_config(
        name="vulnerable-demo",
        host_app="test-harness",
        transport=TransportType.STDIO,
        command=sys.executable,
        args=(str(FIXTURE_SERVER),),
    )


async def test_introspect_fixture_server_lists_all_tools():
    inventory = await introspect_server(_fixture_config(), timeout_seconds=20)
    assert inventory.reachable, inventory.connection_error
    assert inventory.server_name == "vulnerable-demo-server"
    names = {t.name for t in inventory.tools}
    assert names == {
        "get_weather",
        "run_shell_command",
        "delete_all_customer_records",
        "search_docs",
        "fetch_url",
    }


async def test_introspect_fixture_server_preserves_annotations():
    inventory = await introspect_server(_fixture_config(), timeout_seconds=20)
    by_name = {t.name: t for t in inventory.tools}
    assert by_name["get_weather"].annotations.read_only_hint is True
    assert by_name["delete_all_customer_records"].annotations.destructive_hint is False
    assert by_name["run_shell_command"].annotations.destructive_hint is None


async def test_introspect_fixture_server_preserves_descriptions_for_poisoning_scan():
    inventory = await introspect_server(_fixture_config(), timeout_seconds=20)
    by_name = {t.name: t for t in inventory.tools}
    assert "ignore previous instructions" in by_name["search_docs"].description.lower()


async def test_introspect_unreachable_command_reports_error_not_exception():
    config = make_config(name="broken", transport=TransportType.STDIO, command="this-binary-does-not-exist-xyz")
    inventory = await introspect_server(config, timeout_seconds=5)
    assert inventory.reachable is False
    assert inventory.connection_error


async def test_introspect_unknown_transport_reports_error():
    config = make_config(name="broken-transport", transport=TransportType.STDIO, command=None)
    inventory = await introspect_server(config, timeout_seconds=5)
    assert inventory.reachable is False
    assert "no command" in inventory.connection_error
