"""Top-level orchestration: discover configs -> connect & introspect -> run
static rules -> optionally run active probes -> optionally check baseline
drift -> assemble one ScanReport.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from mcp.client import Client

from mcp_sentinel.client.connector import introspect_server
from mcp_sentinel.config import settings
from mcp_sentinel.discovery.config_locations import ConfigLocation, existing_config_locations
from mcp_sentinel.discovery.parser import extract_raw_entries, load_config_files
from mcp_sentinel.models import Finding, MCPServerConfig, ScanReport, ServerInventory
from mcp_sentinel.probes.active import run_active_probes
from mcp_sentinel.rules import auth, baseline, poisoning, privilege


@dataclass(frozen=True)
class ScanOptions:
    active_probes: bool = False
    check_drift: bool = True
    save_baseline: bool = True
    timeout_seconds: float = field(default_factory=lambda: settings.timeout_seconds)
    state_dir: Path = field(default_factory=lambda: Path(settings.state_dir))


def _connection_secrets(server: MCPServerConfig, raw_entries_by_path: dict[str, dict]) -> tuple[dict[str, str] | None, dict[str, str] | None]:
    raw = raw_entries_by_path.get(server.source_config_path, {}).get(server.config_name, {})
    env = raw.get("env") if isinstance(raw.get("env"), dict) else None
    headers = raw.get("headers") if isinstance(raw.get("headers"), dict) else None
    return env, headers


async def _probe_inventory(inventory: ServerInventory, env: dict[str, str] | None, headers: dict[str, str] | None, timeout_seconds: float) -> list[Finding]:
    from mcp_sentinel.client.connector import build_transport

    try:
        transport = build_transport(inventory.config, headers, env)
        async with Client(server=transport, read_timeout_seconds=timeout_seconds) as client:
            return await run_active_probes(client, inventory, read_timeout_seconds=timeout_seconds)
    except Exception:  # noqa: BLE001 - a probing-connection failure must not sink the whole scan; the server's static findings still stand
        return []


async def run_scan(locations: list[ConfigLocation] | None = None, options: ScanOptions | None = None) -> tuple[ScanReport, list[str]]:
    """Run one full scan. Returns (report, warnings) - warnings are non-fatal
    problems encountered while parsing config files (see discovery/parser.py)."""
    options = options or ScanOptions()
    locations = locations if locations is not None else existing_config_locations()

    servers, warnings = load_config_files(locations)
    raw_entries_by_path: dict[str, dict] = {str(loc.path): extract_raw_entries(loc) for loc in locations}

    report = ScanReport(active_probes_run=options.active_probes)
    previous_baseline = baseline.load_baseline(options.state_dir) if options.check_drift else {}

    for server in servers:
        env, headers = _connection_secrets(server, raw_entries_by_path)
        inventory = await introspect_server(server, headers=headers, env=env, timeout_seconds=options.timeout_seconds)
        report.inventories.append(inventory)

        report.findings.extend(auth.check_transport_auth(server))

        if not inventory.reachable:
            report.findings.append(_unreachable_finding(inventory))
            continue

        report.findings.extend(privilege.check_server_privileges(inventory))
        report.findings.extend(poisoning.check_server_poisoning(inventory))
        if options.check_drift:
            report.findings.extend(baseline.check_drift(inventory, previous_baseline))
        if options.active_probes:
            report.findings.extend(await _probe_inventory(inventory, env, headers, options.timeout_seconds))

    if options.check_drift and options.save_baseline:
        baseline.save_baseline(options.state_dir, baseline.build_baseline(report.inventories))

    return report, warnings


def _unreachable_finding(inventory: ServerInventory) -> Finding:
    from mcp_sentinel.models import RiskCategory, Severity

    return Finding(
        finding_id=f"unreachable:{inventory.config.server_id}",
        severity=Severity.MEDIUM,
        category=RiskCategory.UNREACHABLE_SERVER,
        title=f"Server '{inventory.config.config_name}' is configured but was not reachable",
        description=f"Connecting to server '{inventory.config.server_id}' failed: {inventory.connection_error}",
        server_id=inventory.config.server_id,
        evidence={"connection_error": inventory.connection_error},
        recommendation="Confirm the server is running and reachable, or remove the grant if it's stale (a stale grant is itself attack surface - see OWASP MCP09 Shadow MCP Servers).",
        references=(),
    )
