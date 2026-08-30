"""Rich terminal interface for MCP Sentinel."""
from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from mcp_sentinel.config import settings
from mcp_sentinel.discovery.config_locations import ConfigLocation, existing_config_locations, known_config_locations
from mcp_sentinel.engine import ScanOptions, run_scan
from mcp_sentinel.models import ScanReport, Severity
from mcp_sentinel.report.json_report import report_to_json
from mcp_sentinel.report.markdown_report import render_markdown_report

app = typer.Typer(help="Inventory MCP servers and agent tool-grants; flag over-privileged, unauthenticated, and poisoned tools.")
console = Console()

_SEVERITY_STYLE = {Severity.CRITICAL: "bold red", Severity.HIGH: "red", Severity.MEDIUM: "yellow", Severity.LOW: "cyan", Severity.INFO: "dim"}


@app.command("list-configs")
def list_configs() -> None:
    """Show every known agent-host config location and whether it exists on this machine."""
    table = Table(title="MCP client config locations")
    for column in ("Host app", "Path", "Found"):
        table.add_column(column)
    for loc in known_config_locations():
        found = "[green]yes[/green]" if loc.path.is_file() else "[dim]no[/dim]"
        table.add_row(loc.host_app, str(loc.path), found)
    console.print(table)


def _render_summary(report: ScanReport) -> None:
    table = Table(title=f"MCP Sentinel — {report.total_servers} server(s), {report.total_tools} tool(s)")
    for column in ("Severity", "Count"):
        table.add_column(column)
    for sev, count in report.counts_by_severity.items():
        style = _SEVERITY_STYLE.get(sev, "")
        label = f"[{style}]{sev.value.upper()}[/{style}]" if style else sev.value.upper()
        table.add_row(label, str(count))
    console.print(table)

    for finding in report.findings_sorted():
        style = _SEVERITY_STYLE.get(finding.severity, "")
        tag = f"[{style}]{finding.severity.value.upper()}[/{style}]" if style else finding.severity.value.upper()
        tool_part = f" (tool: {finding.tool_name})" if finding.tool_name else ""
        console.print(f"{tag} {finding.server_id}{tool_part}: {finding.title}")


@app.command()
def scan(
    config: list[str] = typer.Option([], "--config", help="Path to a specific MCP config file to scan (repeatable). Defaults to auto-discovering known agent-host locations."),
    active: bool = typer.Option(False, "--active", help="Actively invoke read-only tools and scan their real responses for injection (see README's safety model)."),
    no_drift: bool = typer.Option(False, "--no-drift", help="Skip baseline drift/rug-pull comparison against the previous scan."),
    timeout: float | None = typer.Option(None, "--timeout", help="Per-server connection timeout in seconds (default from config)."),
    out_json: Path | None = typer.Option(None, "--out-json", help="Write the full report as JSON to this path."),
    out_markdown: Path | None = typer.Option(None, "--out-markdown", help="Write the full report as Markdown to this path."),
    fail_on: Severity | None = typer.Option(None, "--fail-on", help="Exit non-zero if any finding at or above this severity is present (critical/high/medium/low/info)."),
) -> None:
    """Scan MCP servers: discover configs, connect, inventory tools, and flag risks."""
    if config:
        missing = [p for p in config if not Path(p).is_file()]
        if missing:
            for p in missing:
                console.print(f"[red]Config file not found:[/red] {p}")
            raise typer.Exit(1)
        locations = [ConfigLocation("manual", Path(p)) for p in config]
    else:
        locations = existing_config_locations()
        if not locations:
            console.print("[yellow]No MCP client config files found. Pass --config to point at one explicitly, or run 'list-configs' to see known locations.[/yellow]")
            raise typer.Exit(1)

    options = ScanOptions(active_probes=active, check_drift=not no_drift, timeout_seconds=timeout or settings.timeout_seconds)
    report, warnings = asyncio.run(run_scan(locations, options))

    for w in warnings:
        console.print(f"[yellow]config warning:[/yellow] {w}")

    _render_summary(report)

    if not settings.has_llm_key and active:
        console.print("[yellow]ANTHROPIC_API_KEY not set — active-probe analysis used heuristics only, no LLM judge pass. See README.md.[/yellow]")

    if out_json:
        out_json.write_text(report_to_json(report), encoding="utf-8")
        console.print(f"[green]Wrote JSON report to {out_json}[/green]")
    if out_markdown:
        out_markdown.write_text(render_markdown_report(report), encoding="utf-8")
        console.print(f"[green]Wrote Markdown report to {out_markdown}[/green]")

    if fail_on is not None:
        from mcp_sentinel.models import severity_rank

        threshold = severity_rank(fail_on)
        if any(severity_rank(f.severity) <= threshold for f in report.findings):
            raise typer.Exit(2)


@app.command("check-setup")
def check_setup() -> None:
    """Report first-run configuration without failing noisily."""
    console.print(f"ANTHROPIC_API_KEY: {'[green]configured[/green]' if settings.has_llm_key else '[yellow]not configured — active-probe analysis will use heuristics only (see README.md)[/yellow]'}")
    console.print(f"Model: {settings.anthropic_model}")
    console.print(f"Timeout per request: {settings.timeout_seconds}s")
    console.print(f"State dir (baselines): {settings.state_dir}")
    found = [loc for loc in known_config_locations() if loc.path.is_file()]
    console.print(f"Known agent-host configs found on this machine: {len(found)} (run 'list-configs' for details)")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
