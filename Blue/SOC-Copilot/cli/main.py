"""Rich terminal interface for SOC Copilot."""
from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from soc_copilot.config import settings
from soc_copilot.economics.cost import cost_summary
from soc_copilot.economics.pricing import suggest_pricing
from soc_copilot.ingest.adapters import ADAPTERS
from soc_copilot.models import Client, PipelineResult
from soc_copilot.pipeline import ingest_files, run_pipeline
from soc_copilot.report.digest import render_client_digest

app = typer.Typer(help="Correlate MSP alert exports into triaged, ticket-ready incidents.")
console = Console()

_PRIORITY_STYLE = {"P1": "bold red", "P2": "orange3", "P3": "yellow", "P4": "dim"}


def _parse_alert_specs(alerts: list[str]) -> list[tuple[Path, str]]:
    specs: list[tuple[Path, str]] = []
    for entry in alerts:
        if ":" in entry:
            path_part, source = entry.rsplit(":", 1)
        else:
            path_part, source = entry, "generic"
        path = Path(path_part)
        if not path.exists():
            raise typer.BadParameter(f"Alert file does not exist: {path}")
        if source.lower() not in ADAPTERS:
            raise typer.BadParameter(f"Unknown source adapter '{source}'. Available: {', '.join(sorted(ADAPTERS))}")
        specs.append((path, source.lower()))
    return specs


def render_queue(result: PipelineResult) -> None:
    table = Table(title=f"Incident queue — {result.client.name}")
    for column in ("Priority", "Severity", "Host/User", "Verdict", "Confidence", "Summary"):
        table.add_column(column)
    for r in result.incidents:
        t = r.triage
        style = _PRIORITY_STYLE.get(t.suggested_priority.value, "")
        table.add_row(
            f"[{style}]{t.suggested_priority.value}[/{style}]" if style else t.suggested_priority.value,
            t.severity.value,
            r.incident.host or r.incident.user or "—",
            t.verdict.value,
            f"{t.confidence}%",
            t.summary[:80] + ("…" if len(t.summary) > 80 else ""),
        )
    console.print(table)
    summary = cost_summary(result)
    console.print(
        Panel(
            f"Alerts ingested: {result.total_alerts_ingested}  |  Incidents: {len(result.incidents)}  |  "
            f"Flagged for review: {result.needs_review_count}\n"
            f"LLM-triaged: {summary['incidents_llm_triaged']}  |  Heuristic-only: {summary['incidents_heuristic_only']}\n"
            f"Estimated cost: ${summary['total_cost_usd']:.4f} "
            f"({summary['total_input_tokens']} in / {summary['total_output_tokens']} out tokens)",
            title="Run summary",
            border_style="cyan",
        )
    )
    if not settings.has_llm_key:
        console.print("[yellow]ANTHROPIC_API_KEY not set — all verdicts above are heuristic fallback, not real triage. See README.md.[/yellow]")


def _write_outputs(result: PipelineResult, out_dir: Path, period_label: str) -> None:
    tickets_dir = out_dir / "tickets"
    tickets_dir.mkdir(parents=True, exist_ok=True)
    for r in result.incidents:
        path = tickets_dir / f"{r.incident.incident_id}.md"
        path.write_text(r.ticket_note_markdown, encoding="utf-8")
    digest_path = out_dir / "digest.md"
    digest_path.write_text(render_client_digest(result, period_label), encoding="utf-8")
    console.print(f"[green]Wrote {len(result.incidents)} ticket note(s) to {tickets_dir} and a digest to {digest_path}[/green]")


@app.command()
def run(
    client_id: str = typer.Option(..., "--client-id"),
    client_name: str = typer.Option(..., "--client-name"),
    tier: str = typer.Option("standard", "--tier", help="standard | high | crown_jewel"),
    alerts: list[str] = typer.Option(..., "--alerts", help="path[:source] — source is one of: " + ", ".join(sorted(ADAPTERS)) + " (default generic). Repeatable."),
    window: int = typer.Option(None, "--window", help="Correlation window in minutes (default from config)."),
    out_dir: Path = typer.Option(Path("output"), "--out-dir"),
    period_label: str = typer.Option("This period", "--period-label"),
) -> None:
    """Ingest one or more alert exports for a client, correlate, triage, and write ticket notes + a digest."""
    specs = _parse_alert_specs(alerts)
    client = Client(client_id=client_id, name=client_name, criticality_tier=tier)
    loaded_alerts, warnings = ingest_files(specs, client_id)
    for w in warnings:
        console.print(f"[yellow]ingest warning:[/yellow] {w}")
    if not loaded_alerts:
        console.print("[bold red]No alerts were successfully parsed from the given files.[/bold red]")
        raise typer.Exit(1)
    result = run_pipeline(loaded_alerts, client, correlation_window_minutes=window)
    render_queue(result)
    _write_outputs(result, out_dir, period_label)


@app.command("check-setup")
def check_setup() -> None:
    """Report first-run configuration without failing noisily."""
    console.print(f"ANTHROPIC_API_KEY: {'[green]configured[/green]' if settings.has_llm_key else '[yellow]not configured — triage will use the heuristic fallback (see README.md)[/yellow]'}")
    console.print(f"Model: {settings.anthropic_model}")
    console.print(f"Correlation window: {settings.correlation_window_minutes} minutes")
    console.print(f"Cost rates: ${settings.cost_per_1m_input}/1M input tokens, ${settings.cost_per_1m_output}/1M output tokens")
    console.print(f"Known source adapters: {', '.join(sorted(ADAPTERS))}")


@app.command()
def pricing(
    endpoints: int = typer.Option(..., "--endpoints", help="Total endpoints across the client(s) this pricing covers."),
) -> None:
    """Illustrative MSP-scaled pricing suggestion — edit soc_copilot/economics/pricing.py for your own costs."""
    suggestion = suggest_pricing(endpoints)
    console.print(
        Panel(
            f"Tier: {suggestion.tier_name}\n"
            f"Endpoints: {suggestion.endpoint_count}\n"
            f"Suggested: ${suggestion.monthly_price_low:,.2f} – ${suggestion.monthly_price_high:,.2f} / month\n"
            f"(${suggestion.price_per_endpoint_low:.2f} – ${suggestion.price_per_endpoint_high:.2f} per endpoint / month)\n\n"
            f"[dim]{suggestion.notes}[/dim]",
            title="Pricing suggestion",
            border_style="cyan",
        )
    )


def main() -> None:
    app()


if __name__ == "__main__":
    main()
