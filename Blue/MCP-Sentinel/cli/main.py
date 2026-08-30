"""Rich terminal interface for MCP Sentinel. Fleshed out once the scan engine lands."""
from __future__ import annotations

import typer
from rich.console import Console

from mcp_sentinel.config import settings

app = typer.Typer(help="Inventory MCP servers and agent tool-grants; flag over-privileged, unauthenticated, and poisoned tools.")
console = Console()


@app.command("check-setup")
def check_setup() -> None:
    """Report first-run configuration without failing noisily."""
    console.print(f"ANTHROPIC_API_KEY: {'[green]configured[/green]' if settings.has_llm_key else '[yellow]not configured — injection-probe analysis will use heuristics only (see README.md)[/yellow]'}")
    console.print(f"Model: {settings.anthropic_model}")
    console.print(f"Timeout per request: {settings.timeout_seconds}s")
    console.print(f"State dir (baselines): {settings.state_dir}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
