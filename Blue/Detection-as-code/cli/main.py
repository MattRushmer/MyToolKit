"""Rich terminal interface for Detection Forge."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from detection_forge.attack.attack_data import validate_attack_tags
from detection_forge.config import ATTACK_STIX_PATH, settings
from detection_forge.export import VALID_TARGETS
from detection_forge.models import GeneratedRule, PipelineResult
from detection_forge.rules.validator import apply_validation

app = typer.Typer(help="Turn CTI into validated, testable detections.")
console = Console()


def _expand_logs(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            for pattern in ("*.json", "*.ndjson", "*.jsonl"):
                files.extend(sorted(path.glob(pattern)))
        elif path.is_file():
            files.append(path)
        else:
            raise typer.BadParameter(f"Log path does not exist: {path}")
    return list(dict.fromkeys(files))


def _rule_panel(rule: GeneratedRule) -> Panel:
    validation = "[green]STRUCTURALLY VALID[/green]" if rule.structurally_valid else "[bold red]STRUCTURAL VALIDATION FAILED[/bold red]"
    details = f"[bold]{rule.title}[/bold]\nID: {rule.sigma_id}\nLevel: "
    try:
        details += str(yaml.safe_load(rule.rule_yaml).get("level", "unspecified"))
    except Exception:
        details += "unspecified"
    details += f"\nATT&CK tags: {', '.join(rule.attack_tags) or 'none'}\n{validation}"
    if rule.structural_errors:
        details += "\n[red]Issues:[/red] " + "; ".join(rule.structural_errors)
    return Panel(details, title="Generated rule", border_style="cyan")


def render_result(result: PipelineResult) -> None:
    rule = result.rule
    console.print(_rule_panel(rule))
    console.print(Panel(rule.rule_yaml, title="Rule YAML", border_style="blue"))
    table = Table(title="ATT&CK tag validation")
    for column in ("Tag", "Technique", "Valid", "Reason"):
        table.add_column(column)
    if rule.attack_validations:
        for item in rule.attack_validations:
            table.add_row(item.tag, item.technique_name or item.technique_id, "[green]Yes[/green]" if item.valid else "[bold red]No[/bold red]", item.reason or "")
    else:
        table.add_row("—", "—", "[bold red]No tags validated[/bold red]", "No ATT&CK technique tags found")
    console.print(table)
    if result.backtest:
        backtest = result.backtest
        console.print(Panel(f"Events scanned: {backtest.total_events_scanned}\nMatches: {backtest.match_count}\nMatch rate: {backtest.match_rate:.2%}", title="Backtest", border_style="magenta"))
        for event in backtest.matched_events[:5]:
            console.print(Panel(json.dumps(event.record, indent=2, default=str), title=f"Match at line {event.line_number} ({', '.join(event.matched_selection_names) or 'selection'})"))
        if backtest.unmapped_fields:
            console.print(f"[yellow]Unmapped fields: {', '.join(backtest.unmapped_fields)}[/yellow]")
        if backtest.parse_errors:
            console.print(Panel(
                "\n".join(backtest.parse_errors),
                title="[bold red]Backtest errors[/bold red] (results above may be incomplete)",
                border_style="red",
            ))
    else:
        console.print("[dim]No log files supplied; backtest was skipped.[/dim]")
    if result.noise:
        colors = {"low": "green", "medium": "yellow", "high": "orange3", "critical": "bold red"}
        noise = result.noise
        factors = "\n".join(f"• {f.name} ({f.score_impact:g}): {f.explanation}" for f in noise.factors) or "• No contributing factors reported"
        console.print(Panel(f"[{colors.get(noise.band, 'white')}]{noise.total_score:.1f}/100 — {noise.band.upper()}[/{colors.get(noise.band, 'white')}]\n{noise.summary}\n{factors}", title="Expected noise", border_style=colors.get(noise.band, "white")))
    for exported in result.exports:
        if exported.warnings:
            console.print(f"[yellow]{exported.target} warnings: {'; '.join(exported.warnings)}[/yellow]")
    verdict = "[bold green]READY TO SHIP[/bold green]" if result.ready_to_ship else "[bold red]NOT READY — see issues above[/bold red]"
    console.print(Panel(verdict, title="Verdict", border_style="green" if result.ready_to_ship else "red"))


def _write_exports(result: PipelineResult, out_dir: Path) -> None:
    for exported in result.exports:
        if exported.target == "error" or not exported.filename:
            console.print(f"[bold red]Export failed, nothing written:[/bold red] {'; '.join(exported.warnings) or 'unknown error'}")
            continue
        path = out_dir / exported.target / exported.filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(exported.content, encoding="utf-8")
        console.print(f"[green]Wrote {exported.target} export:[/green] {path}")


@app.command()
def run(
    cti_file: Path | None = typer.Option(None, "--cti-file"),
    cti_text: str | None = typer.Option(None, "--cti-text"),
    logs: list[Path] = typer.Option([], "--logs"),
    export: list[str] = typer.Option(["sigma"], "--export"),
    out_dir: Path = typer.Option(Path("output"), "--out-dir"),
) -> None:
    """Generate, validate, backtest, score, and export a rule."""
    if cti_file and cti_text:
        raise typer.BadParameter("Use either --cti-file or --cti-text, not both.")
    if cti_file:
        text = cti_file.read_text(encoding="utf-8", errors="replace")
        source = cti_file.name
    elif cti_text:
        text, source = cti_text, "command-line-text"
    elif not sys.stdin.isatty():
        text, source = sys.stdin.read(), "stdin"
    else:
        raise typer.BadParameter("Provide --cti-file or --cti-text (or pipe CTI text to stdin).")
    invalid = set(export) - VALID_TARGETS
    if invalid:
        raise typer.BadParameter(f"Unsupported export target(s): {', '.join(sorted(invalid))}")
    try:
        from detection_forge.pipeline import run_pipeline
        result = run_pipeline(text, source_name=source, log_file_paths=_expand_logs(logs), export_targets=export)
    except Exception as exc:
        from detection_forge.llm.anthropic_client import LLMNotConfiguredError
        if isinstance(exc, LLMNotConfiguredError):
            console.print("[bold red]ANTHROPIC_API_KEY is not configured.[/bold red] Set it as described in README.md, then try again.")
        else:
            console.print(f"[bold red]Pipeline stage failed:[/bold red] {exc}")
        raise typer.Exit(1)
    render_result(result)
    _write_exports(result, out_dir)


@app.command()
def validate(rule_file: Path = typer.Option(..., "--rule-file", exists=True, readable=True)) -> None:
    """Validate a hand-written Sigma rule without an LLM call."""
    rule_yaml = rule_file.read_text(encoding="utf-8", errors="replace")
    try:
        raw = yaml.safe_load(rule_yaml) or {}
        tags = [str(tag) for tag in raw.get("tags", [])]
    except Exception:
        tags = []
    rule = apply_validation(GeneratedRule(rule_yaml=rule_yaml, title="", sigma_id="", attack_tags=tags))
    rule.attack_validations = validate_attack_tags(tags)
    console.print(_rule_panel(rule))
    table = Table(title="ATT&CK tag validation")
    for column in ("Tag", "Technique", "Valid", "Reason"):
        table.add_column(column)
    for item in rule.attack_validations:
        table.add_row(item.tag, item.technique_name or item.technique_id, "Yes" if item.valid else "No", item.reason or "")
    console.print(table)
    if not rule.structurally_valid or any(not x.valid for x in rule.attack_validations):
        raise typer.Exit(1)


@app.command("check-setup")
def check_setup() -> None:
    """Report first-run dependencies without failing noisily."""
    console.print(f"ANTHROPIC_API_KEY: {'[green]configured[/green]' if settings.has_llm_key else '[yellow]not configured (see README.md)[/yellow]'}")
    console.print(f"ATT&CK STIX dataset: {'[green]present[/green]' if ATTACK_STIX_PATH.exists() else '[red]missing[/red]'} ({ATTACK_STIX_PATH})")
    for backend, module in (("splunk", "sigma.backends.splunk"), ("elasticsearch", "sigma.backends.elasticsearch")):
        try:
            __import__(module)
            status = "[green]available[/green]"
        except Exception as exc:
            status = f"[yellow]unavailable: {exc}[/yellow]"
        console.print(f"{backend} exporter: {status}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
