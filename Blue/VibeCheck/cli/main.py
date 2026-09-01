"""Rich terminal interface for VibeCheck."""
from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from vibecheck.config import settings
from vibecheck.engine import ScanOptions, run_scan
from vibecheck.models import ScanReport, Severity, severity_rank
from vibecheck.report.json_report import report_to_json
from vibecheck.report.markdown_report import render_markdown_report

app = typer.Typer(help="Security reviewer tuned for AI-generated (\"vibe-coded\") code: hallucinated auth checks, copy-pasted insecure patterns, and hallucinated dependencies, plus baseline SAST coverage.")
console = Console()

_SEVERITY_STYLE = {Severity.CRITICAL: "bold red", Severity.HIGH: "red", Severity.MEDIUM: "yellow", Severity.LOW: "cyan", Severity.INFO: "dim"}


def _render_summary(report: ScanReport) -> None:
    table = Table(title=f"VibeCheck — {report.files_scanned} file(s) scanned")
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
        location = f"{finding.file}:{finding.line}" if finding.file else "(project-wide)"
        console.print(f"{tag} [{finding.rule_id}] {location}: {finding.title}")


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), help="Directory to scan."),
    check_deps: bool = typer.Option(False, "--check-deps", help="Check every declared dependency against PyPI/npm for hallucinated ('slopsquatted') packages. Requires network access."),
    llm_judge: bool = typer.Option(False, "--llm-judge", help="Run an optional Claude second-opinion pass on hallucinated-auth findings. Requires ANTHROPIC_API_KEY."),
    out_json: Path | None = typer.Option(None, "--out-json", help="Write the full report as JSON to this path."),
    out_markdown: Path | None = typer.Option(None, "--out-markdown", help="Write the full report as Markdown to this path."),
    fail_on: Severity | None = typer.Option(None, "--fail-on", help="Exit non-zero if any finding at or above this severity is present (critical/high/medium/low/info)."),
) -> None:
    """Scan a directory of Python/JS/TS source for AI-generated-code failure modes."""
    if not path.is_dir():
        console.print(f"[red]Not a directory:[/red] {path}")
        raise typer.Exit(1)

    options = ScanOptions(check_dependencies=check_deps, llm_judge=llm_judge)
    report = run_scan(path, options)

    for w in report.warnings:
        console.print(f"[yellow]warning:[/yellow] {w}")

    _render_summary(report)

    if llm_judge and not settings.has_llm_key:
        console.print("[yellow]ANTHROPIC_API_KEY not set — auth findings were not double-checked by the LLM judge. See README.md.[/yellow]")

    if out_json:
        out_json.write_text(report_to_json(report), encoding="utf-8")
        console.print(f"[green]Wrote JSON report to {out_json}[/green]")
    if out_markdown:
        out_markdown.write_text(render_markdown_report(report), encoding="utf-8")
        console.print(f"[green]Wrote Markdown report to {out_markdown}[/green]")

    if fail_on is not None:
        threshold = severity_rank(fail_on)
        if any(severity_rank(f.severity) <= threshold for f in report.findings):
            raise typer.Exit(2)


@app.command("check-setup")
def check_setup() -> None:
    """Report first-run configuration without failing noisily."""
    console.print(f"ANTHROPIC_API_KEY: {'[green]configured[/green]' if settings.has_llm_key else '[yellow]not configured — --llm-judge will be a no-op (see README.md)[/yellow]'}")
    console.print(f"Model: {settings.anthropic_model}")
    console.print(f"Registry lookup timeout: {settings.registry_timeout_seconds}s")
    console.print(f"Registry cache dir: {settings.cache_dir}")
    console.print(f"Max file size scanned: {settings.max_file_bytes} bytes")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
