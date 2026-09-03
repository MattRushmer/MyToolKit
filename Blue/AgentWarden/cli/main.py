"""Rich terminal interface for AgentWarden."""
from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from agentwarden.clock import SystemClock
from agentwarden.config import settings
from agentwarden.ids import new_id
from agentwarden.models import Severity, severity_rank
from agentwarden.report.json_report import render_audit_events_json, render_blast_radius_json
from agentwarden.report.markdown_report import render_audit_events_markdown, render_blast_radius_markdown
from agentwarden.store import audit as audit_store
from agentwarden.store import calls as calls_store
from agentwarden.store import grants as grants_store
from agentwarden.store import sessions as sessions_store
from agentwarden.store.connection import Store

app = typer.Typer(help="Runtime credential broker and policy engine for AI-agent-held credentials over MCP.")
console = Console()

_SEVERITY_STYLE = {Severity.CRITICAL: "bold red", Severity.HIGH: "red", Severity.MEDIUM: "yellow", Severity.LOW: "cyan", Severity.INFO: "dim"}


def _run(coro):
    return asyncio.run(coro)


@app.command("check-setup")
def check_setup() -> None:
    """Report first-run configuration without failing noisily."""
    console.print(f"ANTHROPIC_API_KEY: {'[green]configured[/green]' if settings.has_llm_key else '[yellow]not configured — task review will be a no-op (see README.md)[/yellow]'}")
    console.print(f"Model: {settings.anthropic_model}")
    console.print(f"State dir: {settings.state_dir}")
    console.print(f"Default grant TTL: {settings.default_ttl_seconds}s")
    console.print(f"Default blast-radius ceiling: {settings.blast_radius_ceiling} distinct upstream(s)")


@app.command()
def demo(
    out_json: Path | None = typer.Option(None, "--out-json", help="Write the demo's audit report as JSON to this path."),
    out_markdown: Path | None = typer.Option(None, "--out-markdown", help="Write the demo's audit report as Markdown to this path."),
) -> None:
    """Run the scripted fixtures/demo_scenario.py end-to-end against three
    in-memory demo MCP servers, and print what AgentWarden allowed, denied,
    and flagged."""
    from fixtures.demo_scenario import build_demo_proxy, run_demo_scenario

    async def _go():
        # Fresh every run: the demo uses fixed session/task ids so the walkthrough
        # output is stable and readable, so a stale DB from a prior run would
        # otherwise accumulate call history under those same ids and skew the
        # blast-radius counts on every subsequent run.
        db_path = Path(settings.state_dir) / "demo.db"
        db_path.unlink(missing_ok=True)
        store = Store(db_path)
        await store.open()
        proxy, pool = await build_demo_proxy(store)
        try:
            result = await run_demo_scenario(proxy)
        finally:
            await pool.stop()

        table = Table(title="AgentWarden demo scenario")
        for column in ("Step", "Tool", "Result"):
            table.add_column(column)
        for s in result.steps:
            style = "red" if s.is_error else "green"
            table.add_row(s.description, f"{s.tool_name}@{s.upstream}", f"[{style}]{s.result_text}[/{style}]")
        console.print(table)

        events = await audit_store.list_events(store)
        console.print(f"\n[bold]{len(events)} audit event(s) recorded.[/bold] Severity breakdown:")
        counts: dict[Severity, int] = {sev: 0 for sev in Severity}
        for e in events:
            counts[e.severity] += 1
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
            if counts[sev]:
                style = _SEVERITY_STYLE[sev]
                console.print(f"  [{style}]{sev.value.upper()}[/{style}]: {counts[sev]}")

        if out_json:
            out_json.write_text(render_audit_events_json(events), encoding="utf-8")
            console.print(f"[green]Wrote JSON audit report to {out_json}[/green]")
        if out_markdown:
            out_markdown.write_text(render_audit_events_markdown(events), encoding="utf-8")
            console.print(f"[green]Wrote Markdown audit report to {out_markdown}[/green]")

        console.print(f"\nRun `agentwarden blast-radius --task {result.task_id} --db {db_path}` to see the full blast-radius report.")
        await store.close()

    _run(_go())


@app.command()
def audit(
    db: Path = typer.Option(..., "--db", help="Path to the AgentWarden SQLite state file."),
    session: str | None = typer.Option(None, "--session", help="Filter to one session."),
    min_severity: Severity | None = typer.Option(None, "--min-severity", help="Only show findings at or above this severity."),
    out_json: Path | None = typer.Option(None, "--out-json"),
    out_markdown: Path | None = typer.Option(None, "--out-markdown"),
) -> None:
    """Show the audit event log."""
    async def _go():
        store = Store(db)
        await store.open()
        events = await audit_store.list_events(store, session_id=session, min_severity=min_severity)
        for e in sorted(events, key=lambda e: (severity_rank(e.severity), e.seq)):
            style = _SEVERITY_STYLE[e.severity]
            console.print(f"[{style}]{e.severity.value.upper()}[/{style}] [{e.event_type.value}] session={e.session_id} task={e.task_id} tool={e.tool_name or '-'}")
        if out_json:
            out_json.write_text(render_audit_events_json(events), encoding="utf-8")
            console.print(f"[green]Wrote {out_json}[/green]")
        if out_markdown:
            out_markdown.write_text(render_audit_events_markdown(events), encoding="utf-8")
            console.print(f"[green]Wrote {out_markdown}[/green]")
        await store.close()

    _run(_go())


@app.command("blast-radius")
def blast_radius_cmd(
    db: Path = typer.Option(..., "--db"),
    task: str | None = typer.Option(None, "--task"),
    session: str | None = typer.Option(None, "--session", help="Resolve to this session's task."),
    ceiling: int = typer.Option(None, "--ceiling", help="Override the ceiling used to compute 'exceeded' (defaults to config)."),
    out_json: Path | None = typer.Option(None, "--out-json"),
    out_markdown: Path | None = typer.Option(None, "--out-markdown"),
) -> None:
    """Compute and show a task's blast-radius report."""
    from agentwarden.analysis.blast_radius import compute_blast_radius

    if task is None and session is None:
        console.print("[red]Pass --task or --session.[/red]")
        raise typer.Exit(1)

    async def _go():
        store = Store(db)
        await store.open()
        task_id = task
        if task_id is None:
            s = await sessions_store.get_session(store, session)
            if s is None:
                console.print(f"[red]No such session: {session}[/red]")
                raise typer.Exit(1)
            task_id = s.task_id
        report = await compute_blast_radius(store, task_id, ceiling or settings.blast_radius_ceiling, SystemClock())
        console.print(render_blast_radius_markdown(report))
        if out_json:
            out_json.write_text(render_blast_radius_json(report), encoding="utf-8")
        if out_markdown:
            out_markdown.write_text(render_blast_radius_markdown(report), encoding="utf-8")
        await store.close()
        if report.exceeded:
            raise typer.Exit(2)

    _run(_go())


@app.command("list-sessions")
def list_sessions(db: Path = typer.Option(..., "--db"), active_only: bool = typer.Option(False, "--active")) -> None:
    """List sessions."""
    async def _go():
        store = Store(db)
        await store.open()
        sessions = await sessions_store.list_active_sessions(store) if active_only else []
        if not active_only:
            def _all(conn):
                return conn.execute("SELECT session_id FROM sessions").fetchall()
            rows = await store.run(_all)
            sessions = [await sessions_store.get_session(store, r["session_id"]) for r in rows]
        table = Table(title="AgentWarden sessions")
        for column in ("Session", "Task", "Parent", "Status", "Started"):
            table.add_column(column)
        for s in sessions:
            if s is None:
                continue
            table.add_row(s.session_id, s.task_id, s.parent_session_id or "-", s.status.value, s.started_at.isoformat())
        console.print(table)
        await store.close()

    _run(_go())


@app.command()
def grants(db: Path = typer.Option(..., "--db"), session: str = typer.Option(..., "--session")) -> None:
    """Show every grant minted for one session."""
    async def _go():
        store = Store(db)
        await store.open()
        table = Table(title=f"Grants for session {session}")
        for column in ("Tool", "Upstream", "Status", "Issued", "Expires"):
            table.add_column(column)
        for g in await grants_store.list_grants_for_session(store, session):
            table.add_row(g.tool_name, g.upstream_server_id, g.status.value, g.issued_at.isoformat(), g.expires_at.isoformat())
        console.print(table)
        await store.close()

    _run(_go())


@app.command()
def revoke(
    db: Path = typer.Option(..., "--db"),
    session: str | None = typer.Option(None, "--session"),
    grant: str | None = typer.Option(None, "--grant"),
) -> None:
    """Revoke a specific grant, or every active/in-flight grant for a session."""
    if not session and not grant:
        console.print("[red]Pass --session or --grant.[/red]")
        raise typer.Exit(1)

    async def _go():
        store = Store(db)
        await store.open()
        if grant:
            ok = await grants_store.revoke_grant(store, grant)
            console.print(f"[green]Revoked[/green]" if ok else "[yellow]Nothing to revoke (already terminal, or unknown grant id).[/yellow]")
        else:
            count = await grants_store.revoke_session_grants(store, session)
            console.print(f"[green]Revoked {count} grant(s) for session {session}.[/green]")
        await store.close()

    _run(_go())


@app.command("review-task")
def review_task_cmd(db: Path = typer.Option(..., "--db"), task: str = typer.Option(..., "--task")) -> None:
    """Optional Claude second opinion on one task's full audit trail (requires ANTHROPIC_API_KEY)."""
    from agentwarden.analysis.blast_radius import compute_blast_radius
    from agentwarden.llm.client import LLMNotConfiguredError, review_task
    from agentwarden.report.markdown_report import render_audit_events_markdown, render_blast_radius_markdown

    if not settings.has_llm_key:
        console.print("[yellow]ANTHROPIC_API_KEY not set — nothing to do. See README.md.[/yellow]")
        raise typer.Exit(1)

    async def _go():
        store = Store(db)
        await store.open()
        events = await audit_store.list_events(store)
        task_events = [e for e in events if e.task_id == task]
        report = await compute_blast_radius(store, task, settings.blast_radius_ceiling, SystemClock())
        await store.close()

        verdict = review_task(render_blast_radius_markdown(report), render_audit_events_markdown(task_events))
        style = "bold red" if verdict.looks_malicious else "green"
        console.print(f"[{style}]{'LOOKS MALICIOUS' if verdict.looks_malicious else 'looks benign'}[/{style}] (confidence {verdict.confidence}%)")
        console.print(verdict.reasoning)

    _run(_go())


@app.command()
def serve(
    config: Path = typer.Argument(..., help="Path to the agentwarden serve config YAML."),
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8642, "--port"),
) -> None:
    """Run the live proxy over streamable HTTP, mediating real upstream MCP servers."""
    from agentwarden.broker.sweeper import run_sweeper_loop
    from agentwarden.policy.schema import load_enforcement_modes, load_policy_file
    from agentwarden.proxy.server import AgentWardenProxy
    from agentwarden.proxy.upstream import UpstreamPool
    from agentwarden.serve_config import ServeConfigError, load_serve_config

    try:
        cfg = load_serve_config(config)
    except ServeConfigError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

    async def _go():
        store = Store(Path(settings.state_dir) / "agentwarden.db")
        await store.open()
        pool = UpstreamPool(cfg.upstreams)
        await pool.start()

        policy_rules = load_policy_file(cfg.policy_file)
        enforcement_modes = load_enforcement_modes(cfg.policy_file)
        proxy = AgentWardenProxy(
            identity_id=cfg.identity_id, identity_label=cfg.identity_label, listener_source=str(config),
            transport_label="http", policy_rules_by_identity=policy_rules, enforcement_modes=enforcement_modes,
            upstream_pool=pool, store=store, clock=SystemClock(), new_id=new_id, instance_id=new_id("instance"),
            blast_radius_ceiling=cfg.blast_radius_ceiling,
        )
        await proxy.start()
        console.print(f"[green]AgentWarden listening on http://{host}:{port} — identity '{cfg.identity_id}', {len(cfg.upstreams)} upstream(s)[/green]")

        import anyio

        async with anyio.create_task_group() as tg:
            tg.start_soon(run_sweeper_loop, store, SystemClock(), new_id)
            await proxy.mcp_server.run_streamable_http_async(host=host, port=port)

    _run(_go())


def main() -> None:
    app()


if __name__ == "__main__":
    main()
