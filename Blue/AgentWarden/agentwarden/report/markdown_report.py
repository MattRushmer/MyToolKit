"""Render AuditEvent lists and BlastRadiusReports as Markdown."""
from __future__ import annotations

from agentwarden.models import AuditEvent, BlastRadiusReport, Severity, severity_rank

_SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)


def _defang(text: str) -> str:
    """Audit detail can echo tool-call arguments or a rejected delegation
    claim's text - both are attacker-influenced in principle, same spirit as
    MCP-Sentinel's report defanging."""
    return text.replace("](", "] (")


def render_audit_events_markdown(events: list[AuditEvent]) -> str:
    counts = {s: 0 for s in Severity}
    for e in events:
        counts[e.severity] += 1

    lines = [
        "# AgentWarden audit report",
        "",
        f"Events: {len(events)}",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for sev in _SEVERITY_ORDER:
        lines.append(f"| {sev.value.upper()} | {counts[sev]} |")
    lines.append("")

    if not events:
        lines.append("No events.")
        return "\n".join(lines)

    lines.append("## Events")
    lines.append("")
    for event in sorted(events, key=lambda e: (severity_rank(e.severity), e.seq)):
        lines.append(f"### [{event.severity.value.upper()}] {event.event_type.value} (seq {event.seq})")
        lines.append("")
        lines.append(f"- **Timestamp:** {event.timestamp.isoformat()}")
        lines.append(f"- **Session:** `{event.session_id}`  **Task:** `{event.task_id}`  **Identity:** `{event.identity_id}`")
        if event.tool_name:
            lines.append(f"- **Tool:** `{event.tool_name}`" + (f" on `{event.upstream_server_id}`" if event.upstream_server_id else ""))
        if event.detail:
            detail_text = ", ".join(f"{k}={v!r}" for k, v in event.detail.items())
            lines.append(f"- **Detail:** {_defang(detail_text)}")
        lines.append("")

    return "\n".join(lines)


def render_blast_radius_markdown(report: BlastRadiusReport) -> str:
    lines = [
        "# AgentWarden blast-radius report",
        "",
        f"Root session: `{report.root_session_id}`",
        f"Task: `{report.task_id}`",
        f"Computed at: {report.computed_at.isoformat()}",
        f"Ceiling: {report.ceiling} distinct upstream(s)",
        f"Sessions visited: {report.sessions_visited}",
        f"**Exceeded: {'YES' if report.exceeded else 'no'}** ({len(report.distinct_upstreams)} distinct upstream(s) reached)",
        "",
        "## Reachable (upstream, tool) pairs",
        "",
    ]
    if not report.reachable:
        lines.append("None.")
        return "\n".join(lines)

    lines.append("| Upstream | Tool | Reached via |")
    lines.append("|---|---|---|")
    for upstream, tool in sorted(report.reachable):
        path = " → ".join(report.path_by_pair.get((upstream, tool), []))
        lines.append(f"| `{upstream}` | `{tool}` | {path} |")

    return "\n".join(lines)
