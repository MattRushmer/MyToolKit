"""Render AuditEvent lists and BlastRadiusReports as Markdown."""
from __future__ import annotations

from agentwarden.models import AuditEvent, BlastRadiusReport, Severity, severity_rank

_SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)


def _escape_code_span(text: str) -> str:
    """Neutralize characters that would let a value break out of a Markdown
    inline-code span (`` `text` ``) it's interpolated into below. session_id/
    task_id are validated to a safe charset at the proxy boundary (see
    proxy/server.py's H3 fix) before they ever reach here, but tool_name/
    upstream_server_id/identity_id are not attacker-constrained the same way,
    so this stays a second, independent layer rather than relying solely on
    upstream validation."""
    return text.replace("`", "'").replace("\n", " ").replace("\r", "")


def _defang(text: str) -> str:
    """Audit detail can echo tool-call arguments or a rejected delegation
    claim's text - both are attacker-influenced in principle, same spirit as
    MCP-Sentinel's report defanging. Backticks/newlines are also neutralized
    (via _escape_code_span) even though detail text isn't itself wrapped in a
    code span - a raw backtick or newline in an argument value can still
    forge Markdown structure in the rendered report."""
    return _escape_code_span(text).replace("](", "] (")


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
        lines.append(
            f"- **Session:** `{_escape_code_span(event.session_id)}`  "
            f"**Task:** `{_escape_code_span(event.task_id)}`  "
            f"**Identity:** `{_escape_code_span(event.identity_id)}`"
        )
        if event.tool_name:
            tool_span = f"`{_escape_code_span(event.tool_name)}`"
            upstream_span = f" on `{_escape_code_span(event.upstream_server_id)}`" if event.upstream_server_id else ""
            lines.append(f"- **Tool:** {tool_span}{upstream_span}")
        if event.detail:
            detail_text = ", ".join(f"{k}={v!r}" for k, v in event.detail.items())
            lines.append(f"- **Detail:** {_defang(detail_text)}")
        lines.append("")

    return "\n".join(lines)


def render_blast_radius_markdown(report: BlastRadiusReport) -> str:
    lines = [
        "# AgentWarden blast-radius report",
        "",
        f"Root session: `{_escape_code_span(report.root_session_id)}`",
        f"Task: `{_escape_code_span(report.task_id)}`",
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
        # ASCII "->" rather than U+2192: Rich writes this straight through to
        # whatever the console's stdout encoding is, and a default Windows
        # console (cp1252) can't encode U+2192 - crashes agentwarden
        # blast-radius with UnicodeEncodeError instead of printing a report.
        path = " -> ".join(_escape_code_span(s) for s in report.path_by_pair.get((upstream, tool), []))
        lines.append(f"| `{_escape_code_span(upstream)}` | `{_escape_code_span(tool)}` | {path} |")

    return "\n".join(lines)
