"""Render a ScanReport as a human-readable Markdown summary."""
from __future__ import annotations

from mcp_sentinel.models import Finding, ScanReport, Severity

_SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)


def _defang_markdown_links(text: str) -> str:
    """A Finding's description can carry attacker-influenced text (e.g. the
    optional LLM judge is explicitly allowed to quote a short fragment of a
    hostile tool response in its reasoning - see llm/prompts.py). Breaking
    the "](" that starts a Markdown link/image target keeps that quoted text
    readable while stopping it from becoming a live link a viewer might
    auto-render or auto-fetch."""
    return text.replace("](", "] (")


def _finding_section(finding: Finding) -> str:
    # title and tool_name can both embed a server-supplied tool name -
    # attacker-controlled input for a hostile/poisoned server, same as
    # description (see _defang_markdown_links's docstring).
    lines = [
        f"### [{finding.severity.value.upper()}] {_defang_markdown_links(finding.title)}",
        "",
        f"- **Server:** `{finding.server_id}`",
    ]
    if finding.tool_name:
        lines.append(f"- **Tool:** `{_defang_markdown_links(finding.tool_name)}`")
    lines.append(f"- **Category:** {finding.category.value}")
    if finding.references:
        lines.append(f"- **References:** {', '.join(finding.references)}")
    lines.append("")
    lines.append(_defang_markdown_links(finding.description))
    if finding.recommendation:
        lines.append("")
        lines.append(f"**Recommendation:** {finding.recommendation}")
    lines.append("")
    return "\n".join(lines)


def render_markdown_report(report: ScanReport) -> str:
    counts = report.counts_by_severity
    lines = [
        "# MCP Sentinel scan report",
        "",
        f"Scanned at: {report.scanned_at.isoformat()}",
        f"Servers scanned: {report.total_servers}",
        f"Tools inventoried: {report.total_tools}",
        f"Active probing: {'enabled' if report.active_probes_run else 'disabled'}",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for sev in _SEVERITY_ORDER:
        lines.append(f"| {sev.value.upper()} | {counts[sev]} |")
    lines.append("")

    if not report.findings:
        lines.append("No findings.")
        return "\n".join(lines)

    lines.append("## Findings")
    lines.append("")
    for finding in report.findings_sorted():
        lines.append(_finding_section(finding))

    return "\n".join(lines)
