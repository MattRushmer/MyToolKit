"""Render a ScanReport as a human-readable Markdown summary."""
from __future__ import annotations

from vibecheck.models import Finding, ScanReport, Severity

_SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)


def _defang_markdown_links(text: str) -> str:
    """A finding's snippet/description echoes source text from the scanned
    repo - not attacker-controlled the way a live MCP server's response
    would be, but still worth not turning into a clickable/auto-fetched
    Markdown link if a URL or `](` happens to appear in a comment or string."""
    return text.replace("](", "] (")


def _finding_section(finding: Finding) -> str:
    lines = [
        f"### [{finding.severity.value.upper()}] {_defang_markdown_links(finding.title)}",
        "",
        f"- **Rule:** `{finding.rule_id}`",
        f"- **Location:** `{finding.file}:{finding.line}`" if finding.file else "- **Location:** (project-wide)",
        f"- **Category:** {finding.category.value}",
    ]
    if finding.references:
        lines.append(f"- **References:** {', '.join(finding.references)}")
    lines.append("")
    lines.append(_defang_markdown_links(finding.description))
    if finding.snippet:
        lines.append("")
        lines.append(f"```\n{finding.snippet}\n```")
    if finding.recommendation:
        lines.append("")
        lines.append(f"**Recommendation:** {finding.recommendation}")
    lines.append("")
    return "\n".join(lines)


def render_markdown_report(report: ScanReport) -> str:
    counts = report.counts_by_severity
    lines = [
        "# VibeCheck scan report",
        "",
        f"Scanned at: {report.scanned_at.isoformat()}",
        f"Root: `{report.root}`",
        f"Files scanned: {report.files_scanned}",
        f"Dependency registry check: {'enabled' if report.dependency_check_run else 'disabled'}",
        f"LLM second-opinion judge: {'enabled' if report.llm_judge_run else 'disabled'}",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for sev in _SEVERITY_ORDER:
        lines.append(f"| {sev.value.upper()} | {counts[sev]} |")
    lines.append("")

    if report.warnings:
        lines.append("## Warnings")
        lines.append("")
        for w in report.warnings:
            lines.append(f"- {w}")
        lines.append("")

    if not report.findings:
        lines.append("No findings.")
        return "\n".join(lines)

    lines.append("## Findings")
    lines.append("")
    for finding in report.findings_sorted():
        lines.append(_finding_section(finding))

    return "\n".join(lines)
