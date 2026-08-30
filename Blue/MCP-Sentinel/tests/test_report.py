import json

from factories import make_config

from mcp_sentinel.models import Finding, RiskCategory, ScanReport, ServerInventory, Severity
from mcp_sentinel.report.json_report import report_to_dict, report_to_json
from mcp_sentinel.report.markdown_report import render_markdown_report


def _report() -> ScanReport:
    report = ScanReport()
    report.inventories.append(ServerInventory(config=make_config("demo"), reachable=True))
    report.findings.append(
        Finding(
            finding_id="priv-exec:demo:run",
            severity=Severity.HIGH,
            category=RiskCategory.OVER_PRIVILEGED_TOOL,
            title="Tool grants exec",
            description="It runs shell commands.",
            server_id="claude-desktop:demo",
            tool_name="run",
            recommendation="Remove it.",
            references=("MCP05:2025 Command Injection & Execution",),
        )
    )
    report.findings.append(
        Finding(
            finding_id="poison-phrase:demo:tool:x",
            severity=Severity.CRITICAL,
            category=RiskCategory.TOOL_POISONING,
            title="Poisoned description",
            description="Contains injected instructions.",
            server_id="claude-desktop:demo",
        )
    )
    return report


def test_report_to_json_round_trips_through_json_loads():
    report = _report()
    text = report_to_json(report)
    data = json.loads(text)
    assert data["summary"]["total_servers"] == 1
    assert data["summary"]["counts_by_severity"]["critical"] == 1
    assert data["summary"]["counts_by_severity"]["high"] == 1
    assert len(data["findings"]) == 2
    # Enum/datetime fields must serialize as plain JSON values, not repr() text.
    assert data["findings"][0]["severity"] == "critical"  # sorted worst-first
    assert isinstance(data["scanned_at"], str)


def test_report_to_dict_sorts_findings_worst_first():
    payload = report_to_dict(_report())
    severities = [f["severity"] for f in payload["findings"]]
    assert severities == ["critical", "high"]


def test_markdown_report_contains_summary_table_and_findings():
    md = render_markdown_report(_report())
    assert "| CRITICAL | 1 |" in md
    assert "| HIGH | 1 |" in md
    assert "Tool grants exec" in md
    assert "Poisoned description" in md
    assert "`run`" in md  # tool name rendered


def test_markdown_report_handles_no_findings():
    md = render_markdown_report(ScanReport())
    assert "No findings." in md


def test_markdown_report_defangs_malicious_tool_name_in_title_and_tool_line():
    # A round-2 security review found the original Markdown-injection fix
    # only defanged Finding.description - title and tool_name are also
    # attacker-controlled (a hostile server's own declared tool name) and
    # were still rendered as live "](" link syntax.
    report = ScanReport()
    malicious_name = "pwned](http://evil.example/exfil?d=1"
    report.findings.append(
        Finding(
            finding_id="probe-phrase:demo:pwned",
            severity=Severity.CRITICAL,
            category=RiskCategory.PROMPT_INJECTION,
            title=f"Tool '{malicious_name}' response contains instruction-injection phrasing",
            description="ok",
            server_id="claude-desktop:demo",
            tool_name=malicious_name,
        )
    )
    md = render_markdown_report(report)
    assert "](http://evil.example" not in md
    assert "] (http://evil.example" in md
