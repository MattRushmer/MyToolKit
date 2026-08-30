from mcp_sentinel.models import (
    Finding,
    RiskCategory,
    ScanReport,
    ServerInventory,
    Severity,
    ToolInfo,
    severity_rank,
)
from factories import make_config


def test_severity_rank_orders_critical_first():
    assert severity_rank(Severity.CRITICAL) < severity_rank(Severity.HIGH)
    assert severity_rank(Severity.HIGH) < severity_rank(Severity.MEDIUM)
    assert severity_rank(Severity.MEDIUM) < severity_rank(Severity.LOW)
    assert severity_rank(Severity.LOW) < severity_rank(Severity.INFO)


def test_scan_report_counts_by_severity():
    report = ScanReport()
    report.findings.append(_finding(Severity.CRITICAL))
    report.findings.append(_finding(Severity.CRITICAL))
    report.findings.append(_finding(Severity.LOW))
    counts = report.counts_by_severity
    assert counts[Severity.CRITICAL] == 2
    assert counts[Severity.LOW] == 1
    assert counts[Severity.HIGH] == 0


def test_scan_report_findings_sorted_worst_first():
    report = ScanReport()
    report.findings.append(_finding(Severity.LOW))
    report.findings.append(_finding(Severity.CRITICAL))
    report.findings.append(_finding(Severity.MEDIUM))
    ordered = report.findings_sorted()
    assert [f.severity for f in ordered] == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]


def test_scan_report_total_tools_sums_across_servers():
    report = ScanReport()
    inv1 = ServerInventory(config=make_config("a"), tools=[ToolInfo(name="t1"), ToolInfo(name="t2")])
    inv2 = ServerInventory(config=make_config("b"), tools=[ToolInfo(name="t3")])
    report.inventories.extend([inv1, inv2])
    assert report.total_tools == 3
    assert report.total_servers == 2


def _finding(severity: Severity) -> Finding:
    return Finding(
        finding_id="f1",
        severity=severity,
        category=RiskCategory.OVER_PRIVILEGED_TOOL,
        title="t",
        description="d",
        server_id="s1",
    )
