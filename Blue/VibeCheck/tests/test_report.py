from __future__ import annotations

import json

from vibecheck.models import Category, Finding, ScanReport, Severity
from vibecheck.report.json_report import report_to_json
from vibecheck.report.markdown_report import render_markdown_report


def _sample_report() -> ScanReport:
    report = ScanReport(root="/tmp/project", files_scanned=3)
    report.findings.append(Finding(
        finding_id="VIBE-SEC-01:app.py:5",
        rule_id="VIBE-SEC-01",
        severity=Severity.CRITICAL,
        category=Category.HARDCODED_SECRET,
        title="Hardcoded secret",
        description="A secret is hardcoded.",
        file="app.py",
        line=5,
        snippet='API_KEY = "..."',
        recommendation="Move it to an env var.",
        references=("CWE-798",),
    ))
    return report


def test_json_report_round_trips_findings():
    payload = json.loads(report_to_json(_sample_report()))
    assert payload["files_scanned"] == 3
    assert len(payload["findings"]) == 1
    assert payload["findings"][0]["rule_id"] == "VIBE-SEC-01"
    assert payload["counts_by_severity"]["critical"] == 1


def test_markdown_report_contains_finding_details():
    text = render_markdown_report(_sample_report())
    assert "VIBE-SEC-01" in text
    assert "Hardcoded secret" in text
    assert "app.py:5" in text
    assert "CWE-798" in text


def test_markdown_report_handles_no_findings():
    text = render_markdown_report(ScanReport(root="/tmp/project", files_scanned=1))
    assert "No findings." in text


def test_markdown_report_defangs_link_syntax_in_description():
    report = ScanReport(root="/tmp/project", files_scanned=1)
    report.findings.append(Finding(
        finding_id="x", rule_id="x", severity=Severity.LOW, category=Category.INSECURE_CONFIG,
        title="t", description="see [here](http://evil.example) for details", file="a.py", line=1,
    ))
    text = render_markdown_report(report)
    assert "](http" not in text
