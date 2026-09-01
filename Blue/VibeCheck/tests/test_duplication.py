from __future__ import annotations

from vibecheck.duplication.duplication import cluster_duplicate_insecure_findings, normalize_snippet
from vibecheck.models import Category, Finding, Severity


def _finding(file: str, line: int, rule_id: str, snippet: str, severity: Severity = Severity.CRITICAL) -> Finding:
    return Finding(
        finding_id=f"{rule_id}:{file}:{line}",
        rule_id=rule_id,
        severity=severity,
        category=Category.INJECTION,
        title="SQL query built from an f-string/concatenation/%-format",
        description="...",
        file=file,
        line=line,
        snippet=snippet,
    )


def test_normalize_replaces_strings_numbers_and_identifiers():
    a = normalize_snippet('cursor.execute(f"SELECT * FROM users WHERE id={user_id}")')
    b = normalize_snippet('cursor.execute(f"SELECT * FROM orders WHERE id={order_id}")')
    assert a == b


def test_two_occurrences_of_same_pattern_are_clustered():
    findings = [
        _finding("a.py", 10, "VIBE-SEC-05", 'cursor.execute(f"SELECT * FROM t WHERE id={x}")'),
        _finding("b.py", 20, "VIBE-SEC-05", 'cursor.execute(f"SELECT * FROM t WHERE id={y}")'),
    ]
    clusters = cluster_duplicate_insecure_findings(findings)
    assert len(clusters) == 1
    assert clusters[0].evidence["occurrence_count"] == 2


def test_single_occurrence_is_not_clustered():
    findings = [_finding("a.py", 10, "VIBE-SEC-05", 'cursor.execute(f"SELECT * FROM t WHERE id={x}")')]
    assert cluster_duplicate_insecure_findings(findings) == []


def test_different_rule_ids_do_not_cluster_together():
    findings = [
        _finding("a.py", 10, "VIBE-SEC-05", 'cursor.execute(f"SELECT * FROM t WHERE id={x}")'),
        _finding("b.py", 20, "VIBE-SEC-02", 'cursor.execute(f"SELECT * FROM t WHERE id={x}")'),
    ]
    clusters = cluster_duplicate_insecure_findings(findings)
    assert clusters == []


def test_cluster_severity_escalates_to_critical():
    findings = [
        _finding("a.py", 10, "VIBE-SEC-09", "hashlib.md5(password)", severity=Severity.HIGH),
        _finding("b.py", 20, "VIBE-SEC-09", "hashlib.md5(password)", severity=Severity.HIGH),
    ]
    clusters = cluster_duplicate_insecure_findings(findings)
    assert clusters[0].severity == Severity.CRITICAL
