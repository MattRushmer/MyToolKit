"""Shared data contracts used across the scanner, rules, auth analysis,
duplication clustering, dependency checks, and reporting."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Ordering used to sort findings worst-first without a custom comparator.
_SEVERITY_RANK = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}


def severity_rank(severity: Severity) -> int:
    return _SEVERITY_RANK[severity]


class Category(str, Enum):
    HALLUCINATED_AUTH = "hallucinated_auth"
    INSECURE_DUPLICATION = "insecure_duplication"
    HALLUCINATED_DEPENDENCY = "hallucinated_dependency"
    HARDCODED_SECRET = "hardcoded_secret"
    DANGEROUS_CALL = "dangerous_call"
    INJECTION = "injection"
    WEAK_CRYPTO = "weak_crypto"
    INSECURE_CONFIG = "insecure_config"


class Language(str, Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    UNKNOWN = "unknown"


_EXTENSION_LANGUAGE = {
    ".py": Language.PYTHON,
    ".js": Language.JAVASCRIPT,
    ".jsx": Language.JAVASCRIPT,
    ".mjs": Language.JAVASCRIPT,
    ".cjs": Language.JAVASCRIPT,
    ".ts": Language.TYPESCRIPT,
    ".tsx": Language.TYPESCRIPT,
}


def language_for_path(path: Path) -> Language:
    return _EXTENSION_LANGUAGE.get(path.suffix.lower(), Language.UNKNOWN)


@dataclass(frozen=True)
class SourceFile:
    """One scanned file, already read into memory. `rel_path` (POSIX-style,
    relative to the scan root) is what every Finding/RouteInfo cites, so
    reports are stable across machines instead of embedding an absolute path."""

    abs_path: Path
    rel_path: str
    language: Language
    text: str
    lines: tuple[str, ...] = field(default_factory=tuple)

    @property
    def line_count(self) -> int:
        return len(self.lines)


@dataclass(frozen=True)
class Finding:
    finding_id: str
    rule_id: str  # stable catalog id, e.g. "VIBE-AUTH-01" - see rules/catalog.py
    severity: Severity
    category: Category
    title: str
    description: str
    file: str
    line: int = 0
    end_line: int | None = None
    snippet: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    references: tuple[str, ...] = ()  # e.g. ("CWE-798", "OWASP-A07:2021")


@dataclass
class ScanReport:
    root: str
    scanned_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    dependency_check_run: bool = False
    llm_judge_run: bool = False
    warnings: list[str] = field(default_factory=list)

    @property
    def counts_by_severity(self) -> dict[Severity, int]:
        counts = {s: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    @property
    def counts_by_category(self) -> dict[Category, int]:
        counts = {c: 0 for c in Category}
        for f in self.findings:
            counts[f.category] += 1
        return counts

    def findings_sorted(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (severity_rank(f.severity), f.file, f.line))
