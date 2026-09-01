"""Top-level orchestration: walk source files -> run baseline SAST rules ->
run auth-hallucination analysis -> cluster duplicated insecure patterns ->
optionally check declared dependencies against their registry -> optionally
run an LLM second-opinion pass on auth findings -> assemble one ScanReport.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from pathlib import Path

from vibecheck.auth.hallucination_rules import (
    check_fail_open_auth,
    check_sibling_route_gaps,
    check_tautological_auth,
    check_undefined_guards,
    check_unused_auth_helpers,
)
from vibecheck.auth.route_extractor import extract_javascript_routes, extract_python_routes
from vibecheck.auth.symbol_index import build_javascript_symbol_index, build_python_symbol_index
from vibecheck.config import settings
from vibecheck.dependencies.extractor import extract_declared_dependencies
from vibecheck.dependencies.findings import build_dependency_findings
from vibecheck.dependencies.registry import check_dependencies_exist
from vibecheck.duplication.duplication import cluster_duplicate_insecure_findings
from vibecheck.llm.client import AuthJudgeVerdict, judge_auth_finding
from vibecheck.models import Category, Finding, Language, ScanReport, SourceFile
from vibecheck.rules.crypto_and_config import check_crypto_and_config
from vibecheck.rules.dangerous_calls import check_dangerous_calls
from vibecheck.rules.injection import check_injection
from vibecheck.rules.secrets import check_secrets
from vibecheck.scanner.walker import discover_source_files

_LLM_FALSE_POSITIVE_CONFIDENCE_THRESHOLD = 70
_CODE_CONTEXT_LINES = 4


@dataclass(frozen=True)
class ScanOptions:
    check_dependencies: bool = False
    llm_judge: bool = False
    cache_dir: Path = field(default_factory=lambda: Path(settings.cache_dir))
    registry_timeout_seconds: float = field(default_factory=lambda: settings.registry_timeout_seconds)


def _run_baseline_rules(sources: list[SourceFile]) -> list[Finding]:
    findings: list[Finding] = []
    for source in sources:
        findings.extend(check_secrets(source))
        findings.extend(check_dangerous_calls(source))
        findings.extend(check_injection(source))
        findings.extend(check_crypto_and_config(source))
    return findings


def _run_auth_analysis(sources: list[SourceFile]) -> list[Finding]:
    python_sources = [s for s in sources if s.language is Language.PYTHON]
    js_sources = [s for s in sources if s.language in (Language.JAVASCRIPT, Language.TYPESCRIPT)]

    python_routes = [route for s in python_sources for route in extract_python_routes(s)]
    js_routes = [route for s in js_sources for route in extract_javascript_routes(s)]

    py_symbol_index = build_python_symbol_index(python_sources)
    js_symbol_index = build_javascript_symbol_index(js_sources)
    route_handler_names = frozenset(r.handler_name for r in python_routes)

    findings: list[Finding] = []
    findings.extend(check_undefined_guards(python_routes, py_symbol_index))
    findings.extend(check_undefined_guards(js_routes, js_symbol_index))
    findings.extend(check_sibling_route_gaps(python_routes))
    findings.extend(check_sibling_route_gaps(js_routes))
    findings.extend(check_unused_auth_helpers(py_symbol_index, route_handler_names))
    for source in python_sources:
        findings.extend(check_fail_open_auth(source))
        findings.extend(check_tautological_auth(source))
    return findings


def _code_context(sources_by_path: dict[str, SourceFile], file: str, line: int) -> str:
    source = sources_by_path.get(file)
    if source is None or line <= 0:
        return ""
    start = max(0, line - 1 - _CODE_CONTEXT_LINES)
    end = min(len(source.lines), line + _CODE_CONTEXT_LINES)
    return "\n".join(source.lines[start:end])


def _apply_llm_judge(findings: list[Finding], sources_by_path: dict[str, SourceFile]) -> tuple[list[Finding], list[str]]:
    judged: list[Finding] = []
    warnings: list[str] = []
    for finding in findings:
        if finding.category is not Category.HALLUCINATED_AUTH:
            judged.append(finding)
            continue
        try:
            verdict: AuthJudgeVerdict = judge_auth_finding(
                finding.title, finding.description, _code_context(sources_by_path, finding.file, finding.line)
            )
        except Exception as exc:  # noqa: BLE001 - one judge call failing must not sink the rest of the scan
            warnings.append(f"LLM judge call failed for {finding.finding_id}: {exc}")
            judged.append(finding)
            continue

        evidence = dict(finding.evidence)
        evidence["llm_verdict"] = {"is_real_vulnerability": verdict.is_real_vulnerability, "confidence": verdict.confidence, "reasoning": verdict.reasoning}
        title = finding.title
        if not verdict.is_real_vulnerability and verdict.confidence >= _LLM_FALSE_POSITIVE_CONFIDENCE_THRESHOLD:
            title = f"[LLM judge: likely false positive] {finding.title}"
        # Severity is deliberately left untouched: the judge reasons over source
        # from the scanned (untrusted) repository, so treating its opinion as
        # authoritative enough to lower severity would let a prompt-injection
        # attempt in that source silently downgrade a real finding below a
        # --fail-on threshold. The verdict is surfaced for a human to read
        # (evidence + title), never used to change what CI gates on.
        judged.append(dataclasses.replace(finding, evidence=evidence, title=title))
    return judged, warnings


def run_scan(root: Path, options: ScanOptions | None = None) -> ScanReport:
    options = options or ScanOptions()
    root = root.resolve()

    sources, walk_warnings = discover_source_files(root)
    sources_by_path = {s.rel_path: s for s in sources}

    report = ScanReport(
        root=str(root),
        files_scanned=len(sources),
        warnings=list(walk_warnings),
        dependency_check_run=options.check_dependencies,
        llm_judge_run=options.llm_judge and settings.has_llm_key,
    )

    baseline_findings = _run_baseline_rules(sources)
    report.findings.extend(baseline_findings)
    report.findings.extend(_run_auth_analysis(sources))
    report.findings.extend(cluster_duplicate_insecure_findings(baseline_findings))

    if options.check_dependencies:
        deps = extract_declared_dependencies(root)
        results = check_dependencies_exist(deps, options.cache_dir, options.registry_timeout_seconds)
        report.findings.extend(build_dependency_findings(deps, results))

    if options.llm_judge:
        if settings.has_llm_key:
            judged, judge_warnings = _apply_llm_judge(report.findings, sources_by_path)
            report.findings = judged
            report.warnings.extend(judge_warnings)
        else:
            report.warnings.append("--llm-judge requested but ANTHROPIC_API_KEY is not set; skipped (see README.md).")

    return report
