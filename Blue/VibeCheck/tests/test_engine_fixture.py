"""End-to-end: run the real engine against fixtures/vibe_demo_app (no network
calls - dependency checking is opt-in) and confirm every planted finding
category is caught."""
from __future__ import annotations

from pathlib import Path

from vibecheck.engine import ScanOptions, run_scan
from vibecheck.rules.catalog import (
    VIBE_AUTH_FAIL_OPEN,
    VIBE_AUTH_SIBLING_GAP,
    VIBE_AUTH_TAUTOLOGY,
    VIBE_AUTH_UNDEFINED_DECORATOR,
    VIBE_AUTH_UNUSED_HELPER,
    VIBE_DUP_INSECURE_CLUSTER,
    VIBE_SEC_DEBUG_ENABLED,
    VIBE_SEC_HARDCODED_SECRET,
    VIBE_SEC_PERMISSIVE_CORS,
    VIBE_SEC_SHELL_INJECTION,
    VIBE_SEC_SQL_INJECTION,
    VIBE_SEC_WEAK_PASSWORD_HASH,
)


def test_demo_app_triggers_every_planted_rule(demo_app_root: Path):
    report = run_scan(demo_app_root, ScanOptions())
    rule_ids = {f.rule_id for f in report.findings}

    expected = {
        VIBE_AUTH_UNDEFINED_DECORATOR,
        VIBE_AUTH_FAIL_OPEN,
        VIBE_AUTH_TAUTOLOGY,
        VIBE_AUTH_UNUSED_HELPER,
        VIBE_AUTH_SIBLING_GAP,
        VIBE_DUP_INSECURE_CLUSTER,
        VIBE_SEC_HARDCODED_SECRET,
        VIBE_SEC_SQL_INJECTION,
        VIBE_SEC_SHELL_INJECTION,
        VIBE_SEC_PERMISSIVE_CORS,
        VIBE_SEC_DEBUG_ENABLED,
        VIBE_SEC_WEAK_PASSWORD_HASH,
    }
    missing = expected - rule_ids
    assert not missing, f"expected rules not triggered by fixture: {missing}"


def test_scan_does_not_crash_on_empty_directory(tmp_path: Path):
    report = run_scan(tmp_path, ScanOptions())
    assert report.files_scanned == 0
    assert report.findings == []


def test_llm_judge_false_positive_verdict_annotates_but_never_lowers_severity(demo_app_root: Path, monkeypatch):
    """A judge verdict is untrusted-source-influenced output (the model reads
    scanned repo code to reach it) - it must never be able to silently move a
    finding below a --fail-on threshold, even a confident false-positive
    verdict. See engine.py's _apply_llm_judge docstring/comment."""
    import dataclasses

    import vibecheck.engine as engine_module
    from vibecheck.llm.client import AuthJudgeVerdict
    from vibecheck.models import Severity

    monkeypatch.setattr(engine_module, "settings", dataclasses.replace(engine_module.settings, anthropic_api_key="test-key"))
    monkeypatch.setattr(
        engine_module, "judge_auth_finding",
        lambda title, description, context: AuthJudgeVerdict(is_real_vulnerability=False, confidence=99, reasoning="looks fine to me"),
    )

    report = run_scan(demo_app_root, ScanOptions(llm_judge=True))
    auth_findings = [f for f in report.findings if f.category.value == "hallucinated_auth"]
    assert auth_findings, "fixture should still produce auth findings"
    for finding in auth_findings:
        assert finding.severity in (Severity.CRITICAL, Severity.HIGH)  # unchanged by the verdict
        assert "llm_verdict" in finding.evidence
        assert "likely false positive" in finding.title.lower()


def test_llm_judge_without_api_key_adds_warning_and_skips(demo_app_root: Path, monkeypatch):
    import dataclasses

    import vibecheck.engine as engine_module

    monkeypatch.setattr(engine_module, "settings", dataclasses.replace(engine_module.settings, anthropic_api_key=None))

    report = run_scan(demo_app_root, ScanOptions(llm_judge=True))
    assert report.llm_judge_run is False
    assert any("llm-judge" in w.lower() for w in report.warnings)
