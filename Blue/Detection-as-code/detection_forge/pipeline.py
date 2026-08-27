"""Top-level orchestration: the one function both the CLI and the web app call.

ingest -> LLM draft -> structural + ATT&CK validation -> backtest against
user logs (optional) -> noise scoring -> SIEM export.
"""
from __future__ import annotations

from pathlib import Path

from detection_forge.ingest.cti_ingest import load_cti_from_text
from detection_forge.models import PipelineResult
from detection_forge.rules.generator import generate_rule


def run_pipeline(
    cti_text: str,
    source_name: str = "unnamed-report",
    log_file_paths: list[Path] | None = None,
    export_targets: list[str] | None = None,
) -> PipelineResult:
    export_targets = export_targets if export_targets is not None else ["sigma"]

    cti = load_cti_from_text(cti_text, source_name=source_name)
    rule = generate_rule(cti)

    backtest = None
    if log_file_paths:
        from detection_forge.backtest.matcher import run_backtest

        backtest = run_backtest(rule, log_file_paths)

    noise = None
    if rule.structurally_valid:
        from detection_forge.scoring.noise_score import score_rule

        noise = score_rule(rule, backtest)

    exports = []
    if rule.structurally_valid:
        from detection_forge.export import export_all

        exports = export_all(rule, export_targets)

    return PipelineResult(cti=cti, rule=rule, backtest=backtest, noise=noise, exports=exports)
