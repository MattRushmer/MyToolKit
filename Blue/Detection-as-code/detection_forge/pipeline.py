"""Top-level orchestration: the one function both the CLI and the web app call.

ingest -> LLM draft -> structural + ATT&CK validation -> backtest against
user logs (optional) -> noise scoring -> SIEM export.
"""
from __future__ import annotations

from pathlib import Path

from detection_forge.ingest.cti_ingest import load_cti_from_text
from detection_forge.models import BacktestResult, ExportedRule, NoiseScore, PipelineResult
from detection_forge.rules.generator import generate_rule

# Downstream stages (backtest/scoring/export) are each already internally
# defensive (they catch their own per-item failures and report warnings
# instead of raising), but that coverage isn't guaranteed to be total. If a
# stage *does* raise unexpectedly, we still have an already-generated,
# already-validated rule the caller paid an LLM call for - crashing the whole
# pipeline and discarding it would be worse than degrading gracefully with a
# visible error, consistent with every other stage's own fail-visible design.


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
        try:
            from detection_forge.backtest.matcher import run_backtest

            backtest = run_backtest(rule, log_file_paths)
        except Exception as exc:
            backtest = BacktestResult(
                log_file=", ".join(Path(p).name for p in log_file_paths),
                total_events_scanned=0,
                parse_errors=[f"Backtest stage crashed unexpectedly: {exc}"],
            )

    noise = None
    if rule.structurally_valid:
        try:
            from detection_forge.scoring.noise_score import score_rule

            noise = score_rule(rule, backtest)
        except Exception as exc:
            # Fail closed: an unscored rule is treated as critical noise risk
            # rather than silently shipping with no noise information at all.
            noise = NoiseScore(
                total_score=100.0,
                band="critical",
                summary=f"Noise scoring crashed unexpectedly ({exc}); treat as unscored and review manually.",
            )

    exports = []
    if rule.structurally_valid:
        try:
            from detection_forge.export import export_all

            exports = export_all(rule, export_targets)
        except Exception as exc:
            exports = [
                ExportedRule(
                    target="error",
                    content="",
                    filename="",
                    warnings=[f"Export stage crashed unexpectedly: {exc}"],
                )
            ]

    return PipelineResult(cti=cti, rule=rule, backtest=backtest, noise=noise, exports=exports)
