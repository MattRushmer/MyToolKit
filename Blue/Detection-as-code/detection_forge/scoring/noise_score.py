"""Transparent, conservative heuristic noise scoring for drafted Sigma rules.

Not a calibrated statistical model - a weighted sum of readable heuristics
meant to focus analyst attention, most reliable when a representative sample
log set is supplied for backtesting.
"""
from __future__ import annotations

from typing import Any

import yaml

from detection_forge.config import settings
from detection_forge.models import BacktestResult, GeneratedRule, NoiseFactor, NoiseScore

_FREE_TEXT_FIELDS = {"commandline", "parentcommandline", "details", "message", "description"}

# With a backtest, empirical match rate is the strongest signal (45 of 100
# points). Without one, those 45 points are unavailable - if left as dead
# weight, a maximally broad, wildcard-heavy rule could never score above the
# "medium" noise band no matter how bad its structure/wildcards look on
# paper (25+15+10+5 = 55 max, below the default "high" threshold of 55...
# still not below "critical"=80). So the remaining four factors' weights are
# renormalized to sum to 100 whenever no backtest is available, so a
# structural-only assessment can still reach "high"/"critical" when warranted.
_WEIGHTS_WITH_BACKTEST = {
    "empirical_match_rate": 45,
    "structural_specificity": 25,
    "wildcard_density": 15,
    "falsepositives": 10,
    "level_mismatch": 5,
}
_NO_BACKTEST_TOTAL = sum(v for k, v in _WEIGHTS_WITH_BACKTEST.items() if k != "empirical_match_rate")
_WEIGHTS_WITHOUT_BACKTEST = {
    k: v * 100 / _NO_BACKTEST_TOTAL for k, v in _WEIGHTS_WITH_BACKTEST.items() if k != "empirical_match_rate"
}

# Kept as the public name other code/tests may reference; reflects the
# "backtest available" weighting, which is the common/expected case.
SCORING_WEIGHTS = _WEIGHTS_WITH_BACKTEST


def _raw(rule: GeneratedRule) -> dict:
    try:
        value = yaml.safe_load(rule.rule_yaml) or {}
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def _selection_field_dicts(value: Any) -> list[dict]:
    """Extract every field:value dict out of a raw Sigma selection value.

    Handles both shapes the Sigma spec allows: a single dict (AND of fields),
    and a list of dicts (OR of AND-groups) - the latter was previously
    skipped entirely by this scorer, silently treating list-shaped selections
    as zero constraints / zero wildcard risk regardless of actual content.
    """
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _empirical_match_rate_factor(backtest: BacktestResult | None) -> NoiseFactor | None:
    if not backtest or not backtest.total_events_scanned:
        return None
    rate = backtest.match_rate
    raw_score = min(100.0, rate / 0.05 * 100.0)
    note = f"Matched {backtest.match_count}/{backtest.total_events_scanned} events ({rate:.1%})."
    if rate == 0 and backtest.unmapped_fields:
        note += " Zero matches may reflect missing test fields: " + ", ".join(backtest.unmapped_fields) + "."
    impact = raw_score * _WEIGHTS_WITH_BACKTEST["empirical_match_rate"] / 100
    return NoiseFactor("Empirical match rate", impact, note)


def _structural_specificity_factor(selections: dict, condition: str, weight: float) -> tuple[NoiseFactor, int]:
    main = [v for k, v in selections.items() if not k.startswith("filter")]
    # For an OR-of-AND-groups selection, overall breadth is set by its
    # weakest (fewest-constraint) alternative, not the sum across branches.
    constraint_counts = [min(len(d) for d in _selection_field_dicts(v)) for v in main if _selection_field_dicts(v)]
    constraints = sum(constraint_counts)
    has_filter = "not filter" in condition.lower()

    structural_raw = max(0.0, 85 - constraints * 22)
    if has_filter:
        structural_raw = max(0.0, structural_raw - 20)
    if constraints <= 1 and " or " in condition.lower():
        structural_raw = min(100.0, structural_raw + 15)

    impact = structural_raw * weight / 100
    explanation = (
        f"{constraints} field constraint(s) across main selection(s); "
        f"{'subtractive filter present' if has_filter else 'no subtractive filter'}."
    )
    return NoiseFactor("Structural specificity", impact, explanation), constraints


def _wildcard_density_factor(selections: dict, weight: float) -> NoiseFactor:
    risky = 0
    for value in selections.values():
        for field_dict in _selection_field_dicts(value):
            for key, val in field_dict.items():
                field, *mods = str(key).split("|")
                vals = val if isinstance(val, list) else [val]
                is_free_text = field.lower() in _FREE_TEXT_FIELDS
                is_broad = "contains" in mods or any(str(x).startswith("*") or str(x).endswith("*") for x in vals)
                if is_free_text and is_broad:
                    risky += 1
    wildcard_raw = min(100.0, risky * 45)
    impact = wildcard_raw * weight / 100
    return NoiseFactor("Free-text wildcard density", impact, f"Found {risky} broad free-text wildcard/contains condition(s).")


def _falsepositives_factor(raw: dict, weight: float) -> NoiseFactor:
    fps = raw.get("falsepositives") or []
    if not isinstance(fps, list):
        fps = [fps]
    generic = not fps or all(str(x).strip().lower() in {"", "unknown", "n/a", "none"} for x in fps)
    fp_raw = 85.0 if generic else max(5.0, 35.0 - min(len(fps), 3) * 10)
    impact = fp_raw * weight / 100
    explanation = "False positives are generic or absent." if generic else "Rule documents concrete analyst-review false positives."
    return NoiseFactor("False-positive guidance", impact, explanation)


def _level_mismatch_factor(raw: dict, constraints: int, weight: float) -> NoiseFactor:
    level = str(raw.get("level", "")).lower()
    mismatch = level in {"high", "critical"} and constraints <= 1
    impact = (100.0 if mismatch else 0.0) * weight / 100
    explanation = "High severity has limited supporting specificity." if mismatch else "Severity is broadly consistent with rule specificity."
    return NoiseFactor("Level/specificity mismatch", impact, explanation)


def score_rule(rule: GeneratedRule, backtest: BacktestResult | None) -> NoiseScore:
    raw = _raw(rule)
    detection = raw.get("detection", {}) if isinstance(raw.get("detection"), dict) else {}
    selections = {k: v for k, v in detection.items() if k != "condition"}
    condition = str(detection.get("condition", ""))

    factors: list[NoiseFactor] = []
    total = 0.0

    has_backtest_factor = backtest is not None and backtest.total_events_scanned > 0
    weights = _WEIGHTS_WITH_BACKTEST if has_backtest_factor else {"empirical_match_rate": 0, **_WEIGHTS_WITHOUT_BACKTEST}

    empirical_factor = _empirical_match_rate_factor(backtest)
    if empirical_factor:
        factors.append(empirical_factor)
        total += empirical_factor.score_impact

    structural_factor, constraints = _structural_specificity_factor(selections, condition, weights["structural_specificity"])
    factors.append(structural_factor)
    total += structural_factor.score_impact

    wildcard_factor = _wildcard_density_factor(selections, weights["wildcard_density"])
    factors.append(wildcard_factor)
    total += wildcard_factor.score_impact

    fp_factor = _falsepositives_factor(raw, weights["falsepositives"])
    factors.append(fp_factor)
    total += fp_factor.score_impact

    level_factor = _level_mismatch_factor(raw, constraints, weights["level_mismatch"])
    factors.append(level_factor)
    total += level_factor.score_impact

    total = round(min(100.0, total), 1)
    if total >= settings.noise_critical_threshold:
        band = "critical"
    elif total >= settings.noise_high_threshold:
        band = "high"
    elif total >= settings.noise_medium_threshold:
        band = "medium"
    else:
        band = "low"

    summary = f"Estimated noise is {band} ({total}/100). Review the listed broadness signals before deployment."
    if not has_backtest_factor:
        summary += " No sample logs were backtested, so this is a structural-only estimate."

    return NoiseScore(total, band, factors, summary)
