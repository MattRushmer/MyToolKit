"""Transparent, conservative heuristic noise scoring for drafted Sigma rules."""
from __future__ import annotations

import yaml

from detection_forge.config import settings
from detection_forge.models import BacktestResult, GeneratedRule, NoiseFactor, NoiseScore

# Weights deliberately favour observed behaviour; the remaining factors explain risk
# when a representative log corpus is unavailable.
SCORING_WEIGHTS = {
    "empirical_match_rate": 45,  # strongest signal when sample logs are representative
    "structural_specificity": 25,  # rules with few constraints tend to be broad
    "wildcard_density": 15,  # free-text wildcard matching is particularly expensive/noisy
    "falsepositives": 10,  # analyst acknowledgement of concrete benign cases matters
    "level_mismatch": 5,  # only a small additional penalty for overstated severity
}


def _raw(rule: GeneratedRule) -> dict:
    try:
        value = yaml.safe_load(rule.rule_yaml) or {}
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def score_rule(rule: GeneratedRule, backtest: BacktestResult | None) -> NoiseScore:
    raw = _raw(rule)
    detection = raw.get("detection", {}) if isinstance(raw.get("detection"), dict) else {}
    factors: list[NoiseFactor] = []
    total = 0.0
    if backtest and backtest.total_events_scanned:
        rate = backtest.match_rate
        raw_score = min(100.0, rate / 0.05 * 100.0)
        note = f"Matched {backtest.match_count}/{backtest.total_events_scanned} events ({rate:.1%})."
        if rate == 0 and backtest.unmapped_fields:
            note += " Zero matches may reflect missing test fields: " + ", ".join(backtest.unmapped_fields) + "."
        impact = raw_score * SCORING_WEIGHTS["empirical_match_rate"] / 100
        factors.append(NoiseFactor("Empirical match rate", impact, note))
        total += impact
    selections = {k: v for k, v in detection.items() if k != "condition"}
    condition = str(detection.get("condition", ""))
    main = [v for k, v in selections.items() if not k.startswith("filter")]
    field_counts = [len(v) for v in main if isinstance(v, dict)]
    constraints = sum(field_counts)
    structural_raw = max(0.0, 85 - constraints * 22)
    if "not filter" in condition.lower(): structural_raw = max(0.0, structural_raw - 20)
    if constraints <= 1 and " or " in condition.lower(): structural_raw = min(100.0, structural_raw + 15)
    impact = structural_raw * SCORING_WEIGHTS["structural_specificity"] / 100
    factors.append(NoiseFactor("Structural specificity", impact, f"{constraints} field constraint(s) across main selection(s); {'subtractive filter present' if 'not filter' in condition.lower() else 'no subtractive filter'}."))
    total += impact
    risky = 0
    free_text = {"commandline", "parentcommandline", "details", "message", "description"}
    for value in selections.values():
        if not isinstance(value, dict): continue
        for key, val in value.items():
            field, *mods = str(key).split("|")
            vals = val if isinstance(val, list) else [val]
            if field.lower() in free_text and ("contains" in mods or any(str(x).startswith("*") or str(x).endswith("*") for x in vals)):
                risky += 1
    wildcard_raw = min(100.0, risky * 45)
    impact = wildcard_raw * SCORING_WEIGHTS["wildcard_density"] / 100
    factors.append(NoiseFactor("Free-text wildcard density", impact, f"Found {risky} broad free-text wildcard/contains condition(s)."))
    total += impact
    fps = raw.get("falsepositives") or []
    if not isinstance(fps, list): fps = [fps]
    generic = not fps or all(str(x).strip().lower() in {"", "unknown", "n/a", "none"} for x in fps)
    fp_raw = 85.0 if generic else max(5.0, 35.0 - min(len(fps), 3) * 10)
    impact = fp_raw * SCORING_WEIGHTS["falsepositives"] / 100
    factors.append(NoiseFactor("False-positive guidance", impact, "False positives are generic or absent." if generic else "Rule documents concrete analyst-review false positives."))
    total += impact
    level = str(raw.get("level", "")).lower()
    mismatch_raw = 100.0 if level in {"high", "critical"} and constraints <= 1 else 0.0
    impact = mismatch_raw * SCORING_WEIGHTS["level_mismatch"] / 100
    factors.append(NoiseFactor("Level/specificity mismatch", impact, "High severity has limited supporting specificity." if mismatch_raw else "Severity is broadly consistent with rule specificity."))
    total = round(min(100.0, total), 1)
    band = "critical" if total >= settings.noise_critical_threshold else "high" if total >= settings.noise_high_threshold else "medium" if total >= settings.noise_medium_threshold else "low"
    return NoiseScore(total, band, factors, f"Estimated noise is {band} ({total}/100). Review the listed broadness signals before deployment.")
