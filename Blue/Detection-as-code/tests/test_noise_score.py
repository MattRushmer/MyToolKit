from detection_forge.models import BacktestResult, GeneratedRule
from detection_forge.scoring.noise_score import score_rule
from pathlib import Path
import yaml

def test_zero_match_with_unmapped_field_is_explained():
    rule = GeneratedRule('title: x\nid: x\ndetection:\n selection:\n  Image|endswith: x\n condition: selection\nfalsepositives: [Unknown]\nlevel: critical\n', 'x', 'x')
    result = score_rule(rule, BacktestResult("x", 5, unmapped_fields=["Image"]))
    assert 0 <= result.total_score <= 100 and result.band in {"low", "medium", "high", "critical"}
    assert any("missing test fields" in factor.explanation for factor in result.factors)

def test_broad_generic_rule_scores_meaningfully():
    rule = GeneratedRule('title: x\nid: x\ndetection:\n selection:\n  CommandLine|contains: evil\n condition: selection\nfalsepositives: [Unknown]\nlevel: critical\n', 'x', 'x')
    assert score_rule(rule, None).total_score >= 30

def test_powershell_example_scores_with_contains_factor():
    path = Path(__file__).parents[1] / "detection_forge/rules/examples/powershell_encoded_command.yml"
    text = path.read_text(); raw = yaml.safe_load(text)
    score = score_rule(GeneratedRule(text, raw["title"], raw["id"]), None)
    assert any(f.name == "Free-text wildcard density" and f.score_impact > 0 for f in score.factors)

def test_list_shaped_or_of_and_selection_is_not_silently_ignored():
    # Regression: a selection expressed as a list of field-dicts (OR of
    # AND-groups) was previously skipped entirely by both the structural
    # specificity and wildcard density scanners, letting a maximally broad
    # rule ("match anything with a CommandLine or an Image field") score as
    # "low" noise purely because the scorer never looked inside the list.
    rule_yaml = (
        "title: x\nid: x\ndetection:\n"
        " selection:\n"
        "  - CommandLine|contains: '*'\n"
        "  - Image|endswith: '*'\n"
        " condition: selection\n"
        "falsepositives: [Unknown]\nlevel: critical\n"
    )
    score = score_rule(GeneratedRule(rule_yaml, "x", "x"), None)
    wildcard_factor = next(f for f in score.factors if f.name == "Free-text wildcard density")
    assert wildcard_factor.score_impact > 0
    assert score.band in {"high", "critical"}

def test_structural_only_score_can_reach_high_band_without_backtest():
    # Regression: without a backtest, the empirical-match-rate weight (45 of
    # 100 points) was simply unavailable, so the remaining factors' max
    # combined score (55) could never clear the default "high" threshold
    # (55) let alone "critical" (80) - a maximally broad, wildcard-heavy,
    # unfiltered, no-falsepositives-documented, overstated-severity rule
    # should be able to score as high/critical on structure alone.
    rule_yaml = (
        "title: x\nid: x\ndetection:\n"
        " selection:\n"
        "  CommandLine|contains: '*'\n"
        " condition: selection\n"
        "level: critical\n"
    )
    score = score_rule(GeneratedRule(rule_yaml, "x", "x"), None)
    assert score.band in {"high", "critical"}, f"expected high/critical, got {score.band} ({score.total_score})"
