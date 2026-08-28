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
