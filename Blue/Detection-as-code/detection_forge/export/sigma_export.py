"""Native Sigma YAML export - trivial passthrough, always available."""
from __future__ import annotations

from detection_forge.models import ExportedRule, GeneratedRule


def export_sigma(rule: GeneratedRule) -> ExportedRule:
    return ExportedRule(target="sigma", content=rule.rule_yaml, filename=f"{rule.sigma_id}.yml")
