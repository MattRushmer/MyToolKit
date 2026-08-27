"""Orchestrates: CTI -> LLM draft -> structural validation -> ATT&CK tag validation,
with a bounded repair loop when the first draft doesn't structurally validate.
"""
from __future__ import annotations

import re

from detection_forge.attack.attack_data import validate_attack_tags
from detection_forge.config import settings
from detection_forge.llm.anthropic_client import draft_sigma_rule
from detection_forge.llm.prompts import build_generation_prompt
from detection_forge.models import CTIInput, GeneratedRule
from detection_forge.rules.validator import apply_validation

_TAG_RE = re.compile(r"attack\.t\d{4}(?:\.\d{3})?", re.IGNORECASE)


def _extract_tags(rule_yaml: str) -> list[str]:
    try:
        import yaml as pyyaml

        raw = pyyaml.safe_load(rule_yaml) or {}
        tags = raw.get("tags", []) or []
        return [str(t) for t in tags]
    except Exception:
        return _TAG_RE.findall(rule_yaml)


def generate_rule(cti: CTIInput) -> GeneratedRule:
    prompt = build_generation_prompt(cti)
    repair_notes: str | None = None
    last: GeneratedRule | None = None

    for attempt in range(settings.max_generation_retries + 1):
        if repair_notes:
            prompt = build_generation_prompt(cti, repair_notes=repair_notes)

        draft = draft_sigma_rule(prompt)

        generated = GeneratedRule(
            rule_yaml=draft.rule_yaml,
            title="",
            sigma_id="",
            model_used=draft.model_used,
            raw_llm_response=draft.raw_response,
            generation_notes=draft.generation_notes,
        )
        generated = apply_validation(generated)
        generated.attack_tags = _extract_tags(generated.rule_yaml)
        generated.attack_validations = validate_attack_tags(generated.attack_tags)

        last = generated

        if generated.structurally_valid:
            break

        repair_notes = "\n".join(f"- {e}" for e in generated.structural_errors)

    assert last is not None
    return last
