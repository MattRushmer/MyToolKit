"""Structural validation of a drafted Sigma rule using pySigma itself.

We deliberately trust pySigma's own parser as the source of truth for
"is this syntactically/structurally a valid Sigma rule" rather than
hand-rolling YAML schema checks, since pySigma is what will actually be used
downstream to convert the rule for a SIEM.
"""
from __future__ import annotations

import uuid

from detection_forge.models import GeneratedRule


def validate_structure(rule_yaml: str) -> tuple[bool, list[str], str, str]:
    """Parse and structurally validate a Sigma rule.

    Returns (is_valid, errors, title, sigma_id). title/sigma_id are best-effort
    even on failure (extracted from raw YAML) so the UI can still show *something*.
    """
    errors: list[str] = []
    title = "(untitled)"
    sigma_id = ""

    try:
        import yaml as pyyaml

        raw = pyyaml.safe_load(rule_yaml) or {}
        title = str(raw.get("title", title))
        sigma_id = str(raw.get("id", ""))
    except Exception as exc:
        errors.append(f"YAML did not even parse as a mapping: {exc}")
        return False, errors, title, sigma_id

    try:
        from sigma.exceptions import SigmaError
        from sigma.rule import SigmaRule

        parsed = SigmaRule.from_yaml(rule_yaml)
    except Exception as exc:  # covers SigmaError subclasses and raw yaml errors
        errors.append(str(exc))
        return False, errors, title, sigma_id

    # A few extra checks pySigma's parser doesn't hard-fail on but we care about.
    if not parsed.title or not str(parsed.title).strip():
        errors.append("Rule has an empty title")

    if not sigma_id:
        errors.append("Rule is missing an 'id' field")
    else:
        try:
            uuid.UUID(sigma_id)
        except ValueError:
            errors.append(f"Rule id '{sigma_id}' is not a valid UUID")

    if not parsed.detection or not parsed.detection.detections:
        errors.append("Rule has no detection selections")

    tags = [str(t) for t in (parsed.tags or [])]
    if not any(t.lower().startswith("attack.t") for t in tags):
        errors.append("Rule has no attack.txxxx technique tag - CTI-derived rules should map to ATT&CK")

    return (len(errors) == 0), errors, title, sigma_id or str(uuid.uuid4())


def apply_validation(generated: GeneratedRule) -> GeneratedRule:
    """Mutates-and-returns a GeneratedRule with structural validation results filled in."""
    is_valid, errors, title, sigma_id = validate_structure(generated.rule_yaml)
    generated.structurally_valid = is_valid
    generated.structural_errors = errors
    generated.title = title
    generated.sigma_id = sigma_id
    return generated
