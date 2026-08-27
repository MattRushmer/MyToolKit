"""Validates LLM-generated ATT&CK tags against a real, offline MITRE ATT&CK dataset.

Prevents shipping rules with hallucinated `attack.txxxx` technique IDs by
cross-checking every tag against a locally bundled STIX 2.0 enterprise-attack
bundle (data/enterprise-attack.json). No live TAXII calls at generation time.
"""
from __future__ import annotations

import re
import threading

from detection_forge.config import ATTACK_STIX_PATH
from detection_forge.models import AttackTagValidation

_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)

_lock = threading.Lock()
_attack_data = None
_load_error: str | None = None


def _get_attack_data():
    """Lazily load the STIX bundle once per process (it's ~50MB)."""
    global _attack_data, _load_error
    if _attack_data is not None or _load_error is not None:
        return _attack_data
    with _lock:
        if _attack_data is not None or _load_error is not None:
            return _attack_data
        if not ATTACK_STIX_PATH.exists():
            _load_error = (
                f"ATT&CK STIX bundle not found at {ATTACK_STIX_PATH}. "
                "Run scripts/download_attack_data.py first."
            )
            return None
        try:
            from mitreattack.stix20 import MitreAttackData

            _attack_data = MitreAttackData(str(ATTACK_STIX_PATH))
        except Exception as exc:  # pragma: no cover - defensive, reported to caller
            _load_error = f"Failed to load ATT&CK dataset: {exc}"
            return None
    return _attack_data


def attack_dataset_available() -> tuple[bool, str | None]:
    """Returns (available, error_message)."""
    data = _get_attack_data()
    return data is not None, _load_error


def parse_technique_id(tag: str) -> str | None:
    """Extract e.g. 'T1059.001' from an 'attack.t1059.001' Sigma tag, else None."""
    match = _TAG_RE.match(tag.strip())
    if not match:
        return None
    return match.group(1).upper()


def validate_attack_tags(tags: list[str]) -> list[AttackTagValidation]:
    """Validate every attack.* tag in a rule against the real ATT&CK technique list.

    Non-ATT&CK tags (e.g. 'cve.2024-12345') are skipped entirely, not flagged.
    """
    data = _get_attack_data()
    results: list[AttackTagValidation] = []

    for tag in tags:
        technique_id = parse_technique_id(tag)
        if technique_id is None:
            continue  # not an attack.* tag, nothing to validate

        if data is None:
            results.append(
                AttackTagValidation(
                    tag=tag,
                    technique_id=technique_id,
                    valid=False,
                    reason=_load_error or "ATT&CK dataset unavailable",
                )
            )
            continue

        try:
            obj = data.get_object_by_attack_id(technique_id, "attack-pattern")
        except Exception as exc:  # pragma: no cover - defensive
            obj = None
            reason = f"lookup error: {exc}"
        else:
            reason = None

        if obj is None:
            results.append(
                AttackTagValidation(
                    tag=tag,
                    technique_id=technique_id,
                    valid=False,
                    reason=reason or f"{technique_id} is not a known ATT&CK technique (likely hallucinated)",
                )
            )
        else:
            name = obj.get("name") if isinstance(obj, dict) else getattr(obj, "name", None)
            is_deprecated = bool(
                (obj.get("x_mitre_deprecated") if isinstance(obj, dict) else getattr(obj, "x_mitre_deprecated", False))
                or (obj.get("revoked") if isinstance(obj, dict) else getattr(obj, "revoked", False))
            )
            results.append(
                AttackTagValidation(
                    tag=tag,
                    technique_id=technique_id,
                    valid=not is_deprecated,
                    technique_name=name,
                    reason="technique is deprecated/revoked in current ATT&CK data" if is_deprecated else None,
                )
            )

    return results
