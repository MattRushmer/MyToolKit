"""Dispatches rule export to the requested SIEM target format(s)."""
from __future__ import annotations

from detection_forge.models import ExportedRule, GeneratedRule

VALID_TARGETS = {"sigma", "splunk", "elasticsearch", "wazuh"}
_VALID_TARGETS = VALID_TARGETS  # kept for internal readability below


def export_all(rule: GeneratedRule, targets: list[str]) -> list[ExportedRule]:
    """Runs each requested exporter independently - one target crashing must
    never discard the other already-successful exports (each exporter is
    also internally defensive, but this is a second line of defense)."""
    results: list[ExportedRule] = []
    for target in targets:
        key = target.strip().lower()
        try:
            if key == "sigma":
                from detection_forge.export.sigma_export import export_sigma

                results.append(export_sigma(rule))
            elif key == "splunk":
                from detection_forge.export.splunk_export import export_splunk

                results.append(export_splunk(rule))
            elif key == "elasticsearch":
                from detection_forge.export.elastic_export import export_elasticsearch

                results.append(export_elasticsearch(rule))
            elif key == "wazuh":
                from detection_forge.export.wazuh_export import export_wazuh

                results.append(export_wazuh(rule))
            else:
                results.append(
                    ExportedRule(
                        target=key,
                        content="",
                        filename="",
                        warnings=[f"Unknown export target '{target}'. Valid targets: {', '.join(sorted(_VALID_TARGETS))}"],
                    )
                )
        except Exception as exc:
            results.append(
                ExportedRule(
                    target=key,
                    content="",
                    filename="",
                    warnings=[f"Export to '{key}' crashed unexpectedly: {exc}"],
                )
            )
    return results
