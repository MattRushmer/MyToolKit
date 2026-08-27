"""Export a generated Sigma rule to the supported deployment formats."""
from __future__ import annotations

from detection_forge.models import ExportedRule, GeneratedRule


def export_all(rule: GeneratedRule, targets: list[str]) -> list[ExportedRule]:
    exporters = {}
    from detection_forge.export.sigma_export import export_sigma
    from detection_forge.export.splunk_export import export_splunk
    from detection_forge.export.elastic_export import export_elasticsearch
    from detection_forge.export.wazuh_export import export_wazuh
    exporters.update(sigma=export_sigma, splunk=export_splunk, elasticsearch=export_elasticsearch, wazuh=export_wazuh)
    output: list[ExportedRule] = []
    for target in targets:
        func = exporters.get(target.lower())
        if func is None:
            output.append(ExportedRule(target=target, content="", filename="", warnings=[f"Unknown export target: {target}"]))
            continue
        try:
            output.append(func(rule))
        except Exception as exc:
            output.append(ExportedRule(target=target, content="", filename="", warnings=[f"Export failed: {exc}"]))
    return output
