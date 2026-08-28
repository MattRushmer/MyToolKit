"""Splunk SPL export via the official pySigma Splunk backend."""
from __future__ import annotations

from detection_forge.models import ExportedRule, GeneratedRule


def export_splunk(rule: GeneratedRule) -> ExportedRule:
    filename = f"{rule.sigma_id}.spl"
    try:
        from sigma.backends.splunk import SplunkBackend
        from sigma.collection import SigmaCollection

        collection = SigmaCollection.from_yaml(rule.rule_yaml)
        queries = SplunkBackend().convert(collection)
        content = "\n\n# --- additional Sigma condition ---\n\n".join(str(query) for query in queries) if isinstance(queries, list) else str(queries)
        return ExportedRule(target="splunk", content=content, filename=filename)
    except Exception as exc:
        return ExportedRule(
            target="splunk",
            content=f"# Splunk conversion failed: {exc}",
            filename=filename,
            warnings=[f"Splunk conversion failed: {exc}"],
        )
