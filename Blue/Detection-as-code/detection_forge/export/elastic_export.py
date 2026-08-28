"""Elasticsearch (Lucene) export via the official pySigma Elasticsearch backend."""
from __future__ import annotations

from detection_forge.models import ExportedRule, GeneratedRule


def export_elasticsearch(rule: GeneratedRule) -> ExportedRule:
    filename = f"{rule.sigma_id}.lucene"
    try:
        from sigma.backends.elasticsearch import LuceneBackend
        from sigma.collection import SigmaCollection

        collection = SigmaCollection.from_yaml(rule.rule_yaml)
        queries = LuceneBackend().convert(collection)
        content = "\n\n# --- additional Sigma condition ---\n\n".join(str(query) for query in queries) if isinstance(queries, list) else str(queries)
        return ExportedRule(target="elasticsearch", content=content, filename=filename)
    except Exception as exc:
        return ExportedRule(
            target="elasticsearch",
            content=f"# Elasticsearch conversion failed: {exc}",
            filename=filename,
            warnings=[f"Elasticsearch conversion failed: {exc}"],
        )
