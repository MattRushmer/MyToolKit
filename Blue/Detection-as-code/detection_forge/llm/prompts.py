"""Prompt construction for CTI -> Sigma rule generation.

Grounding strategy (RAG-lite, no vector DB): instead of trusting the model's
memory of Sigma syntax, we embed a handful of real, structurally-correct
example rules directly in the prompt (see rules/examples/) and force
structured tool-call output so we always get clean YAML back, not prose
wrapped around a code fence.
"""
from __future__ import annotations

from detection_forge.config import EXAMPLE_RULES_DIR
from detection_forge.models import CTIInput

SYSTEM_PROMPT = """You are a detection engineer who writes Sigma rules (sigmahq.io spec).

Rules you must follow:
1. Output MUST be valid Sigma YAML: title, id (a fresh random UUID4), status: experimental,
   description, references, author: "detection-forge (LLM-drafted, unreviewed)", date,
   logsource (category/product/service), detection (named selections + condition),
   falsepositives (be specific and honest, not "unknown"), level, tags.
2. Every ATT&CK tag MUST be a real, currently-valid technique ID in the form
   attack.txxxx or attack.txxxx.yyy. Do not invent technique IDs. If you are not
   certain a technique ID is correct, omit it rather than guess.
3. Prefer precise field conditions (exact match, endswith on full binary names,
   contains on distinctive strings) over broad wildcards. Every broad or
   high-cardinality condition (e.g. a bare CommandLine|contains on a common word)
   materially increases false positives in production - avoid it unless the CTI
   report gives you no more specific anchor.
4. Include a `filter_*` selection with `and not` in the condition whenever you can
   think of a concrete, common legitimate cause of the same telemetry - do not leave
   this to the analyst.
5. Base the rule ONLY on what is stated or strongly implied by the CTI text and the
   extracted IOCs you're given. Do not invent behavior the report doesn't describe.
6. You must call the emit_sigma_rule tool exactly once with your final answer. Do not
   respond in plain text.
"""


def _load_example_rules() -> str:
    blocks = []
    for path in sorted(EXAMPLE_RULES_DIR.glob("*.yml")):
        blocks.append(f"# Example: {path.stem}\n{path.read_text(encoding='utf-8')}")
    return "\n\n".join(blocks)


def build_generation_prompt(cti: CTIInput, repair_notes: str | None = None) -> str:
    ioc_lines = "\n".join(
        f"- [{ioc.ioc_type}] {ioc.value}  (context: \"{ioc.context}\")" for ioc in cti.iocs
    ) or "(no IOCs auto-extracted; rely on the report text itself)"

    cve_lines = ", ".join(cti.cve_ids) if cti.cve_ids else "(none detected)"

    prompt = f"""Here are {len(list(EXAMPLE_RULES_DIR.glob('*.yml')))} example Sigma rules showing the exact
style, structure, and specificity level expected:

{_load_example_rules()}

---

Now draft ONE new Sigma rule from this CTI report.

Source: {cti.source_name}
CVE IDs mentioned: {cve_lines}

Auto-extracted IOCs (use the ones that are actually behaviorally relevant - e.g. a
dropped filename or registry key is often more useful in a rule than a raw IP the
report only mentions as C2 infrastructure, which belongs in falsepositives/references
context, not necessarily a field match unless the logsource supports network fields):
{ioc_lines}

CTI report text:
\"\"\"
{cti.raw_text[:12000]}
\"\"\"
"""
    if repair_notes:
        prompt += f"""

Your previous attempt failed validation with these errors - fix them and resubmit
a complete, corrected rule via emit_sigma_rule (don't just describe the fix):
{repair_notes}
"""
    return prompt


EMIT_SIGMA_RULE_TOOL = {
    "name": "emit_sigma_rule",
    "description": "Submit the final drafted Sigma detection rule.",
    "input_schema": {
        "type": "object",
        "properties": {
            "rule_yaml": {
                "type": "string",
                "description": "Complete, valid Sigma rule as a single YAML document.",
            },
            "generation_notes": {
                "type": "string",
                "description": (
                    "2-5 sentences for the analyst: what specifically in the CTI report "
                    "justifies this rule, what you deliberately left out or narrowed and why, "
                    "and any assumptions you made about the log source."
                ),
            },
        },
        "required": ["rule_yaml", "generation_notes"],
    },
}
