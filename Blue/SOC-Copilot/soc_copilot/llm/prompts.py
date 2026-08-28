"""Prompt construction for incident triage.

One tool call does both the verdict AND the tailored remediation note - not
two separate LLM round-trips - because per-incident LLM cost is a first-class
constraint for this product (see soc_copilot/economics/cost.py): an MSP
running this across a dozen clients' alert queues every day is paying per
token, and doubling calls doubles that bill for no analytical benefit.
"""
from __future__ import annotations

from soc_copilot.models import Client, Incident

SYSTEM_PROMPT = """You are a SOC analyst triaging alerts for a Managed Service Provider (MSP)
that runs security monitoring for many small/mid-size business clients. Nobody on the MSP's
team is a dedicated detection engineer - assume the person reading your output is a competent
generalist IT technician, not a specialist, and write accordingly: plain language, concrete
next steps, no unexplained jargon.

Rules you must follow:
1. You are triaging one INCIDENT - a cluster of one or more alerts already correlated by host/
   user/time window. Read all of them together as one story before deciding.
2. verdict must be one of: true_positive (real malicious/unwanted activity), false_positive
   (tooling error / misfire, not real activity at all), benign_positive (the activity is real
   but expected/authorized - e.g. IT admin's own remote session - so it still gets a note but
   isn't an incident), needs_investigation (you cannot confidently call it from the evidence
   given - this is a legitimate, honest answer, not a cop-out; use it rather than guessing).
3. confidence (0-100) must reflect actual certainty. A single vague low-severity alert with no
   corroboration should rarely be above 50-60 confidence in either direction.
4. severity is the technical severity of what's actually happening (informational/low/medium/
   high/critical), independent of suggested_priority.
5. suggested_priority (P1-P4) is the PSA ticket queue priority: P1 = drop everything, active
   compromise/ransomware-in-progress; P2 = same-day; P3 = this week; P4 = FYI/log only. Weigh
   the client's stated criticality tier into this, not just technical severity - the same
   alert can be P2 for a standard client and P1 for a "crown_jewel" client.
6. attack_techniques: list MITRE ATT&CK technique IDs (e.g. "T1059.001") ONLY when you are
   reasonably confident they apply given the evidence. Do not pad the list to look thorough -
   omit anything you're not confident about.
7. analyst_notes: one paragraph, written for the ticket. Say what you saw, why you called it
   what you called it, and what's still uncertain.
8. tailored_recommendation: 2-4 sentences of what's specific to THIS incident, on top of (not
   repeating) the standard playbook the tech will already see for this alert category - e.g.
   which specific host/account needs isolating, what to check first, what NOT to do (like
   rebooting a box you need to forensically preserve).
9. You must call the emit_triage tool exactly once with your final answer. Do not respond in
   plain text.
"""


def build_triage_prompt(incident: Incident, client: Client) -> str:
    alert_lines = []
    for a in incident.alerts:
        alert_lines.append(
            f"- [{a.source}] {a.timestamp.isoformat()} severity={a.severity_raw or a.severity.value} "
            f"category={a.category} title=\"{a.title}\" user={a.user or '(none)'}\n"
            f"  description: {a.description or '(none provided)'}"
        )
    alerts_block = "\n".join(alert_lines)

    return f"""Client: {client.name} (id={client.client_id}, criticality_tier={client.criticality_tier})
Host: {incident.host or '(no host - grouped by user)'}
Primary user: {incident.user or '(none)'}
Window: {incident.opened_at.isoformat()} to {incident.closed_at.isoformat()}
Alert sources involved: {', '.join(incident.sources)}
Alert count: {len(incident.alerts)}

Correlated alerts in this incident (already grouped by host/user + time window - read as one story):
{alerts_block}

Triage this incident now and call emit_triage with your verdict, confidence, severity,
suggested_priority, attack_techniques, analyst_notes, and tailored_recommendation.
"""


EMIT_TRIAGE_TOOL = {
    "name": "emit_triage",
    "description": "Submit the final triage verdict and remediation guidance for this incident.",
    "input_schema": {
        "type": "object",
        "properties": {
            "verdict": {
                "type": "string",
                "enum": ["true_positive", "false_positive", "benign_positive", "needs_investigation"],
            },
            "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
            "severity": {
                "type": "string",
                "enum": ["informational", "low", "medium", "high", "critical"],
            },
            "suggested_priority": {"type": "string", "enum": ["P1", "P2", "P3", "P4"]},
            "summary": {"type": "string", "description": "One line, for a ticket queue list."},
            "analyst_notes": {"type": "string", "description": "One paragraph for the ticket."},
            "attack_techniques": {
                "type": "array",
                "items": {"type": "string"},
                "description": "MITRE ATT&CK technique IDs you are confident apply, e.g. ['T1059.001']. Empty array if none.",
            },
            "tailored_recommendation": {
                "type": "string",
                "description": "2-4 incident-specific sentences on top of the standard category playbook.",
            },
        },
        "required": [
            "verdict",
            "confidence",
            "severity",
            "suggested_priority",
            "summary",
            "analyst_notes",
            "attack_techniques",
            "tailored_recommendation",
        ],
    },
}
