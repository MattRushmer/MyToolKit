"""No-LLM-key fallback triage, plus the pre-score used to order the queue
before an LLM verdict exists.

This deliberately never returns FALSE_POSITIVE or BENIGN_POSITIVE - clearing
an alert is a judgment call the heuristic isn't equipped to make, so it always
escalates to NEEDS_INVESTIGATION at a low, clearly-labeled confidence instead
of silently suppressing something a keyword scan just didn't recognize. That
mirrors Detection Forge's fail-closed noise scoring: an unscored/uncertain
incident is treated as needing eyes on it, not treated as safe by default.
"""
from __future__ import annotations

from soc_copilot.models import AttackTechniqueTag, Incident, Priority, Severity, TriageResult, Verdict
from soc_copilot.triage.attack_reference import lookup

_SEVERITY_BASE_SCORE = {
    Severity.INFORMATIONAL: 5,
    Severity.LOW: 20,
    Severity.MEDIUM: 40,
    Severity.HIGH: 65,
    Severity.CRITICAL: 85,
}

# (keyword, technique_id) - first match per incident text wins per keyword; text is a bag of
# words so multiple techniques can be surfaced for one incident.
_KEYWORD_TECHNIQUES = [
    ("ransomware", "T1486"),
    ("canary", "T1486"),
    ("encrypt", "T1486"),
    ("lsass", "T1003.001"),
    ("credential dump", "T1003.001"),
    ("mimikatz", "T1003.001"),
    ("procdump", "T1003.001"),
    ("encoded command", "T1059.001"),
    ("powershell", "T1059.001"),
    ("injection", "T1055"),
    ("injected", "T1055"),
    ("macro", "T1204.002"),
    ("phishing", "T1566"),
    ("impossible travel", "T1078"),
    ("suspicious sign-in", "T1078"),
    ("brute force", "T1110"),
    ("password spray", "T1110.003"),
    ("port scan", "T1046"),
    ("registry run key", "T1547.001"),
    ("persistence", "T1547"),
    ("scheduled task", "T1053.005"),
    ("exfil", "T1041"),
]

# Independently corroborated by keyword AND at least one real security tool -
# these push the score up hard because they're rarely benign.
_HIGH_CONFIDENCE_KEYWORDS = ("ransomware", "canary", "lsass", "mimikatz", "procdump", "credential dump")


def _incident_text(incident: Incident) -> str:
    return " ".join(f"{a.title} {a.description} {a.category}" for a in incident.alerts).lower()


def _score_to_severity(score: float) -> Severity:
    if score >= 80:
        return Severity.CRITICAL
    if score >= 60:
        return Severity.HIGH
    if score >= 40:
        return Severity.MEDIUM
    if score >= 20:
        return Severity.LOW
    return Severity.INFORMATIONAL


def _score_to_priority(score: float) -> Priority:
    if score >= 60:
        return Priority.P1
    if score >= 40:
        return Priority.P2
    if score >= 20:
        return Priority.P3
    return Priority.P4


def pre_score(incident: Incident) -> float:
    """0-100 heuristic priority score, used both as the no-LLM-key fallback
    severity and to order the queue before/without an LLM verdict."""
    max_severity = max((a.severity for a in incident.alerts), key=lambda s: list(Severity).index(s))
    score = float(_SEVERITY_BASE_SCORE[max_severity])
    if len(incident.alerts) >= 3:
        score += 10
    if len(incident.sources) > 1:
        score += 10
    text = _incident_text(incident)
    if any(kw in text for kw in _HIGH_CONFIDENCE_KEYWORDS):
        score += 15
    return min(score, 100.0)


def detect_techniques(incident: Incident) -> list[AttackTechniqueTag]:
    text = _incident_text(incident)
    found: dict[str, AttackTechniqueTag] = {}
    for keyword, technique_id in _KEYWORD_TECHNIQUES:
        if keyword in text and technique_id not in found:
            recognized, name = lookup(technique_id)
            found[technique_id] = AttackTechniqueTag(technique_id=technique_id, technique_name=name, recognized=recognized)
    return list(found.values())


def heuristic_triage(incident: Incident) -> TriageResult:
    score = pre_score(incident)
    severity = _score_to_severity(score)
    priority = _score_to_priority(score)
    techniques = detect_techniques(incident)
    alert_titles = "; ".join(dict.fromkeys(a.title for a in incident.alerts))
    return TriageResult(
        incident_id=incident.incident_id,
        verdict=Verdict.NEEDS_INVESTIGATION,
        confidence=35,  # deliberately low/fixed: this is a keyword heuristic, not real analysis
        severity=severity,
        suggested_priority=priority,
        summary=f"[heuristic, no LLM key] {len(incident.alerts)} alert(s) on {incident.host or incident.user}: {alert_titles}"[:280],
        analyst_notes=(
            "Generated without an LLM verdict (ANTHROPIC_API_KEY not configured). This is a "
            "keyword/severity heuristic only - it flags for review, it does not clear anything. "
            f"Score {score:.0f}/100 from: peak source severity, {len(incident.alerts)} correlated "
            f"alert(s) across {len(incident.sources)} source(s), and keyword matches. Set "
            "ANTHROPIC_API_KEY for a real triage verdict, confidence, and recommendation."
        ),
        attack_techniques=techniques,
        is_llm_generated=False,
        model_used="heuristic-v1",
    )
