"""Cluster insecure patterns that recur across the codebase.

Rather than running a second, separate clone-detection pass over every file,
this works off the findings the rule engine already produced: an LLM asked to
"add an endpoint like the others" tends to copy-paste the *same* vulnerable
line verbatim (same rule firing, same normalized shape) into every new
handler. Two or more occurrences of the same rule with the same normalized
snippet, at distinct file:line locations, get collapsed into one
higher-severity cluster finding instead of N separate low-signal ones - the
point being that a pattern repeated on purpose across a codebase is a
systemic issue, not a typo.
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict

from vibecheck.models import Category, Finding, Severity, severity_rank
from vibecheck.rules.catalog import VIBE_DUP_INSECURE_CLUSTER

# Tokens that define the *shape* of a dangerous pattern and must survive
# normalization (otherwise `eval(x)` and `subprocess.run(x, shell=True)`
# would normalize to the same thing and cluster together incorrectly).
_KEEP_TOKENS = frozenset({
    "eval", "exec", "os", "system", "popen", "subprocess", "run", "call", "Popen",
    "check_call", "check_output", "shell", "True", "False", "None", "pickle", "load",
    "loads", "yaml", "execute", "executemany", "query", "cursor", "format", "new",
    "Function", "child_process", "verify",
})

_STRING_RE = re.compile(r"""(['"`])(?:(?!\1).)*\1""")
_NUMBER_RE = re.compile(r"\b\d+\b")
_IDENTIFIER_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")


def normalize_snippet(snippet: str) -> str:
    text = _STRING_RE.sub("STR", snippet)
    text = _NUMBER_RE.sub("NUM", text)
    text = _IDENTIFIER_RE.sub(lambda m: m.group(0) if m.group(0) in _KEEP_TOKENS else "VAR", text)
    return re.sub(r"\s+", " ", text).strip()


def cluster_duplicate_insecure_findings(findings: list[Finding], min_occurrences: int = 2) -> list[Finding]:
    groups: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for finding in findings:
        if not finding.snippet:
            continue
        groups[(finding.rule_id, normalize_snippet(finding.snippet))].append(finding)

    clusters: list[Finding] = []
    for (rule_id, normalized), members in groups.items():
        locations = sorted({(m.file, m.line) for m in members})
        if len(locations) < min_occurrences:
            continue

        worst = min(members, key=lambda m: severity_rank(m.severity))
        digest = hashlib.sha1(f"{rule_id}:{normalized}".encode("utf-8")).hexdigest()[:10]
        first_file, first_line = locations[0]

        clusters.append(Finding(
            finding_id=f"{VIBE_DUP_INSECURE_CLUSTER}:{digest}",
            rule_id=VIBE_DUP_INSECURE_CLUSTER,
            severity=Severity.CRITICAL if severity_rank(worst.severity) <= severity_rank(Severity.HIGH) else Severity.HIGH,
            category=Category.INSECURE_DUPLICATION,
            title=f"Same insecure pattern ({worst.title}) copy-pasted across {len(locations)} locations",
            description=(
                f"The same '{rule_id}' pattern - '{worst.title}' - appears at {len(locations)} distinct "
                "locations with near-identical code. A single instance of an insecure pattern can be an "
                "oversight; the same exact pattern reproduced across the codebase is what happens when an "
                "LLM is asked to replicate an existing (already-vulnerable) handler for a new endpoint - "
                "fixing only the first occurrence found leaves every copy exploitable."
            ),
            file=first_file,
            line=first_line,
            snippet=worst.snippet,
            evidence={
                "source_rule": rule_id,
                "occurrence_count": len(locations),
                "occurrences": [{"file": f, "line": ln} for f, ln in locations],
            },
            recommendation=f"Fix the underlying issue once in a shared helper and replace every one of the {len(locations)} occurrences with a call to it, rather than patching each copy independently.",
            references=worst.references,
        ))

    return clusters
