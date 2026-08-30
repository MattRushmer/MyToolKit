"""Shared injection-pattern detection, used against two different surfaces:

  - rules/poisoning.py: a tool/resource/prompt's *static* description text.
  - probes/analyzer.py: a tool's *live response* content, from actually
    invoking it (see probes/active.py) - catches a compromised upstream or a
    backend that injects instructions into results it returns, which static
    description scanning can never see.

Kept as one module so the two callers can never drift into detecting
different things while calling themselves "the same check".
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from mcp_sentinel.models import Severity

_INJECTION_PHRASES = re.compile(
    r"(ignore (all|any|the)?\s*(previous|prior|above)\s*instructions?"
    r"|disregard (previous|prior|the)\s*(system\s*)?prompt"
    r"|do not (tell|inform|mention to)\s*the user"
    r"|without (asking|telling|informing)\s*the user"
    r"|new instructions?:"
    r"|you must (now|always)"
    r"|<system>|\[system\]|</?instructions?>"
    r"|before (calling|using|responding).{0,40}(also|first|silently)\s*call"
    r"|this tool must be called before)",
    re.IGNORECASE,
)

_HIDDEN_MARKUP = re.compile(r"<!--.*?-->|<span[^>]*display:\s*none[^>]*>", re.IGNORECASE | re.DOTALL)
_ZERO_WIDTH_CHARS = re.compile(r"[​‌‍⁠﻿]")
_LONG_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")

MAX_REASONABLE_LEN = 2000


@dataclass(frozen=True)
class PatternHit:
    rule: str
    severity: Severity
    title: str
    description: str
    evidence: dict


def _snippet(text: str, length: int = 200) -> str:
    return text[:length] + ("…" if len(text) > length else "")


def detect_injection_patterns(text: str, *, subject_label: str) -> list[PatternHit]:
    """`subject_label` is a human phrase describing what `text` is (e.g.
    "Tool 'search_docs' description" or "Tool 'fetch_url' response"),
    interpolated into each hit's title/description."""
    if not text:
        return []
    hits: list[PatternHit] = []

    if _INJECTION_PHRASES.search(text):
        hits.append(
            PatternHit(
                rule="phrase",
                severity=Severity.CRITICAL,
                title=f"{subject_label} contains instruction-injection phrasing",
                description=(
                    "Text matched known prompt-injection phrasing (e.g. 'ignore previous instructions', "
                    "'without asking the user'). An agent that trusts this text as data may follow it as a command."
                ),
                evidence={"snippet": _snippet(text)},
            )
        )

    if _HIDDEN_MARKUP.search(text):
        hits.append(
            PatternHit(
                rule="hidden-markup",
                severity=Severity.HIGH,
                title=f"{subject_label} contains hidden/invisible markup",
                description="HTML comments or display:none spans hide content from a human reading a UI rendering while a model still receives the full raw text.",
                evidence={"snippet": _snippet(text)},
            )
        )

    if _ZERO_WIDTH_CHARS.search(text):
        hits.append(
            PatternHit(
                rule="zero-width-chars",
                severity=Severity.HIGH,
                title=f"{subject_label} contains zero-width/invisible Unicode characters",
                description="Zero-width characters render as nothing but are still tokenized, and can hide text from human review or break up filtered keywords.",
                evidence={"snippet": _snippet(text)},
            )
        )

    if _LONG_BASE64_BLOB.search(text):
        hits.append(
            PatternHit(
                rule="base64-blob",
                severity=Severity.MEDIUM,
                title=f"{subject_label} contains a large encoded blob",
                description="A long base64-like run is unusual for human-facing content and may smuggle encoded instructions or data past naive keyword filters.",
                evidence={"snippet": _snippet(text)},
            )
        )

    if len(text) > MAX_REASONABLE_LEN:
        hits.append(
            PatternHit(
                rule="oversized",
                severity=Severity.LOW,
                title=f"{subject_label} is unusually long ({len(text)} chars)",
                description="An oversized text blob is a common way to bury injected instructions where a human reviewer is unlikely to read it in full.",
                evidence={"length": len(text)},
            )
        )

    return hits
