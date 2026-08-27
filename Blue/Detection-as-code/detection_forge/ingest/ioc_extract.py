"""Regex-based IOC extraction from raw CTI report text.

This is deliberately not exhaustive threat-intel NLP — it's a fast first pass
that gives the LLM generator concrete anchors (hashes, CVEs, paths, domains)
instead of asking it to re-read the whole report for every fact.
"""
from __future__ import annotations

import re

from detection_forge.models import ExtractedIOC

_PATTERNS: dict[str, re.Pattern[str]] = {
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"(?:com|net|org|io|ru|cn|xyz|top|info|biz|co|gov|edu|info|online|site|club|icu)\b",
        re.IGNORECASE,
    ),
    "windows_path": re.compile(
        r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n\s,;]+\\)*[^\\/:*?\"<>|\r\n\s,;]+"
    ),
    "registry_key": re.compile(
        r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU)\\[^\s\"']+", re.IGNORECASE
    ),
}

# Rough ordering to prevent a sha256 substring being reported again as md5, etc.
_TYPE_PRIORITY = ["cve", "sha256", "sha1", "md5", "ipv4", "windows_path", "registry_key", "domain"]


def extract_iocs(text: str, context_window: int = 60) -> list[ExtractedIOC]:
    """Extract IOCs from text, deduplicated, each carrying a short surrounding snippet."""
    found: dict[tuple[str, str], ExtractedIOC] = {}

    for ioc_type in _TYPE_PRIORITY:
        pattern = _PATTERNS[ioc_type]
        for match in pattern.finditer(text):
            value = match.group(0)
            key = (ioc_type, value.lower())
            if key in found:
                continue
            # skip hash matches that are substrings already captured as a longer hash type
            if ioc_type in ("sha1", "md5") and any(
                value.lower() in existing.value.lower()
                for (etype, _), existing in found.items()
                if etype == "sha256"
            ):
                continue
            start = max(0, match.start() - context_window)
            end = min(len(text), match.end() + context_window)
            snippet = text[start:end].replace("\n", " ").strip()
            found[key] = ExtractedIOC(ioc_type=ioc_type, value=value, context=snippet)

    return list(found.values())


def extract_cve_ids(text: str) -> list[str]:
    seen: list[str] = []
    for match in _PATTERNS["cve"].finditer(text):
        cve = match.group(0).upper()
        if cve not in seen:
            seen.append(cve)
    return seen
