"""Hardcoded secret/credential detection.

Two layers: known vendor key *shapes* (fires regardless of variable name,
since these formats are essentially unique to being a real credential) and a
generic *suspiciously-named-variable holding a literal string* heuristic
(needs a placeholder/entropy filter to keep the false-positive rate down -
`os.environ["API_KEY"]` and `API_KEY = "changeme"` should never fire).
"""
from __future__ import annotations

import math
import re

from vibecheck.models import Category, Finding, Severity, SourceFile
from vibecheck.rules.catalog import CWE_798_HARDCODED_CREDENTIALS, OWASP_A02_CRYPTO_FAILURES, VIBE_SEC_HARDCODED_SECRET

# (label, pattern, severity) - matched independent of surrounding variable name.
_VENDOR_KEY_PATTERNS: tuple[tuple[str, re.Pattern[str], Severity], ...] = (
    ("AWS access key ID", re.compile(r"AKIA[0-9A-Z]{16}"), Severity.CRITICAL),
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9\-_]{20,}"), Severity.CRITICAL),
    ("OpenAI API key", re.compile(r"sk-(?!ant-)[A-Za-z0-9]{20,}"), Severity.CRITICAL),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36}"), Severity.CRITICAL),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,48}"), Severity.HIGH),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), Severity.HIGH),
    ("Private key block", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), Severity.CRITICAL),
)

# name=value / name: value / name := value, single or double quoted.
_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    \b([A-Za-z_][A-Za-z0-9_]*(?:secret|token|passwd|password|pwd|api[_-]?key|access[_-]?key|auth[_-]?key)[A-Za-z0-9_]*)
    \s*[:=]\s*
    ["']([^"'\n]{8,200})["']
    """
)

_PLACEHOLDER_MARKERS = (
    "changeme", "change_me", "your_", "youre", "xxxx", "placeholder", "example",
    "insert", "todo", "dummy", "fake", "replace", "<", "$", "{{", "%(", "%s",
    "test", "sample", "none", "null", "...",
)

# A value built from a reference to an env var / config object isn't a literal
# secret even though the regex above only inspects the quoted text; callers
# pass the *whole matched line* here too so we can bail if it's clearly an
# env-var lookup like `os.environ["API_KEY"]` or `process.env.API_KEY`.
_ENV_LOOKUP_HINTS = ("os.environ", "os.getenv", "process.env", "getenv(")


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _looks_like_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in _PLACEHOLDER_MARKERS)


def check_secrets(source: SourceFile) -> list[Finding]:
    findings: list[Finding] = []

    for line_no, line in enumerate(source.lines, start=1):
        if any(hint in line for hint in _ENV_LOOKUP_HINTS):
            continue

        for label, pattern, severity in _VENDOR_KEY_PATTERNS:
            match = pattern.search(line)
            if match:
                findings.append(_make_finding(source, line_no, line, severity, f"Hardcoded {label} detected", matched=match.group(0)))

        for match in _ASSIGNMENT_RE.finditer(line):
            var_name, value = match.group(1), match.group(2)
            if _looks_like_placeholder(value):
                continue
            entropy = _shannon_entropy(value)
            severity = Severity.HIGH if entropy >= 3.5 else Severity.MEDIUM
            findings.append(
                _make_finding(
                    source, line_no, line, severity,
                    f"Hardcoded credential-like value assigned to '{var_name}'",
                    matched=f"{var_name} = <redacted, entropy {entropy:.1f}>",
                )
            )

    return findings


def _make_finding(source: SourceFile, line_no: int, line: str, severity: Severity, title: str, matched: str) -> Finding:
    return Finding(
        finding_id=f"{VIBE_SEC_HARDCODED_SECRET}:{source.rel_path}:{line_no}",
        rule_id=VIBE_SEC_HARDCODED_SECRET,
        severity=severity,
        category=Category.HARDCODED_SECRET,
        title=title,
        description=(
            "A credential-shaped literal is embedded directly in source. LLM assistants "
            "routinely inline a working key while scaffolding an example and it survives "
            "into the committed version unnoticed."
        ),
        file=source.rel_path,
        line=line_no,
        snippet=line.strip()[:200],
        evidence={"matched": matched},
        recommendation="Move this value to an environment variable or secret manager, rotate it (assume it is already compromised if this was ever pushed), and add it to .gitignore/.env handling.",
        references=(CWE_798_HARDCODED_CREDENTIALS, OWASP_A02_CRYPTO_FAILURES),
    )
