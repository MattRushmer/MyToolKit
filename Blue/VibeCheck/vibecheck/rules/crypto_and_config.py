"""Weak password hashing, disabled TLS verification, permissive CORS, and
debug mode left enabled - regex-based since these are shallow textual
patterns (a keyword argument, a settings assignment) rather than something
that benefits from full AST analysis."""
from __future__ import annotations

import re

from vibecheck.models import Category, Finding, Severity, SourceFile
from vibecheck.rules.catalog import (
    CWE_295_IMPROPER_CERT_VALIDATION,
    CWE_489_DEBUG_CODE,
    CWE_916_WEAK_HASH,
    CWE_942_PERMISSIVE_CORS,
    OWASP_A02_CRYPTO_FAILURES,
    OWASP_A05_SECURITY_MISCONFIGURATION,
    VIBE_SEC_DEBUG_ENABLED,
    VIBE_SEC_PERMISSIVE_CORS,
    VIBE_SEC_TLS_VERIFICATION_DISABLED,
    VIBE_SEC_WEAK_PASSWORD_HASH,
)

_WEAK_HASH_RE = re.compile(r"(?:hashlib\.(md5|sha1)\(|crypto\.createHash\(\s*['\"](md5|sha1)['\"])")
_PASSWORD_CONTEXT_RE = re.compile(r"(?i)pass(?:wd|word)|\bpwd\b")

_TLS_DISABLED_RE = re.compile(
    r"verify\s*=\s*False"
    r"|rejectUnauthorized\s*:\s*false"
    r"|ssl\._create_unverified_context"
    r"|CERT_NONE"
    r"|NODE_TLS_REJECT_UNAUTHORIZED['\"]?\s*[:=]\s*['\"]?0"
)

_CORS_WILDCARD_RE = re.compile(
    r"Access-Control-Allow-Origin[^=:,\n]{0,10}[:=,]\s*['\"]\*['\"]"
    r"|origins['\"]?\s*[:=]\s*\[?\s*['\"]\*['\"]"
)
_CORS_CREDENTIALS_RE = re.compile(
    r"Access-Control-Allow-Credentials[^=:,\n]{0,10}[:=,]\s*['\"]?true['\"]?"
    r"|supports_credentials\s*=\s*True"
    r"|credentials\s*:\s*true"
)

_DEBUG_ENABLED_RE = re.compile(
    r"\.run\([^)]*debug\s*=\s*True"
    r"|^\s*DEBUG\s*=\s*True\b"
    r"|config\[['\"]DEBUG['\"]\]\s*=\s*True"
)


def _finding(source: SourceFile, line_no: int, line: str, rule_id: str, category: Category, severity: Severity, title: str, description: str, recommendation: str, references: tuple[str, ...]) -> Finding:
    return Finding(
        finding_id=f"{rule_id}:{source.rel_path}:{line_no}",
        rule_id=rule_id,
        severity=severity,
        category=category,
        title=title,
        description=description,
        file=source.rel_path,
        line=line_no,
        snippet=line.strip()[:200],
        recommendation=recommendation,
        references=references,
    )


def check_crypto_and_config(source: SourceFile) -> list[Finding]:
    findings: list[Finding] = []
    cors_wildcard_lines: list[int] = []
    has_credentials_flag = False

    for line_no, line in enumerate(source.lines, start=1):
        hash_match = _WEAK_HASH_RE.search(line)
        if hash_match and _PASSWORD_CONTEXT_RE.search(line):
            algo = hash_match.group(1) or hash_match.group(2)
            findings.append(_finding(
                source, line_no, line, VIBE_SEC_WEAK_PASSWORD_HASH, Category.WEAK_CRYPTO, Severity.HIGH,
                f"Password hashed with {algo.upper()}",
                f"{algo.upper()} is fast and unsalted-by-default, making it practical to brute-force or "
                "rainbow-table a leaked password hash. It was never designed for password storage.",
                "Use a password-hashing KDF: bcrypt, scrypt, or argon2 (e.g. passlib's CryptContext, "
                "Django's PBKDF2/Argon2 hashers, or bcrypt.hashpw).",
                (CWE_916_WEAK_HASH, OWASP_A02_CRYPTO_FAILURES),
            ))

        if _TLS_DISABLED_RE.search(line):
            findings.append(_finding(
                source, line_no, line, VIBE_SEC_TLS_VERIFICATION_DISABLED, Category.INSECURE_CONFIG, Severity.HIGH,
                "TLS certificate verification disabled",
                "Disabling certificate verification removes protection against man-in-the-middle attacks - "
                "an LLM will often add this as a quick fix for a local self-signed-cert error and it then "
                "ships to production unnoticed.",
                "Keep verification on and fix the underlying cert (add the CA to the trust store, or use a "
                "properly signed cert) instead of disabling the check.",
                (CWE_295_IMPROPER_CERT_VALIDATION, OWASP_A05_SECURITY_MISCONFIGURATION),
            ))

        if _CORS_WILDCARD_RE.search(line):
            cors_wildcard_lines.append(line_no)
        if _CORS_CREDENTIALS_RE.search(line):
            has_credentials_flag = True

        if _DEBUG_ENABLED_RE.search(line):
            findings.append(_finding(
                source, line_no, line, VIBE_SEC_DEBUG_ENABLED, Category.INSECURE_CONFIG, Severity.HIGH,
                "Debug mode left enabled",
                "Framework debug mode (e.g. Flask's Werkzeug interactive debugger) can leak stack traces, "
                "source, and environment variables to any client that triggers an error - and Werkzeug's "
                "debugger console is a known remote-code-execution vector if it's reachable.",
                "Set debug=False (or drop the flag) before deploying; gate it behind an environment-specific "
                "config value that defaults to off.",
                (CWE_489_DEBUG_CODE, OWASP_A05_SECURITY_MISCONFIGURATION),
            ))

    for line_no in cors_wildcard_lines:
        severity = Severity.CRITICAL if has_credentials_flag else Severity.MEDIUM
        title = "Wildcard CORS origin combined with credentials" if has_credentials_flag else "Wildcard CORS origin"
        description = (
            "Access-Control-Allow-Origin: * paired with credentials support lets any website read "
            "authenticated responses on a logged-in user's behalf."
            if has_credentials_flag else
            "Access-Control-Allow-Origin: * allows any website to read this API's responses client-side. "
            "This is fine for a truly public, unauthenticated API but is very often left over from "
            "development scaffolding on an API that does carry sensitive data."
        )
        findings.append(_finding(
            source, line_no, source.lines[line_no - 1], VIBE_SEC_PERMISSIVE_CORS, Category.INSECURE_CONFIG, severity,
            title, description,
            "Set an explicit allowlist of trusted origins instead of '*', especially if credentials/cookies "
            "are involved.",
            (CWE_942_PERMISSIVE_CORS, OWASP_A05_SECURITY_MISCONFIGURATION),
        ))

    return findings
