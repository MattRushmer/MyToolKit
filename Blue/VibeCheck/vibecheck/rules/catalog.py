"""Stable rule IDs and their external references, shared across rule modules
so every finding cites a checkable ID instead of an invented one.

The VIBE-* IDs are this project's own taxonomy for failure modes that are
specific to (or wildly overrepresented in) LLM-generated code, as opposed to
generic vulnerability classes that already have a CWE/OWASP home.
"""
from __future__ import annotations

# --- LLM-specific: hallucinated / decorative auth -------------------------
VIBE_AUTH_UNDEFINED_DECORATOR = "VIBE-AUTH-01"  # route guarded by a decorator/middleware name that's never defined/imported anywhere in the codebase
VIBE_AUTH_FAIL_OPEN = "VIBE-AUTH-02"            # auth check wrapped in a try/except that swallows the error and falls through to allow access
VIBE_AUTH_TAUTOLOGY = "VIBE-AUTH-03"            # auth condition that is always true (`or True`, `if True or ...`, comparing a var to itself)
VIBE_AUTH_UNUSED_HELPER = "VIBE-AUTH-04"        # an auth-looking helper function is defined but never called anywhere
VIBE_AUTH_SIBLING_GAP = "VIBE-AUTH-05"          # one route is missing the auth decorator/middleware that all its sibling routes in the same file carry

# --- LLM-specific: copy-pasted insecure pattern proliferation -------------
VIBE_DUP_INSECURE_CLUSTER = "VIBE-DUP-01"       # the same insecure code pattern (already flagged by another rule) recurs 2+ times across the codebase

# --- LLM-specific: hallucinated / invented dependencies -------------------
VIBE_DEP_NOT_ON_REGISTRY = "VIBE-DEP-01"        # a declared/imported package does not exist on the real package registry (slopsquatting risk)
VIBE_DEP_REGISTRY_UNCHECKED = "VIBE-DEP-02"     # informational: dependency existence could not be checked (offline / registry error)

# --- Baseline SAST, still tuned for what shows up in vibe-coded apps ------
VIBE_SEC_HARDCODED_SECRET = "VIBE-SEC-01"
VIBE_SEC_DANGEROUS_EVAL = "VIBE-SEC-02"
VIBE_SEC_SHELL_INJECTION = "VIBE-SEC-03"
VIBE_SEC_UNSAFE_DESERIALIZATION = "VIBE-SEC-04"
VIBE_SEC_SQL_INJECTION = "VIBE-SEC-05"
VIBE_SEC_TLS_VERIFICATION_DISABLED = "VIBE-SEC-06"
VIBE_SEC_PERMISSIVE_CORS = "VIBE-SEC-07"
VIBE_SEC_DEBUG_ENABLED = "VIBE-SEC-08"
VIBE_SEC_WEAK_PASSWORD_HASH = "VIBE-SEC-09"

# External references cited alongside the VIBE-SEC-* baseline rules.
CWE_798_HARDCODED_CREDENTIALS = "CWE-798"
CWE_95_EVAL_INJECTION = "CWE-95"
CWE_78_OS_COMMAND_INJECTION = "CWE-78"
CWE_502_UNSAFE_DESERIALIZATION = "CWE-502"
CWE_89_SQL_INJECTION = "CWE-89"
CWE_295_IMPROPER_CERT_VALIDATION = "CWE-295"
CWE_942_PERMISSIVE_CORS = "CWE-942"
CWE_489_DEBUG_CODE = "CWE-489"
CWE_916_WEAK_HASH = "CWE-916"
CWE_1188_MISCONFIGURED_DEFAULT = "CWE-1188"  # umbrella for the VIBE-AUTH-* decorative-auth findings
CWE_1357_SUPPLY_CHAIN = "CWE-1357"           # umbrella for VIBE-DEP-01 hallucinated dependency

OWASP_A01_BROKEN_ACCESS_CONTROL = "OWASP-A01:2021"
OWASP_A02_CRYPTO_FAILURES = "OWASP-A02:2021"
OWASP_A03_INJECTION = "OWASP-A03:2021"
OWASP_A05_SECURITY_MISCONFIGURATION = "OWASP-A05:2021"
OWASP_A08_SOFTWARE_DATA_INTEGRITY_FAILURES = "OWASP-A08:2021"
