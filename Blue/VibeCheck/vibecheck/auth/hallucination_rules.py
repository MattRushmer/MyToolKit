"""Detect auth checks that look real but don't actually gate anything - the
"hallucinated auth" failure mode: an LLM writes code that reads as an
authorization check because that's the statistically expected shape for a
protected route, without it actually being wired up to deny access.

Five independent signals, each cheap and precise on its own rather than one
big fuzzy "does this look protected" score:

  VIBE-AUTH-01 a guard decorator/middleware name that resolves to nothing
               defined or imported anywhere in the project (would NameError
               the first time this route is actually hit)
  VIBE-AUTH-02 the auth check is called inside a try/except whose handler
               swallows the error and falls through instead of denying
  VIBE-AUTH-03 the auth condition is tautological (`... or True`, `x == x`)
  VIBE-AUTH-04 an auth-named helper function is defined but never referenced
  VIBE-AUTH-05 one route is missing the guard that all its siblings (same
               file, same URL prefix) carry
"""
from __future__ import annotations

import ast
import re

from vibecheck.auth.models import RouteInfo
from vibecheck.auth.symbol_index import SymbolIndex
from vibecheck.models import Category, Finding, Severity, SourceFile
from vibecheck.rules.catalog import (
    CWE_1188_MISCONFIGURED_DEFAULT,
    OWASP_A01_BROKEN_ACCESS_CONTROL,
    VIBE_AUTH_FAIL_OPEN,
    VIBE_AUTH_SIBLING_GAP,
    VIBE_AUTH_TAUTOLOGY,
    VIBE_AUTH_UNDEFINED_DECORATOR,
    VIBE_AUTH_UNUSED_HELPER,
)

_REFERENCES = (CWE_1188_MISCONFIGURED_DEFAULT, OWASP_A01_BROKEN_ACCESS_CONTROL)

_AUTH_GUARD_NAME_RE = re.compile(r"(?i)(auth|login|admin|permission|perm|require|jwt|token|access|role|session|credential)")
_AUTH_CALL_NAME_RE = re.compile(r"(?i)^(verify|check|require|ensure|validate|authenticate|authorize)")
_AUTH_CONTEXT_LINE_RE = re.compile(r"(?i)(auth|admin|permission|perm|role|login|access|token|is_staff|is_superuser|credential)")

# Frameworks resolve some guard names through decorators/middleware imported
# under a name our project-wide scan can't see (e.g. re-exported through a
# package __init__). Common ones are allowlisted so they never false-positive.
_KNOWN_FRAMEWORK_GUARDS = frozenset({
    "login_required", "jwt_required", "permission_required", "roles_required",
    "requires_auth", "authenticated", "csrf_protect", "cross_origin",
})


def _resolved_call_name(node: ast.expr) -> str:
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def check_undefined_guards(routes: list[RouteInfo], symbol_index: SymbolIndex) -> list[Finding]:
    findings: list[Finding] = []
    for route in routes:
        if route.file in symbol_index.star_import_files:
            continue  # a `from x import *` in this file could resolve any bare name - can't safely flag
        for name in route.bare_guard_names:
            if not _AUTH_GUARD_NAME_RE.search(name):
                continue  # e.g. @retry, @rate_limited - not an auth claim, not this rule's business
            if name in _KNOWN_FRAMEWORK_GUARDS or name in symbol_index.defined_names:
                continue
            findings.append(Finding(
                finding_id=f"{VIBE_AUTH_UNDEFINED_DECORATOR}:{route.file}:{route.line}:{name}",
                rule_id=VIBE_AUTH_UNDEFINED_DECORATOR,
                severity=Severity.CRITICAL,
                category=Category.HALLUCINATED_AUTH,
                title=f"Guard '{name}' on {route.method} {route.path} is never defined or imported anywhere in the project",
                description=(
                    f"'{name}' is referenced as a guard on this route but no function, class, or import "
                    f"binding named '{name}' exists anywhere in the scanned codebase. Either this route has "
                    "never actually been exercised (it would raise NameError on first hit), or the real "
                    "guard was refactored/renamed and this reference was never updated - both mean the "
                    "route is currently unprotected."
                ),
                file=route.file,
                line=route.line,
                snippet=f"{route.method} {route.path} -> {route.handler_name}() guarded by '{name}'",
                evidence={"handler": route.handler_name, "guard": name, "method": route.method, "path": route.path},
                recommendation=f"Define or import '{name}', or replace it with the project's real auth guard.",
                references=_REFERENCES,
            ))
    return findings


def _is_fail_open_handler(handler: ast.ExceptHandler) -> bool:
    for node in ast.walk(handler):
        if isinstance(node, ast.Raise):
            return False
        if isinstance(node, ast.Return):
            return False
        if isinstance(node, ast.Call):
            name = _resolved_call_name(node.func)
            if name in {"exit", "abort", "quit"}:
                return False
    return True


def _try_body_has_auth_call(try_node: ast.Try) -> bool:
    for stmt in try_node.body:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Call) and _AUTH_CALL_NAME_RE.match(_resolved_call_name(node.func)):
                return True
    return False


def check_fail_open_auth(source: SourceFile) -> list[Finding]:
    try:
        tree = ast.parse(source.text, filename=source.rel_path)
    except SyntaxError:
        return []

    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        if not _try_body_has_auth_call(node):
            continue
        if not any(_is_fail_open_handler(h) for h in node.handlers):
            continue
        findings.append(Finding(
            finding_id=f"{VIBE_AUTH_FAIL_OPEN}:{source.rel_path}:{node.lineno}",
            rule_id=VIBE_AUTH_FAIL_OPEN,
            severity=Severity.CRITICAL,
            category=Category.HALLUCINATED_AUTH,
            title="Auth check fails open: exception is swallowed and execution continues",
            description=(
                "This try/except calls what looks like an auth check, but the except handler neither "
                "re-raises, returns, nor exits - so if the check raises (which is exactly how these "
                "checks usually signal 'denied'), control falls through to the code after the try block "
                "as if the check had passed."
            ),
            file=source.rel_path,
            line=node.lineno,
            snippet=source.lines[node.lineno - 1].strip()[:200] if 0 <= node.lineno - 1 < len(source.lines) else "",
            recommendation="Return/raise an explicit denial (e.g. `return \"forbidden\", 403` or re-raise) from the except block instead of continuing.",
            references=_REFERENCES,
        ))
    return findings


def _is_tautology(test: ast.expr) -> bool:
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or):
        return any(isinstance(v, ast.Constant) and v.value is True for v in test.values)
    if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq):
        left, right = test.left, test.comparators[0]
        return not isinstance(left, ast.Constant) and ast.dump(left) == ast.dump(right)
    return False


def check_tautological_auth(source: SourceFile) -> list[Finding]:
    try:
        tree = ast.parse(source.text, filename=source.rel_path)
    except SyntaxError:
        return []

    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        if not _is_tautology(node.test):
            continue
        line_idx = node.lineno - 1
        line_text = source.lines[line_idx] if 0 <= line_idx < len(source.lines) else ""
        if not _AUTH_CONTEXT_LINE_RE.search(line_text):
            continue
        findings.append(Finding(
            finding_id=f"{VIBE_AUTH_TAUTOLOGY}:{source.rel_path}:{node.lineno}",
            rule_id=VIBE_AUTH_TAUTOLOGY,
            severity=Severity.CRITICAL,
            category=Category.HALLUCINATED_AUTH,
            title="Auth condition is always true",
            description="This condition mentions auth/permission/role state but is structurally always "
            "true (an `or True` branch, or a value compared to itself), so it can never deny access.",
            file=source.rel_path,
            line=node.lineno,
            snippet=line_text.strip()[:200],
            recommendation="Remove the tautological branch/comparison so the condition can actually evaluate to false.",
            references=_REFERENCES,
        ))
    return findings


def _looks_like_auth_helper_name(name: str) -> bool:
    lowered = name.lower()
    verbs = ("verify", "check", "require", "ensure", "validate", "authenticate", "authorize", "is_")
    nouns = ("auth", "admin", "permission", "perm", "access", "token", "login", "role", "session", "credential")
    return any(lowered.startswith(v) for v in verbs) and any(n in lowered for n in nouns)


def check_unused_auth_helpers(symbol_index: SymbolIndex, route_handler_names: frozenset[str]) -> list[Finding]:
    findings: list[Finding] = []
    for fd in symbol_index.function_defs:
        if fd.name in route_handler_names:
            continue  # route handlers are invoked externally over HTTP, not from within the codebase
        if not _looks_like_auth_helper_name(fd.name):
            continue
        if fd.name in symbol_index.referenced_names:
            continue
        findings.append(Finding(
            finding_id=f"{VIBE_AUTH_UNUSED_HELPER}:{fd.file}:{fd.line}:{fd.name}",
            rule_id=VIBE_AUTH_UNUSED_HELPER,
            severity=Severity.HIGH,
            category=Category.HALLUCINATED_AUTH,
            title=f"Auth-looking helper '{fd.name}' is defined but never called",
            description=(
                f"'{fd.name}' reads as an authorization check by name, but nothing in the scanned codebase "
                "calls, decorates with, or otherwise references it. Either it's dead code left over from a "
                "refactor, or it was meant to guard something and the call site was never wired up - the "
                "protection it implies does not currently exist anywhere."
            ),
            file=fd.file,
            line=fd.line,
            snippet=f"def {fd.name}(...): ...",
            recommendation="Wire this helper into the route(s) it's meant to protect, or delete it if it's dead code.",
            references=_REFERENCES,
        ))
    return findings


def _static_prefix(path: str) -> str:
    segments = []
    for seg in path.split("/"):
        if not seg:
            continue
        if seg[0] in "<:{":
            break
        segments.append(seg)
    return "/".join(segments)


def check_sibling_route_gaps(routes: list[RouteInfo]) -> list[Finding]:
    groups: dict[tuple[str, str], list[RouteInfo]] = {}
    for route in routes:
        if route.path == "?":
            continue
        prefix = _static_prefix(route.path)
        if not prefix:
            continue
        groups.setdefault((route.file, prefix), []).append(route)

    findings: list[Finding] = []
    for (_file, prefix), group in groups.items():
        if len(group) < 2:
            continue
        guarded = [r for r in group if any(_AUTH_GUARD_NAME_RE.search(g) for g in r.guard_names)]
        unguarded = [r for r in group if r not in guarded]
        if not guarded or not unguarded:
            continue
        guarded_desc = ", ".join(f"{r.method} {r.path} (line {r.line})" for r in guarded)
        for route in unguarded:
            findings.append(Finding(
                finding_id=f"{VIBE_AUTH_SIBLING_GAP}:{route.file}:{route.line}",
                rule_id=VIBE_AUTH_SIBLING_GAP,
                severity=Severity.HIGH,
                category=Category.HALLUCINATED_AUTH,
                title=f"{route.method} {route.path} has no auth guard, unlike its sibling route(s) under /{prefix}",
                description=(
                    f"Every other route under '/{prefix}' in this file carries an auth guard "
                    f"({guarded_desc}), but this one doesn't. This is the classic copy-paste-and-modify "
                    "pattern where the guard decorator gets dropped on one variant (often when adding a new "
                    "HTTP method to an existing resource) without a deliberate decision to leave it open."
                ),
                file=route.file,
                line=route.line,
                snippet=f"{route.method} {route.path} -> {route.handler_name}()",
                evidence={"handler": route.handler_name, "guarded_siblings": [f"{r.method} {r.path}" for r in guarded]},
                recommendation="Confirm this route is intentionally public; if not, add the same guard its siblings use.",
                references=_REFERENCES,
            ))
    return findings
