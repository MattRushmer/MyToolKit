"""SQL injection via dynamically-built query strings.

The distinguishing signal is *how* the query string was built, not that a
DB call happened: `cursor.execute("SELECT * FROM t WHERE id=%s", (id,))` is
the correct parameterized form and must not fire, while
`cursor.execute(f"SELECT * FROM t WHERE id={id}")` builds attacker-reachable
SQL text directly and must. This is exactly the shortcut an LLM reaches for
when asked to "filter by the id from the request" - parameterization is one
extra step it frequently skips.
"""
from __future__ import annotations

import ast
import re

from vibecheck.models import Category, Finding, Language, Severity, SourceFile
from vibecheck.rules.catalog import CWE_89_SQL_INJECTION, OWASP_A03_INJECTION, VIBE_SEC_SQL_INJECTION

_EXEC_METHODS = {"execute", "executemany"}


def _is_dynamically_built(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):  # f-string
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):  # concat or %-format
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False


def _snippet(source: SourceFile, lineno: int) -> str:
    idx = lineno - 1
    return source.lines[idx].strip()[:200] if 0 <= idx < len(source.lines) else ""


def _python_finding(source: SourceFile, node: ast.Call) -> Finding:
    lineno = node.lineno
    return Finding(
        finding_id=f"{VIBE_SEC_SQL_INJECTION}:{source.rel_path}:{lineno}",
        rule_id=VIBE_SEC_SQL_INJECTION,
        severity=Severity.CRITICAL,
        category=Category.INJECTION,
        title="SQL query built from an f-string/concatenation/%-format",
        description=(
            "The query text passed to execute() is assembled at runtime instead of using the driver's "
            "parameter placeholders, so any value that reaches this string becomes part of the SQL "
            "grammar itself."
        ),
        file=source.rel_path,
        line=lineno,
        snippet=_snippet(source, lineno),
        recommendation="Use parameterized queries: cursor.execute(\"...WHERE id=%s\", (id,)) (or the "
        "equivalent ? / :name placeholder for your driver) instead of building the SQL string.",
        references=(CWE_89_SQL_INJECTION, OWASP_A03_INJECTION),
    )


def _dynamically_built_var_names(tree: ast.Module) -> set[str]:
    """Flow-insensitive, module-wide: a name assigned a dynamically-built
    string anywhere counts as dynamic everywhere. This is the common LLM
    shape - `query = f"...{id}..."` on one line, `cursor.execute(query)` a
    line or two later - and the imprecision (variable shadowing across
    functions/scopes) trades a rare false positive for not missing the
    overwhelmingly common case of the query being built one line before use."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if _is_dynamically_built(node.value):
                names.add(node.targets[0].id)
    return names


def _check_python(source: SourceFile) -> list[Finding]:
    try:
        tree = ast.parse(source.text, filename=source.rel_path)
    except SyntaxError:
        return []

    dynamic_var_names = _dynamically_built_var_names(tree)

    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not (isinstance(node.func, ast.Attribute) and node.func.attr in _EXEC_METHODS):
            continue
        if not node.args:
            continue
        arg = node.args[0]
        is_dynamic = _is_dynamically_built(arg) or (isinstance(arg, ast.Name) and arg.id in dynamic_var_names)
        if is_dynamic:
            findings.append(_python_finding(source, node))
    return findings


# JS/TS: flag common query-call names whose argument is a template literal
# containing an interpolation, or is built with string concatenation.
_JS_QUERY_CALL_RE = re.compile(r"\.(query|execute|raw)\s*\(")
_JS_INTERPOLATED_TEMPLATE_RE = re.compile(r"`[^`]*\$\{[^}]*\}[^`]*`")
_JS_CONCAT_INTO_CALL_RE = re.compile(r"""["'][^"']*["']\s*\+\s*\w""")


def _check_javascript(source: SourceFile) -> list[Finding]:
    findings: list[Finding] = []
    for line_no, line in enumerate(source.lines, start=1):
        if not _JS_QUERY_CALL_RE.search(line):
            continue
        if _JS_INTERPOLATED_TEMPLATE_RE.search(line) or _JS_CONCAT_INTO_CALL_RE.search(line):
            findings.append(Finding(
                finding_id=f"{VIBE_SEC_SQL_INJECTION}:{source.rel_path}:{line_no}",
                rule_id=VIBE_SEC_SQL_INJECTION,
                severity=Severity.CRITICAL,
                category=Category.INJECTION,
                title="SQL/query call built from a template literal or string concatenation",
                description=(
                    "The query argument is built with `${...}` interpolation or `+` concatenation instead "
                    "of the driver's parameterized placeholders, so request-influenced values become part "
                    "of the query text."
                ),
                file=source.rel_path,
                line=line_no,
                snippet=line.strip()[:200],
                recommendation="Use parameterized placeholders (e.g. `?`/`$1` with a bound-values array) "
                "instead of interpolating values into the query string.",
                references=(CWE_89_SQL_INJECTION, OWASP_A03_INJECTION),
            ))
    return findings


def check_injection(source: SourceFile) -> list[Finding]:
    if source.language is Language.PYTHON:
        return _check_python(source)
    if source.language in (Language.JAVASCRIPT, Language.TYPESCRIPT):
        return _check_javascript(source)
    return []
