"""Dangerous-sink detection: eval/exec, shell command execution, and unsafe
deserialization. Python is analyzed via `ast` for precision (no false
positives from comments or string contents); JS/TS falls back to regex
heuristics - documented as approximate in the README."""
from __future__ import annotations

import ast
import re

from vibecheck.models import Category, Finding, Language, Severity, SourceFile
from vibecheck.rules.catalog import (
    CWE_78_OS_COMMAND_INJECTION,
    CWE_95_EVAL_INJECTION,
    CWE_502_UNSAFE_DESERIALIZATION,
    OWASP_A03_INJECTION,
    OWASP_A08_SOFTWARE_DATA_INTEGRITY_FAILURES,
    VIBE_SEC_DANGEROUS_EVAL,
    VIBE_SEC_SHELL_INJECTION,
    VIBE_SEC_UNSAFE_DESERIALIZATION,
)

_SHELL_METHODS = {"run", "call", "Popen", "check_call", "check_output"}


def _is_dynamic(node: ast.AST) -> bool:
    """True if the node isn't a plain string constant - i.e. it's built from
    an f-string, concatenation, or % formatting, which is what turns a
    dangerous call into an actual injection risk vs. a static (if still
    dangerous) call."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return False
    return True


def _snippet(source: SourceFile, lineno: int) -> str:
    idx = lineno - 1
    return source.lines[idx].strip()[:200] if 0 <= idx < len(source.lines) else ""


def _finding(source: SourceFile, node: ast.AST, rule_id: str, category: Category, severity: Severity, title: str, description: str, recommendation: str, references: tuple[str, ...]) -> Finding:
    lineno = getattr(node, "lineno", 0)
    return Finding(
        finding_id=f"{rule_id}:{source.rel_path}:{lineno}",
        rule_id=rule_id,
        severity=severity,
        category=category,
        title=title,
        description=description,
        file=source.rel_path,
        line=lineno,
        snippet=_snippet(source, lineno),
        recommendation=recommendation,
        references=references,
    )


def _check_python(source: SourceFile) -> list[Finding]:
    try:
        tree = ast.parse(source.text, filename=source.rel_path)
    except SyntaxError:
        return []

    findings: list[Finding] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func

        # eval(...) / exec(...)
        if isinstance(func, ast.Name) and func.id in {"eval", "exec"}:
            findings.append(_finding(
                source, node, VIBE_SEC_DANGEROUS_EVAL, Category.DANGEROUS_CALL, Severity.HIGH,
                f"Use of {func.id}()",
                f"{func.id}() executes arbitrary code built from a string at runtime. LLM-generated "
                "code reaches for it as a shortcut for dynamic dispatch far more often than a human "
                "author would, and it's a code-execution sink if any part of the input is attacker-influenced.",
                f"Replace {func.id}() with an explicit dispatch table, ast.literal_eval() for data-only "
                "parsing, or a proper parser for the input format.",
                (CWE_95_EVAL_INJECTION, OWASP_A03_INJECTION),
            ))
            continue

        # os.system(...) / os.popen(...)
        if isinstance(func, ast.Attribute) and func.attr in {"system", "popen"} and isinstance(func.value, ast.Name) and func.value.id == "os":
            arg = node.args[0] if node.args else None
            severity = Severity.CRITICAL if arg is not None and _is_dynamic(arg) else Severity.HIGH
            findings.append(_finding(
                source, node, VIBE_SEC_SHELL_INJECTION, Category.INJECTION, severity,
                f"os.{func.attr}() invoked{' with a dynamically-built command' if severity is Severity.CRITICAL else ''}",
                "os.system()/os.popen() run a string through the system shell. When any part of that "
                "string is built from user input (an f-string, concatenation, or % formatting), this is "
                "direct OS command injection.",
                "Use subprocess.run([...], shell=False) with an argument list instead of a shell string, "
                "and validate/allowlist any user-influenced component.",
                (CWE_78_OS_COMMAND_INJECTION, OWASP_A03_INJECTION),
            ))
            continue

        # subprocess.run/call/Popen/check_call/check_output(..., shell=True)
        if isinstance(func, ast.Attribute) and func.attr in _SHELL_METHODS:
            shell_kw = next((kw for kw in node.keywords if kw.arg == "shell"), None)
            if shell_kw is not None and isinstance(shell_kw.value, ast.Constant) and shell_kw.value.value is True:
                arg = node.args[0] if node.args else None
                severity = Severity.CRITICAL if arg is not None and _is_dynamic(arg) else Severity.HIGH
                findings.append(_finding(
                    source, node, VIBE_SEC_SHELL_INJECTION, Category.INJECTION, severity,
                    f"subprocess.{func.attr}(..., shell=True){' with a dynamically-built command' if severity is Severity.CRITICAL else ''}",
                    "shell=True runs the command through the system shell, so any attacker-influenced "
                    "substring in the command becomes shell metacharacter injection, not just argument "
                    "injection.",
                    "Pass the command as a list (subprocess.run([...], shell=False)) so arguments can never "
                    "be reinterpreted by a shell.",
                    (CWE_78_OS_COMMAND_INJECTION, OWASP_A03_INJECTION),
                ))
            continue

        # pickle.load(s)(...)
        if isinstance(func, ast.Attribute) and func.attr in {"load", "loads"} and isinstance(func.value, ast.Name) and func.value.id == "pickle":
            findings.append(_finding(
                source, node, VIBE_SEC_UNSAFE_DESERIALIZATION, Category.DANGEROUS_CALL, Severity.HIGH,
                "pickle deserialization of external data",
                "pickle.load/loads executes arbitrary code embedded in the pickle stream during "
                "deserialization. Any pickle input that isn't fully trusted (a request body, a queue "
                "message, a file another service wrote) is a remote-code-execution sink.",
                "Use a data-only format (json) for anything that crosses a trust boundary; if pickle is "
                "required for internal-only data, sign/verify the payload before loading it.",
                (CWE_502_UNSAFE_DESERIALIZATION, OWASP_A08_SOFTWARE_DATA_INTEGRITY_FAILURES),
            ))
            continue

        # yaml.load(...) without a safe Loader
        if isinstance(func, ast.Attribute) and func.attr == "load" and isinstance(func.value, ast.Name) and func.value.id == "yaml":
            loader_kw = next((kw for kw in node.keywords if kw.arg == "Loader"), None)
            is_safe = loader_kw is not None and isinstance(loader_kw.value, ast.Attribute) and "Safe" in loader_kw.value.attr
            if not is_safe:
                findings.append(_finding(
                    source, node, VIBE_SEC_UNSAFE_DESERIALIZATION, Category.DANGEROUS_CALL, Severity.HIGH,
                    "yaml.load() without a SafeLoader",
                    "PyYAML's default Loader can construct arbitrary Python objects from the YAML "
                    "document, which is a known code-execution vector for untrusted YAML.",
                    "Use yaml.safe_load(...) or pass Loader=yaml.SafeLoader explicitly.",
                    (CWE_502_UNSAFE_DESERIALIZATION, OWASP_A08_SOFTWARE_DATA_INTEGRITY_FAILURES),
                ))
            continue

    return findings


_JS_EVAL_RE = re.compile(r"\beval\s*\(")
_JS_NEW_FUNCTION_RE = re.compile(r"\bnew\s+Function\s*\(")
_JS_EXEC_RE = re.compile(r"\b(?:child_process\.)?exec(?:Sync)?\s*\(")
_JS_DYNAMIC_ARG_HINT = re.compile(r"[`+]")


def _check_javascript(source: SourceFile) -> list[Finding]:
    findings: list[Finding] = []
    for line_no, line in enumerate(source.lines, start=1):
        if _JS_EVAL_RE.search(line) or _JS_NEW_FUNCTION_RE.search(line):
            findings.append(Finding(
                finding_id=f"{VIBE_SEC_DANGEROUS_EVAL}:{source.rel_path}:{line_no}",
                rule_id=VIBE_SEC_DANGEROUS_EVAL,
                severity=Severity.HIGH,
                category=Category.DANGEROUS_CALL,
                title="Use of eval()/new Function()",
                description="eval() and `new Function()` compile and run a string as code at runtime - a "
                "code-execution sink if any part of that string is attacker-influenced.",
                file=source.rel_path,
                line=line_no,
                snippet=line.strip()[:200],
                recommendation="Replace with an explicit parser/dispatch table for the input.",
                references=(CWE_95_EVAL_INJECTION, OWASP_A03_INJECTION),
            ))

        exec_match = _JS_EXEC_RE.search(line)
        if exec_match:
            dynamic = bool(_JS_DYNAMIC_ARG_HINT.search(line[exec_match.end():]))
            severity = Severity.CRITICAL if dynamic else Severity.MEDIUM
            findings.append(Finding(
                finding_id=f"{VIBE_SEC_SHELL_INJECTION}:{source.rel_path}:{line_no}",
                rule_id=VIBE_SEC_SHELL_INJECTION,
                severity=severity,
                category=Category.INJECTION,
                title=f"child_process exec(){' with a dynamically-built command' if dynamic else ''}",
                description="child_process.exec()/execSync() run a string through the system shell. Building "
                "that string with a template literal or concatenation from any request-influenced value is "
                "OS command injection.",
                file=source.rel_path,
                line=line_no,
                snippet=line.strip()[:200],
                recommendation="Use execFile()/execFileSync() with an argument array instead of a shell string.",
                references=(CWE_78_OS_COMMAND_INJECTION, OWASP_A03_INJECTION),
            ))
    return findings


def check_dangerous_calls(source: SourceFile) -> list[Finding]:
    if source.language is Language.PYTHON:
        return _check_python(source)
    if source.language in (Language.JAVASCRIPT, Language.TYPESCRIPT):
        return _check_javascript(source)
    return []
