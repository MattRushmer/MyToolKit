"""Project-wide symbol table: every name defined (function/class/import) and
every name referenced (as a call, decorator, attribute access, or bare
reference) anywhere in the scanned Python sources. This is what lets
VIBE-AUTH-01 tell a real decorator from a hallucinated one - a name is only
"real" if it resolves to something actually defined or imported somewhere in
the project, not just spelled correctly.

Deliberately over-approximates "referenced" (any Attribute.attr counts, not
just direct calls) so that `self.check_admin()` / `mw.require_auth` style
usage doesn't produce a false "unused helper" finding - the tradeoff is a
false negative on truly-dead helpers with a very common attribute name,
which is the safer direction for a tool that must keep noise low.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field

from vibecheck.auth.models import FunctionDef
from vibecheck.models import Language, SourceFile


@dataclass(frozen=True)
class SymbolIndex:
    defined_names: frozenset[str]
    referenced_names: frozenset[str]
    function_defs: tuple[FunctionDef, ...] = field(default_factory=tuple)


def _import_bindings(node: ast.Import | ast.ImportFrom) -> list[str]:
    bindings = []
    for alias in node.names:
        if alias.asname:
            bindings.append(alias.asname)
        else:
            bindings.append(alias.name.split(".")[0])
    return bindings


def build_python_symbol_index(sources: list[SourceFile]) -> SymbolIndex:
    defined: set[str] = set()
    referenced: set[str] = set()
    function_defs: list[FunctionDef] = []

    trees: list[tuple[SourceFile, ast.Module]] = []
    for source in sources:
        if source.language is not Language.PYTHON:
            continue
        try:
            trees.append((source, ast.parse(source.text, filename=source.rel_path)))
        except SyntaxError:
            continue

    for source, tree in trees:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defined.add(node.name)
                function_defs.append(FunctionDef(file=source.rel_path, line=node.lineno, name=node.name))
            elif isinstance(node, ast.ClassDef):
                defined.add(node.name)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                defined.update(_import_bindings(node))
            elif isinstance(node, ast.Name):
                referenced.add(node.id)
            elif isinstance(node, ast.Attribute):
                referenced.add(node.attr)

    return SymbolIndex(defined_names=frozenset(defined), referenced_names=frozenset(referenced), function_defs=tuple(function_defs))


_JS_DEFINED_RE_PARTS = (
    r"function\s+([A-Za-z_$][A-Za-z0-9_$]*)",
    r"(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=",
    r"class\s+([A-Za-z_$][A-Za-z0-9_$]*)",
    r"import\s+\{([^}]+)\}",
    r"import\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+from",
)


def build_javascript_symbol_index(sources: list[SourceFile]) -> SymbolIndex:
    import re

    defined: set[str] = set()
    referenced: set[str] = set()
    combined_defined_re = re.compile("|".join(_JS_DEFINED_RE_PARTS))
    identifier_re = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")

    for source in sources:
        if source.language not in (Language.JAVASCRIPT, Language.TYPESCRIPT):
            continue
        for line in source.lines:
            for match in combined_defined_re.finditer(line):
                for group in match.groups():
                    if not group:
                        continue
                    for name in group.split(","):
                        name = name.strip().split(" as ")[-1].strip()
                        if name:
                            defined.add(name)
            for name in identifier_re.findall(line):
                referenced.add(name)

    return SymbolIndex(defined_names=frozenset(defined), referenced_names=frozenset(referenced))
