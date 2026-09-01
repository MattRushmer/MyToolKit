"""Extract route/endpoint declarations from Python (Flask/FastAPI/Django-REST
-style decorators) and JS/TS (Express-style `app.METHOD(path, ...mw, handler)`
calls) source files, as the shared input every auth-hallucination rule reasons
about."""
from __future__ import annotations

import ast
import re

from vibecheck.auth.models import RouteInfo
from vibecheck.models import SourceFile

_ROUTE_METHOD_NAMES = {"get", "post", "put", "delete", "patch", "route", "options", "head"}


def _decorator_name(node: ast.expr) -> str:
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return "?"


def _is_bare_decorator(node: ast.expr) -> bool:
    """True for `@name` / `@name(...)` - false for `@obj.name` / `@obj.name(...)`,
    which resolves through some other object we can't verify. See
    RouteInfo.bare_guard_names' docstring."""
    target = node.func if isinstance(node, ast.Call) else node
    return isinstance(target, ast.Name)


def _is_route_decorator(node: ast.expr) -> bool:
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in _ROUTE_METHOD_NAMES


def _route_path(call: ast.Call) -> str:
    if call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
        return call.args[0].value
    return "?"


def _route_method(call: ast.Call) -> str:
    attr = call.func.attr  # type: ignore[union-attr]
    if attr != "route":
        return attr.upper()
    methods_kw = next((kw for kw in call.keywords if kw.arg == "methods"), None)
    if methods_kw is not None and isinstance(methods_kw.value, ast.List):
        names = [elt.value for elt in methods_kw.value.elts if isinstance(elt, ast.Constant) and isinstance(elt.value, str)]
        if names:
            return "/".join(sorted(m.upper() for m in names))
    return "GET"


def extract_python_routes(source: SourceFile) -> list[RouteInfo]:
    try:
        tree = ast.parse(source.text, filename=source.rel_path)
    except SyntaxError:
        return []

    routes: list[RouteInfo] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        route_call: ast.Call | None = None
        other_decorator_names: list[str] = []
        bare_decorator_names: list[str] = []
        for dec in node.decorator_list:
            if route_call is None and _is_route_decorator(dec):
                route_call = dec  # type: ignore[assignment]
                continue
            other_decorator_names.append(_decorator_name(dec))
            if _is_bare_decorator(dec):
                bare_decorator_names.append(_decorator_name(dec))

        if route_call is None:
            continue

        routes.append(RouteInfo(
            file=source.rel_path,
            line=node.lineno,
            method=_route_method(route_call),
            path=_route_path(route_call),
            handler_name=node.name,
            guard_names=tuple(other_decorator_names),
            bare_guard_names=tuple(bare_decorator_names),
        ))

    return routes


# Express-style: app.get('/path', mw1, mw2, handler) - method call on an
# object, first arg a path string, last arg the handler, anything in between
# is a middleware/guard reference. Balanced-paren aware so it tolerates a
# path containing a comma-free literal and simple identifier args; an inline
# arrow-function handler with its own commas is treated as the final arg by
# only splitting on top-level commas.
_JS_ROUTE_CALL_RE = re.compile(
    r"\b(?:app|router|api)\.(get|post|put|delete|patch|all|use)\s*\(\s*(['\"])(?P<path>[^'\"]*)\2\s*,\s*(?P<rest>.*)\)\s*;?\s*$"
)


def _split_top_level_args(text: str) -> list[str]:
    args: list[str] = []
    depth = 0
    current = []
    for ch in text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    tail = "".join(current).strip()
    if tail:
        args.append(tail)
    return args


_JS_IDENTIFIER_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$.]*$")


def extract_javascript_routes(source: SourceFile) -> list[RouteInfo]:
    routes: list[RouteInfo] = []
    for line_no, line in enumerate(source.lines, start=1):
        match = _JS_ROUTE_CALL_RE.search(line)
        if not match:
            continue

        method = match.group(1).upper()
        path = match.group("path") or "?"
        args = _split_top_level_args(match.group("rest"))
        if not args:
            continue

        handler = args[-1]
        guard_args = args[:-1]
        # Only count guard args that look like a plain identifier/reference
        # (e.g. `requireAuth`, `mw.checkAuth`) - an inline arrow function or
        # object literal isn't a named guard we can resolve, so it's dropped
        # rather than guessed at.
        guard_args = [a for a in guard_args if _JS_IDENTIFIER_RE.match(a)]
        guard_names = tuple(a.split(".")[-1] for a in guard_args)
        bare_guard_names = tuple(a for a in guard_args if "." not in a)
        handler_name = handler.split(".")[-1] if _JS_IDENTIFIER_RE.match(handler) else "<inline>"

        routes.append(RouteInfo(
            file=source.rel_path, line=line_no, method=method, path=path, handler_name=handler_name,
            guard_names=guard_names, bare_guard_names=bare_guard_names,
        ))

    return routes
