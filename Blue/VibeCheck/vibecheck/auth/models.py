"""Route-level facts extracted from source, shared by every auth-hallucination rule."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RouteInfo:
    file: str
    line: int
    method: str          # "GET"/"POST"/... or "" if it couldn't be determined
    path: str             # the URL path/prefix, or "?" if not a string literal
    handler_name: str
    # Every decorator name on a Python handler (Attribute decorators collapse to
    # their final segment, e.g. `@auth.login_required` -> "login_required"), or
    # every guard-looking argument passed before the terminal handler in a JS
    # route call - used to detect a missing guard (sibling-route comparison).
    guard_names: tuple[str, ...] = ()
    # Subset of guard_names that are a *bare* reference (`@require_admin`, a
    # plain JS identifier with no dot) rather than an attribute/method access
    # on some other object (`@auth.login_required`, `mw.checkAuth`) - only a
    # bare name can be checked against the project's defined-symbol set with
    # confidence, since an attribute could resolve through a third-party
    # object we have no visibility into.
    bare_guard_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class FunctionDef:
    """Every top-level/module-scope function definition in a file, used to
    check whether a decorator/guard name actually resolves to something
    defined in the codebase."""

    file: str
    line: int
    name: str
    is_called: bool = False
