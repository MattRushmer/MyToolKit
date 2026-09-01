from __future__ import annotations

from tests.conftest import make_source
from vibecheck.auth.hallucination_rules import (
    check_fail_open_auth,
    check_sibling_route_gaps,
    check_tautological_auth,
    check_undefined_guards,
    check_unused_auth_helpers,
)
from vibecheck.auth.route_extractor import extract_python_routes
from vibecheck.auth.symbol_index import build_python_symbol_index
from vibecheck.rules.catalog import (
    VIBE_AUTH_FAIL_OPEN,
    VIBE_AUTH_SIBLING_GAP,
    VIBE_AUTH_TAUTOLOGY,
    VIBE_AUTH_UNDEFINED_DECORATOR,
    VIBE_AUTH_UNUSED_HELPER,
)


def test_undefined_bare_decorator_is_flagged():
    source = make_source(
        """
        @app.route("/admin")
        @require_admin
        def admin_panel():
            return "ok"
        """
    )
    routes = extract_python_routes(source)
    index = build_python_symbol_index([source])
    findings = check_undefined_guards(routes, index)
    assert any(f.rule_id == VIBE_AUTH_UNDEFINED_DECORATOR for f in findings)


def test_defined_decorator_is_not_flagged():
    source = make_source(
        """
        def require_admin(fn):
            return fn

        @app.route("/admin")
        @require_admin
        def admin_panel():
            return "ok"
        """
    )
    routes = extract_python_routes(source)
    index = build_python_symbol_index([source])
    findings = check_undefined_guards(routes, index)
    assert findings == []


def test_known_framework_guard_is_not_flagged():
    source = make_source(
        """
        @app.route("/admin")
        @login_required
        def admin_panel():
            return "ok"
        """
    )
    routes = extract_python_routes(source)
    index = build_python_symbol_index([source])
    findings = check_undefined_guards(routes, index)
    assert findings == []


def test_fail_open_try_except_is_flagged():
    source = make_source(
        """
        def handler():
            try:
                verify_token(request)
            except Exception:
                pass
            return "ok"
        """
    )
    findings = check_fail_open_auth(source)
    assert any(f.rule_id == VIBE_AUTH_FAIL_OPEN for f in findings)


def test_except_that_returns_error_is_not_flagged():
    source = make_source(
        """
        def handler():
            try:
                verify_token(request)
            except Exception:
                return "forbidden", 403
            return "ok"
        """
    )
    findings = check_fail_open_auth(source)
    assert findings == []


def test_except_that_reraises_is_not_flagged():
    source = make_source(
        """
        def handler():
            try:
                verify_token(request)
            except Exception:
                raise
            return "ok"
        """
    )
    findings = check_fail_open_auth(source)
    assert findings == []


def test_non_auth_try_except_is_not_flagged():
    source = make_source(
        """
        def handler():
            try:
                fetch_data()
            except Exception:
                pass
            return "ok"
        """
    )
    findings = check_fail_open_auth(source)
    assert findings == []


def test_tautological_auth_condition_is_flagged():
    source = make_source(
        """
        def handler():
            if is_admin or True:
                return "ok"
        """
    )
    findings = check_tautological_auth(source)
    assert any(f.rule_id == VIBE_AUTH_TAUTOLOGY for f in findings)


def test_tautology_without_auth_context_is_not_flagged():
    source = make_source(
        """
        def handler():
            if enabled or True:
                return "ok"
        """
    )
    findings = check_tautological_auth(source)
    assert findings == []


def test_non_tautological_auth_condition_is_not_flagged():
    source = make_source(
        """
        def handler():
            if is_admin and has_permission:
                return "ok"
        """
    )
    findings = check_tautological_auth(source)
    assert findings == []


def test_unused_auth_helper_is_flagged():
    source = make_source(
        """
        def verify_admin_access(user):
            if not user.is_admin:
                raise PermissionError()
        """
    )
    index = build_python_symbol_index([source])
    findings = check_unused_auth_helpers(index, frozenset())
    assert any(f.rule_id == VIBE_AUTH_UNUSED_HELPER for f in findings)


def test_called_auth_helper_is_not_flagged():
    source = make_source(
        """
        def verify_admin_access(user):
            if not user.is_admin:
                raise PermissionError()

        def handler(user):
            verify_admin_access(user)
        """
    )
    index = build_python_symbol_index([source])
    findings = check_unused_auth_helpers(index, frozenset())
    assert findings == []


def test_route_handler_named_like_auth_helper_is_not_flagged():
    source = make_source(
        """
        def check_admin_status(request):
            return True
        """
    )
    index = build_python_symbol_index([source])
    findings = check_unused_auth_helpers(index, frozenset({"check_admin_status"}))
    assert findings == []


def test_sibling_route_missing_guard_is_flagged():
    source = make_source(
        """
        @app.route("/api/users", methods=["GET"])
        def list_users():
            return []

        @app.route("/api/users", methods=["POST"])
        @require_admin
        def create_user():
            return {}
        """
    )
    routes = extract_python_routes(source)
    findings = check_sibling_route_gaps(routes)
    assert len(findings) == 1
    assert findings[0].rule_id == VIBE_AUTH_SIBLING_GAP
    assert findings[0].line == routes[0].line


def test_all_siblings_guarded_is_not_flagged():
    source = make_source(
        """
        @app.route("/api/users", methods=["GET"])
        @require_admin
        def list_users():
            return []

        @app.route("/api/users", methods=["POST"])
        @require_admin
        def create_user():
            return {}
        """
    )
    routes = extract_python_routes(source)
    findings = check_sibling_route_gaps(routes)
    assert findings == []


def test_unrelated_routes_are_not_grouped():
    source = make_source(
        """
        @app.route("/api/users", methods=["GET"])
        def list_users():
            return []

        @app.route("/api/orders", methods=["GET"])
        @require_admin
        def list_orders():
            return []
        """
    )
    routes = extract_python_routes(source)
    findings = check_sibling_route_gaps(routes)
    assert findings == []
