from __future__ import annotations

from tests.conftest import make_source
from vibecheck.auth.route_extractor import extract_javascript_routes, extract_python_routes
from vibecheck.models import Language


def test_extracts_flask_route_with_bare_decorator():
    source = make_source(
        """
        @app.route("/admin", methods=["POST"])
        @require_admin
        def admin_panel():
            return "ok"
        """
    )
    routes = extract_python_routes(source)
    assert len(routes) == 1
    route = routes[0]
    assert route.method == "POST"
    assert route.path == "/admin"
    assert route.handler_name == "admin_panel"
    assert route.bare_guard_names == ("require_admin",)


def test_extracts_method_shorthand_decorator():
    source = make_source(
        """
        @router.get("/users")
        def list_users():
            return []
        """
    )
    routes = extract_python_routes(source)
    assert routes[0].method == "GET"


def test_attribute_decorator_is_not_a_bare_guard():
    source = make_source(
        """
        @app.route("/protected")
        @auth.login_required
        def protected():
            return "ok"
        """
    )
    routes = extract_python_routes(source)
    assert routes[0].guard_names == ("login_required",)
    assert routes[0].bare_guard_names == ()


def test_non_route_function_is_ignored():
    source = make_source(
        """
        def helper():
            return 1
        """
    )
    assert extract_python_routes(source) == []


def test_extracts_express_route_with_guard():
    source = make_source(
        'app.get("/admin", requireAuth, (req, res) => { res.send("ok"); });\n',
        rel_path="test.js", language=Language.JAVASCRIPT,
    )
    routes = extract_javascript_routes(source)
    assert len(routes) == 1
    assert routes[0].method == "GET"
    assert routes[0].path == "/admin"
    assert routes[0].bare_guard_names == ("requireAuth",)


def test_express_route_without_guard():
    source = make_source(
        'app.get("/public", (req, res) => { res.send("ok"); });\n',
        rel_path="test.js", language=Language.JAVASCRIPT,
    )
    routes = extract_javascript_routes(source)
    assert routes[0].guard_names == ()
