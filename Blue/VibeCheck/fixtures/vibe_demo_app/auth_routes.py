"""Deliberately-vulnerable demo routes covering the VIBE-AUTH-* hallucinated-
auth rules. Never deploy this."""
from flask import Blueprint, jsonify, request

bp = Blueprint("auth", __name__, url_prefix="/api/auth")


def verify_token(token):
    if not token or not token.startswith("Bearer "):
        raise ValueError("invalid token")
    return True


def verify_admin_access(user):
    # VIBE-AUTH-04: this looks like an authorization gate but is never
    # called anywhere in the project - it protects nothing.
    if not user.is_admin:
        raise PermissionError("not admin")


@bp.route("/token/refresh", methods=["POST"])
def refresh_token():
    # VIBE-AUTH-02: fail-open - if verify_token() raises, the exception is
    # swallowed and the handler continues as if it had succeeded.
    try:
        verify_token(request.headers.get("Authorization"))
    except Exception:
        pass
    return jsonify({"new_token": "xyz"})


@bp.route("/admin/debug", methods=["GET"])
def admin_debug():
    is_admin = request.args.get("admin") == "true"
    # VIBE-AUTH-03: tautological condition - `or True` means this branch is
    # always taken regardless of is_admin.
    if is_admin or True:
        return jsonify({"debug": "sensitive-data"})
    return jsonify({"error": "forbidden"}), 403


@bp.route("/admin/settings", methods=["POST"])
@require_admin  # noqa: F821 - VIBE-AUTH-01: never defined or imported anywhere in this project
def update_settings():
    return jsonify({"status": "updated"})
