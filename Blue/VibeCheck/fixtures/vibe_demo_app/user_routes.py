"""Deliberately-vulnerable demo routes covering VIBE-SEC-*, VIBE-DUP-01, and
VIBE-AUTH-05 (sibling-route gap). Never deploy this."""
import sqlite3
import subprocess

from flask import Blueprint, jsonify, request

from auth_routes import verify_token

bp = Blueprint("users", __name__, url_prefix="/api/users")

db = sqlite3.connect(":memory:")


def require_login(handler):
    def wrapper(*args, **kwargs):
        verify_token(request.headers.get("Authorization"))
        return handler(*args, **kwargs)

    wrapper.__name__ = handler.__name__
    return wrapper


@bp.route("/api/users/<user_id>", methods=["GET"])
def get_user(user_id):
    # VIBE-SEC-05 SQL injection (first occurrence - see delete_user below for
    # the copy-pasted duplicate, VIBE-DUP-01) and VIBE-AUTH-05: this sibling
    # has no guard while DELETE on the same resource does.
    query = f"SELECT * FROM users WHERE id={user_id}"
    cursor = db.execute(query)
    return jsonify(cursor.fetchone())


@bp.route("/api/users/<user_id>", methods=["DELETE"])
@require_login
def delete_user(user_id):
    query = f"SELECT * FROM users WHERE id={user_id}"  # VIBE-DUP-01: identical pattern, copy-pasted
    cursor = db.execute(query)
    db.execute(f"DELETE FROM users WHERE id={user_id}")
    return jsonify({"deleted": True})


@bp.route("/api/users/export/<filename>", methods=["GET"])
def export_users(filename):
    # VIBE-SEC-03: shell command built from an f-string with shell=True
    subprocess.run(f"tar czf /tmp/{filename}.tar.gz /data/users", shell=True)
    return jsonify({"status": "exported"})
