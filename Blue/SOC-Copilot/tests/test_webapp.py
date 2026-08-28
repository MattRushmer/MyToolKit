from fastapi.testclient import TestClient

from webapp.main import _exceeds_max_body_size, app


def test_upload_rejects_mismatched_file_and_source_counts():
    client = TestClient(app)

    response = client.post(
        "/run",
        data={"client_id": "client-a", "client_name": "Client A", "alert_sources": "generic"},
        files=[
            ("alert_files", ("one.csv", b"Timestamp,Title\n2026-01-01,One\n", "text/csv")),
            ("alert_files", ("two.csv", b"Timestamp,Title\n2026-01-01,Two\n", "text/csv")),
        ],
    )

    assert response.status_code == 400
    assert "exactly one source adapter" in response.text


def test_exceeds_max_body_size():
    assert _exceeds_max_body_size(None, max_bytes=100) is False  # no Content-Length header: can't judge, let it through
    assert _exceeds_max_body_size("50", max_bytes=100) is False
    assert _exceeds_max_body_size("100", max_bytes=100) is False  # exactly at the limit is not "exceeds"
    assert _exceeds_max_body_size("101", max_bytes=100) is True
    assert _exceeds_max_body_size("not-a-number", max_bytes=100) is False  # malformed header: fail open, not 500


def test_request_over_max_body_size_is_rejected_before_reaching_the_route(monkeypatch):
    import webapp.main as webapp_main

    monkeypatch.setattr(webapp_main, "_MAX_REQUEST_BYTES", 10)
    client = TestClient(app)

    response = client.post(
        "/run",
        data={"client_id": "client-a", "client_name": "Client A", "alert_sources": "generic"},
        files=[("alert_files", ("one.csv", b"Timestamp,Title\n2026-01-01,One\n", "text/csv"))],
    )

    assert response.status_code == 413
