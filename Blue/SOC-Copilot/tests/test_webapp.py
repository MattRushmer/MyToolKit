from fastapi.testclient import TestClient

from webapp.main import app


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
