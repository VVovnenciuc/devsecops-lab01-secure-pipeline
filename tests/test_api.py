import pytest
from fastapi.testclient import TestClient

from notes_api.main import SECURITY_HEADERS, app


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def test_healthz(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@pytest.mark.parametrize("path", ["/healthz", "/api/v1/notes", "/does-not-exist"])
def test_security_headers_on_every_response(client: TestClient, path: str) -> None:
    response = client.get(path)
    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value


def test_create_and_get_note(client: TestClient) -> None:
    created = client.post("/api/v1/notes", json={"title": "t", "body": "b"})
    assert created.status_code == 201
    note_id = created.json()["id"]
    assert client.get(f"/api/v1/notes/{note_id}").json()["title"] == "t"


@pytest.mark.parametrize(
    "payload",
    [{}, {"title": ""}, {"title": "x" * 101}, {"title": "ok", "body": "x" * 2001}],
)
def test_input_validation_rejects_bad_payloads(client: TestClient, payload: dict[str, str]) -> None:
    assert client.post("/api/v1/notes", json=payload).status_code == 422


def test_unknown_note_returns_404(client: TestClient) -> None:
    assert client.get("/api/v1/notes/999999").status_code == 404


def test_docs_disabled_by_default(client: TestClient) -> None:
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404
