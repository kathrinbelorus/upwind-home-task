import os

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
AUTH = {"X-API-Key": os.environ["API_KEY"]}
EMAIL = {"sender": "a@b.com", "subject": "hi"}


def test_health_needs_no_key():
    assert client.get("/health").json() == {"status": "ok"}


def test_analyze_rejects_missing_key():
    assert client.post("/analyze", json=EMAIL).status_code == 401


def test_analyze_rejects_wrong_key():
    response = client.post("/analyze", json=EMAIL, headers={"X-API-Key": "wrong"})
    assert response.status_code == 401


def test_analyze_returns_result():
    response = client.post("/analyze", json=EMAIL, headers=AUTH)
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"score", "verdict", "findings"}


def test_oversized_input_is_rejected():
    huge = {**EMAIL, "subject": "x" * 5000}
    assert client.post("/analyze", json=huge, headers=AUTH).status_code == 422


def test_unknown_fields_are_rejected():
    response = client.post("/analyze", json={**EMAIL, "admin": True}, headers=AUTH)
    assert response.status_code == 422
