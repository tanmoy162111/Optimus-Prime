import pytest
from fastapi.testclient import TestClient


def test_health_requires_no_auth(client):
    response = client.get("/health")
    assert response.status_code == 200


def test_chat_without_token_returns_401(client):
    response = client.post("/api/chat", json={"message": "hello"})
    assert response.status_code == 401


def test_chat_with_wrong_token_returns_401(client):
    response = client.post(
        "/api/chat",
        json={"message": "hello"},
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert response.status_code == 401


def test_chat_with_valid_token_does_not_return_401(client):
    response = client.post(
        "/api/chat",
        json={"message": "hello"},
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code != 401


def test_ws_without_token_returns_403(client):
    with pytest.raises(Exception):
        with client.websocket_connect("/ws/chat") as ws:
            ws.receive_json()


def test_ws_with_wrong_token_returns_403(client):
    with pytest.raises(Exception):
        with client.websocket_connect("/ws/chat?token=wrong") as ws:
            ws.receive_json()


def test_ws_with_valid_token_connects(client):
    with client.websocket_connect("/ws/chat?token=test-token") as ws:
        data = ws.receive_json()
        assert data["type"] == "welcome"
