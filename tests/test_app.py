import base64

import pytest
from fastapi.testclient import TestClient

from salesintel.app.main import create_app


def _basic(user: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("APP_USERNAME", "reviewer")
    monkeypatch.setenv("APP_PASSWORD", "s3cret")
    monkeypatch.delenv("ARTIFACT_REPO", raising=False)
    with TestClient(create_app()) as c:
        yield c


def test_refuses_to_start_without_credentials(monkeypatch):
    monkeypatch.delenv("APP_USERNAME", raising=False)
    monkeypatch.delenv("APP_PASSWORD", raising=False)
    with pytest.raises(RuntimeError):
        create_app()


@pytest.mark.parametrize("path", ["/", "/robots.txt", "/does-not-exist"])
def test_every_route_requires_auth(client, path):
    response = client.get(path)
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"].startswith("Basic")
    assert "noindex" in response.headers["X-Robots-Tag"]


@pytest.mark.parametrize(
    "headers",
    [
        _basic("reviewer", "wrong"),
        _basic("other", "s3cret"),
        {"Authorization": "Basic !!!not-base64"},
        {"Authorization": "Bearer abc"},
        {"Authorization": "Basic " + base64.b64encode(b"no-colon").decode()},
    ],
)
def test_bad_credentials_rejected(client, headers):
    assert client.get("/", headers=headers).status_code == 401


def test_good_credentials_and_noindex(client):
    response = client.get("/", headers=_basic("reviewer", "s3cret"))
    assert response.status_code == 200
    assert "noindex" in response.headers["X-Robots-Tag"]
    robots = client.get("/robots.txt", headers=_basic("reviewer", "s3cret"))
    assert "Disallow: /" in robots.text
