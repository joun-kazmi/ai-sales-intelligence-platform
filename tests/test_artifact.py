import duckdb
import httpx
import pytest
from fastapi.testclient import TestClient

from salesintel.app import artifact as art
from salesintel.app.main import create_app

REPO, TAG, NAME = "owner/repo", "data-v1", "artifact.duckdb"


def make_duckdb(path):
    con = duckdb.connect(str(path))
    con.execute("CREATE TABLE manifest (key VARCHAR, value VARCHAR)")
    con.execute("INSERT INTO manifest VALUES ('input_sha256', 'abc123'), ('rows', '42')")
    con.close()
    return path.read_bytes()


def github(payload: bytes, size: int | None = None, assets=None, seen=None):
    """Mock GitHub API: release lookup, asset URL redirecting to a storage host."""
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append((request.url.host, request.headers.get("authorization")))
        if request.url.path == f"/repos/{REPO}/releases/tags/{TAG}":
            listed = assets if assets is not None else [
                {"name": NAME, "size": len(payload) if size is None else size,
                 "url": f"https://api.github.com/repos/{REPO}/releases/assets/1"}]
            return httpx.Response(200, json={"assets": listed})
        if request.url.path == f"/repos/{REPO}/releases/assets/1":
            return httpx.Response(302, headers={"Location": "https://objects.example-storage.net/blob/1"})
        if request.url.host == "objects.example-storage.net":
            return httpx.Response(200, content=payload)
        return httpx.Response(404)
    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)


def cfg(tmp_path, max_bytes=art.MAX_BYTES_DEFAULT):
    return art.ArtifactConfig(REPO, TAG, NAME, "tok", tmp_path / "dl", max_bytes)


def test_download_validates_and_does_not_leak_token(tmp_path):
    payload = make_duckdb(tmp_path / "src.duckdb")
    seen = []
    path = art.download(cfg(tmp_path), github(payload, seen=seen))
    assert path.read_bytes() == payload
    assert art.read_manifest(path) == {"input_sha256": "abc123", "rows": "42"}
    storage = [auth for host, auth in seen if host == "objects.example-storage.net"]
    assert storage == [None]  # token stays on api.github.com
    assert not list((tmp_path / "dl").glob(".tmp-*"))


def test_size_cap_from_metadata(tmp_path):
    payload = make_duckdb(tmp_path / "src.duckdb")
    with pytest.raises(art.ArtifactError, match="cap"):
        art.download(cfg(tmp_path, max_bytes=10), github(payload))


def test_size_cap_while_streaming(tmp_path):
    payload = make_duckdb(tmp_path / "src.duckdb")
    with pytest.raises(art.ArtifactError, match="cap"):
        art.download(cfg(tmp_path, max_bytes=len(payload) - 1), github(payload, size=1))
    assert not (tmp_path / "dl" / NAME).exists()


def test_missing_asset_and_bad_file(tmp_path):
    with pytest.raises(art.ArtifactError, match="no asset"):
        art.download(cfg(tmp_path), github(b"", assets=[]))
    with pytest.raises(art.ArtifactError, match="DuckDB|manifest"):
        art.download(cfg(tmp_path), github(b"not a database at all"))


def test_partial_config_fails_closed(monkeypatch):
    monkeypatch.setenv("ARTIFACT_REPO", REPO)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    with pytest.raises(art.ArtifactError, match="missing"):
        art.ArtifactConfig.from_env()


def test_app_serves_manifest_after_download(tmp_path, monkeypatch):
    con = duckdb.connect(str(tmp_path / "src.duckdb"))
    con.execute("CREATE TABLE manifest (key VARCHAR, value VARCHAR)")
    con.execute("INSERT INTO manifest VALUES ('input_sha256', 'abc123'), ('rows', '42')")
    con.execute("""CREATE TABLE accounts (rank BIGINT, domain VARCHAR, score BIGINT, tier BIGINT, reasons VARCHAR[],
        why_now VARCHAR[], facts VARCHAR[], appliances VARCHAR[], attribution_label VARCHAR, eligibility VARCHAR,
        eligibility_reason VARCHAR, n_ips BIGINT)""")
    con.execute("CREATE TABLE findings (domain VARCHAR, kind VARCHAR, sentence VARCHAR, cves VARCHAR)")
    con.close()
    payload = (tmp_path / "src.duckdb").read_bytes()
    monkeypatch.setenv("APP_USERNAME", "u")
    monkeypatch.setenv("APP_PASSWORD", "p")
    for k, v in {"ARTIFACT_REPO": REPO, "ARTIFACT_TAG": TAG, "ARTIFACT_NAME": NAME,
                 "GITHUB_TOKEN": "tok", "ARTIFACT_DIR": str(tmp_path)}.items():
        monkeypatch.setenv(k, v)
    real = art.download
    monkeypatch.setattr("salesintel.app.main.download", lambda c: real(c, github(payload)))
    with TestClient(create_app()) as client:
        body = client.get("/", auth=("u", "p")).text
    assert "abc123" in body and "0 accounts" in body
