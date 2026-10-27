import csv
import io

import duckdb
import orjson
import pytest
import zstandard
from fastapi.testclient import TestClient

from salesintel.app.main import create_app
from salesintel.pipeline import extract as extract_mod
from salesintel.pipeline import score as sc

TS = "2026-10-26T10:00:00.000000"
AUTH = ("u", "p")


def _rec(ip, port, module, **kw):
    return {"ip_str": ip, "port": port, "timestamp": TS, "org": "Example Corp", "_shodan": {"module": module}, **kw}


@pytest.fixture(scope="module")
def artifact(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("ui")
    recs = []
    for i in range(70):
        name = f"org{i:02d}.com"
        recs.append(_rec(f"198.51.100.{i}", 443, "https", _shodan={"module": "https", "options": {"hostname": f"www.{name}"}},
                         product="nginx", version="1.18.0", tags=["eol-product"],
                         vulns={f"CVE-2021-{i:04d}": {"cvss": 9.0, "epss": 0.5, "kev": i % 2 == 0}}))
        if i % 5 == 0:
            recs.append(_rec(f"198.51.100.{i}", 3389, "rdp"))
    # Hostile strings from a banner must be escaped wherever they appear.
    recs.append(_rec("198.51.100.250", 80, "http", _shodan={"module": "http", "options": {"hostname": "evil.com"}},
                     product="<script>alert(1)</script>", version="1", tags=["eol-product"],
                     http={"title": "<img src=x onerror=alert(2)>", "server": "<b>bold</b>/1.0"}))
    recs.append(_rec("198.51.100.251", 443, "https", hostnames=["fw.acme-fw.com"], product="FortiGate"))
    src = tmp / "in.jsonl.zst"
    src.write_bytes(zstandard.ZstdCompressor().compress(b"".join(orjson.dumps(r) + b"\n" for r in recs)))
    m = extract_mod.extract(src, tmp / "out", workers=1)
    art = tmp / "artifact.duckdb"
    sc.score(tmp / "out" / "features" / m["input_sha256"], art)
    return art


@pytest.fixture
def client(artifact, monkeypatch):
    monkeypatch.setenv("APP_USERNAME", "u")
    monkeypatch.setenv("APP_PASSWORD", "p")
    monkeypatch.setenv("ARTIFACT_PATH", str(artifact))
    with TestClient(create_app()) as c:
        yield c


@pytest.mark.parametrize("path", ["/", "/plays", "/export.csv", "/account/org00.com", "/?tier=1&play=exposed"])
def test_pages_require_auth_and_render(client, path):
    assert client.get(path).status_code == 401
    r = client.get(path, auth=AUTH)
    assert r.status_code == 200 and "noindex" in r.headers["X-Robots-Tag"]


def test_list_is_ranked_and_paged(client, artifact):
    body = client.get("/", auth=AUTH).text
    total = client.app.state.store.con.cursor().execute(
        "SELECT count(*) FROM accounts WHERE tier > 0 AND eligibility != 'likely_non_prospect'").fetchone()[0]
    assert f"{total} accounts" in body and "page 1 of 2" in body
    assert body.index("org00.com") < body.index("org01.com")  # RDP + KEV ranks above KEV alone
    assert "org01.com" in client.get("/?page=2", auth=AUTH).text or "org01.com" in body


def test_bad_filters_are_rejected(client):
    for qs in ("tier=9", "play=drop%20table", "eligibility=x", "page=abc", "why_now=1;--"):
        assert client.get(f"/?{qs}", auth=AUTH).status_code == 400


def test_account_breakdown_sums_to_score(client, artifact):
    con = client.app.state.store.con.cursor()
    for domain, score, e, s, n in con.execute(
            "SELECT domain, score, exposure_points, software_points, neglect_points FROM accounts").fetchall():
        assert e + s + n == score
    body = client.get("/account/org00.com", auth=AUTH).text
    assert "Score breakdown" in body and "potential" in body and "KEV" in body
    assert client.get("/account/no-such.example", auth=AUTH).status_code == 404


def test_record_strings_are_escaped(client):
    pages = [client.get("/account/evil.com", auth=AUTH).text, client.get("/?tier=all", auth=AUTH).text]
    for body in pages:
        assert "<script>alert(1)" not in body and "<img src=x" not in body and "<b>bold</b>" not in body
    assert "&lt;script&gt;" in pages[0]


def test_csv_matches_filtered_list(client, artifact):
    rows = list(csv.DictReader(io.StringIO(client.get("/export.csv?tier=1", auth=AUTH).text)))
    con = client.app.state.store.con.cursor()
    want = [d for (d,) in con.execute(
        "SELECT domain FROM accounts WHERE tier = 1 AND eligibility != 'likely_non_prospect' ORDER BY rank").fetchall()]
    assert [r["domain"] for r in rows] == want and want


def test_play_counts_match_their_lists(client):
    body = client.get("/plays", auth=AUTH).text
    assert "Who to call" in body and "Head of IT" in body
    exposed = client.get("/?play=exposed", auth=AUTH).text
    assert "14 accounts" in exposed  # 70 orgs, every 5th has RDP
    appliances = client.get("/?play=appliances", auth=AUTH).text
    assert "acme-fw.com" in appliances  # unranked accounts still appear in their play


def test_app_connection_is_capped_for_the_free_tier(client):
    con = client.app.state.store.con.cursor()
    settings = dict(con.execute(
        "SELECT name, value FROM duckdb_settings() WHERE name IN ('memory_limit', 'threads')").fetchall())
    assert settings == {"memory_limit": "256.0 MiB", "threads": "2"}


def test_summary_strip_counts(client):
    cur = client.app.state.store.con.cursor()
    t1 = cur.execute("SELECT count(*) FROM accounts WHERE tier = 1 AND eligibility != 'likely_non_prospect'").fetchone()[0]
    body = client.get("/plays", auth=AUTH).text
    assert f"<b>{t1:,}</b><span>Tier 1 accounts</span>" in body
    assert "Scoring config" in body


def test_short_tags_and_score_bar(client):
    body = client.get("/", auth=AUTH).text
    assert ">RDP exposed<" in body and "nginx 1.18.0 · KEV · EOL" in body
    assert 'title="Exposed Remote Desktop (RDP)' in body  # full sentence on hover
    widths = [int(w) for w in __import__("re").findall(r'style="width: (\d+)%"', body)]
    assert widths and all(0 <= w <= 100 for w in widths)
    hostile = "".join(client.get(f"/?tier=all&page={p}", auth=AUTH).text for p in (1, 2))
    assert "<script>alert(1)" not in hostile and "&lt;script&gt;" in hostile  # tag labels and titles escaped
