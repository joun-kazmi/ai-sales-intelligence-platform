import csv
import pytest

import httpx

from salesintel.eval import rdap

DOC = {
    "name": "EXAMPLE-NET", "country": "US",
    "entities": [
        {"roles": ["technical"], "vcardArray": ["vcard", [["fn", {}, "text", "NOC Team"]]]},
        {"roles": ["registrant"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                                          ["fn", {}, "text", "Example Corp"]]]},
    ],
}


def test_owner_prefers_registrant():
    assert rdap.owner_from_rdap(DOC) == "Example Corp (EXAMPLE-NET, US)"
    assert rdap.owner_from_rdap({"name": "NET-1"}) == "NET-1"
    assert rdap.owner_from_rdap({}) == "unknown"


def test_fill_keeps_columns_and_caches(tmp_path):
    path = tmp_path / "misses.csv"
    rows = [
        {"domain": "a.com", "host": "a.com", "ip": "192.0.2.1", "source": "cert_cn", "resolved_ips": "", "verdict": "ok", "notes": "x"},
        {"domain": "b.com", "host": "b.com", "ip": "192.0.2.1", "source": "ptr", "resolved_ips": "", "verdict": "", "notes": ""},
        {"domain": "c.com", "host": "c.com", "ip": "192.0.2.9", "source": "ptr", "resolved_ips": "", "verdict": "", "notes": ""},
    ]
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req.url.path)
        if req.url.path.endswith("192.0.2.9"):
            return httpx.Response(404)
        return httpx.Response(200, json=DOC)

    res = rdap.fill(path, httpx.Client(transport=httpx.MockTransport(handler)), pause=0)
    out = list(csv.DictReader(open(path)))
    assert res == {"rows": 3, "lookups": 2} and len(seen) == 2  # one lookup per distinct IP
    assert list(out[0]) == ["domain", "host", "ip", "source", "resolved_ips", "ip_owner", "verdict", "notes"]
    assert out[0]["ip_owner"] == out[1]["ip_owner"] == "Example Corp (EXAMPLE-NET, US)"
    assert out[0]["verdict"] == "ok" and out[0]["notes"] == "x"  # hand-check work is kept
    assert out[2]["ip_owner"] == "rdap error 404"
    again = rdap.fill(path, httpx.Client(transport=httpx.MockTransport(handler)), pause=0)
    assert again["lookups"] == 0  # already filled rows are skipped


def _write(path, ips):
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["domain", "host", "ip", "source", "resolved_ips", "verdict", "notes"])
        w.writeheader()
        w.writerows({"domain": f"d{i}.com", "host": f"d{i}.com", "ip": ip, "source": "ptr", "resolved_ips": "",
                     "verdict": "", "notes": ""} for i, ip in enumerate(ips))


def test_dropped_connection_retries_once_then_records_error(tmp_path):
    path = tmp_path / "misses.csv"
    _write(path, ["192.0.2.1", "192.0.2.2"])
    calls = {}

    def handler(req: httpx.Request) -> httpx.Response:
        ip = req.url.path.rsplit("/", 1)[1]
        calls[ip] = calls.get(ip, 0) + 1
        if ip == "192.0.2.1" and calls[ip] == 1:
            raise httpx.RemoteProtocolError("Server disconnected without sending a response.", request=req)
        if ip == "192.0.2.2":
            raise httpx.ConnectTimeout("timed out", request=req)
        return httpx.Response(200, json=DOC)

    res = rdap.fill(path, httpx.Client(transport=httpx.MockTransport(handler)), pause=0)
    out = {r["ip"]: r["ip_owner"] for r in csv.DictReader(open(path))}
    assert res["lookups"] == 2 and calls == {"192.0.2.1": 2, "192.0.2.2": 2}
    assert out["192.0.2.1"] == "Example Corp (EXAMPLE-NET, US)"  # retry succeeded
    assert out["192.0.2.2"] == "rdap error: ConnectTimeout"


def test_progress_is_saved_when_the_run_dies(tmp_path):
    path = tmp_path / "misses.csv"
    _write(path, ["192.0.2.1", "192.0.2.2", "192.0.2.3"])

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("192.0.2.3"):
            raise RuntimeError("unexpected crash")  # not an httpx error: the run stops
        return httpx.Response(200, json=DOC)

    with pytest.raises(RuntimeError):
        rdap.fill(path, httpx.Client(transport=httpx.MockTransport(handler)), pause=0)
    out = list(csv.DictReader(open(path)))
    assert [r["ip_owner"] for r in out] == ["Example Corp (EXAMPLE-NET, US)"] * 2 + [""]
    again = rdap.fill(path, httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=DOC))), pause=0)
    assert again["lookups"] == 1  # the rerun only looks up what is missing
