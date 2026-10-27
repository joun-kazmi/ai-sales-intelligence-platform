import csv

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
