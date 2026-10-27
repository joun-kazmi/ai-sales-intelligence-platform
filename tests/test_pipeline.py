import hashlib
import io

import orjson
import pyarrow.parquet as pq
import pytest
import zstandard

from salesintel.pipeline import extract as extract_mod
from salesintel.pipeline import infra, names, sample
from salesintel.pipeline.project import project

LISTS = infra.load()


def rec(**kw):
    base = {"ip_str": "203.0.113.7", "port": 443, "transport": "tcp", "timestamp": "2026-10-26T01:02:03",
            "org": "Example Corp", "isp": "Example ISP", "_shodan": {"module": "https", "id": "x"}}
    base.update(kw)
    return base


# ---------- names

@pytest.mark.parametrize("raw,want", [
    ("WWW.Example.COM.", "www.example.com"),
    ("example.com:8443", "example.com"),
    ("203.0.113.7", None),
    ("[2001:db8::1]", None),
    ("localhost", None),
    ("not a host", None),
    (None, None),
])
def test_normalize(raw, want):
    assert names.normalize(raw) == want


@pytest.mark.parametrize("host,ip,want", [
    ("203-0-113-7.static.isp.net", "203.0.113.7", True),
    ("7.113.0.203.in-addr.isp.net", "203.0.113.7", True),
    ("host-cb007107.isp.net", "203.0.113.7", True),  # hex
    ("mail.example.com", "203.0.113.7", False),
    ("ec2-1-2-3-4.compute.example.net", "203.0.113.7", True),  # generic dotted quad
])
def test_ip_like(host, ip, want):
    assert names.ip_like(host, ip) is want


def test_candidates_priority_dedup_and_filters():
    got = names.candidates(
        LISTS, "203.0.113.7",
        scan_hostname="shop.acme.co.uk",
        cert_cn="www.acme.co.uk",                 # same registrable domain: deduped
        http_host="203.0.113.7",                  # IP, ignored
        ptr=["203-0-113-7.dsl.isp.net", "mail.other.org", "x.googleusercontent.com"],
    )
    assert got == [("scan_hostname", "acme.co.uk"), ("ptr", "other.org")]


def test_wildcard_cert_cn_is_not_a_source():
    got = names.candidates(LISTS, "203.0.113.7", None, "*.acme.com", None, [])
    assert got == []


def test_private_psl_keeps_dynamic_dns_hosts_separate():
    a = names.candidates(LISTS, "203.0.113.7", "alice.duckdns.org", None, None, [])
    b = names.candidates(LISTS, "203.0.113.8", "bob.duckdns.org", None, None, [])
    assert a[0][1] != b[0][1]


# ---------- infra classes and appliances

def test_infra_class():
    assert infra.infra_class(LISTS, ["cdn"], "Anything", "", "") == "cdn"
    assert infra.infra_class(LISTS, [], "Incapsula Inc", "", "") == "cdn"
    assert infra.infra_class(LISTS, [], "Hetzner Online GmbH", "", "") == "cloud_hosting"
    assert infra.infra_class(LISTS, [], "Example Corp", "", "Amazon") == "cloud_hosting"
    assert infra.infra_class(LISTS, [], "Example Corp", "Example ISP", "") is None


def test_appliance():
    assert infra.appliance(LISTS, "FortiGate", "", "", "") == "fortinet"
    assert infra.appliance(LISTS, "", "Fortis Bank login", "", "") is None
    assert infra.appliance(LISTS, "", "", "", "SonicWALL") == "sonicwall"


# ---------- projection

def test_drop_reasons():
    assert project(rec(tags=["honeypot"]), LISTS) == (None, "honeypot")
    assert project(rec(_shodan={"module": "x11"}), LISTS) == (None, "noise_module")
    assert project(rec(tags=["cdn"]), LISTS) == (None, "cdn_edge_unnamed")


def test_cdn_record_naming_a_domain_is_kept():
    row, reason = project(rec(tags=["cdn"], _shodan={"module": "https", "options": {"hostname": "acme.com"}}), LISTS)
    assert reason == "kept" and row["infra_class"] == "cdn"
    assert row["names"] == [{"source": "scan_hostname", "domain": "acme.com"}]


def test_nameless_customer_record_is_kept_for_via_ip():
    row, reason = project(rec(port=3389, _shodan={"module": "rdp"}), LISTS)
    assert reason == "kept" and row["names"] == [] and row["module"] == "rdp"


def test_projected_fields():
    r = rec(
        product="nginx", version="1.18.0", tags=["eol-product"],
        vulns={"CVE-2021-1": {"cvss": 9.8, "cvss_version": 3.0, "epss": 0.5, "kev": True,
                              "ransomware_campaign": "Known", "verified": False}},
        opts={"vulns": ["CVE-2021-1"]},
        ssl={"versions": ["TLSv1", "-SSLv3"], "cert": {"expired": True, "expires": "20261001000000Z",
             "subject": {"CN": "acme.com", "O": "Acme"}, "issuer": {"CN": "acme.com", "O": "Acme"}}},
        http={"server": "nginx/1.18.0", "title": "x" * 500, "headers": {"Strict-Transport-Security": "max-age=1"}},
        _sample={"ip_domain_count": 3},
    )
    row, _ = project(r, LISTS)
    assert row["vulns"][0] == {"cve": "CVE-2021-1", "cvss": 9.8, "cvss_version": "3.0", "epss": 0.5,
                               "kev": True, "ransomware": "Known", "verified": False}
    assert row["opts_vulns"] == ["CVE-2021-1"]
    assert row["ssl_versions"] == ["TLSv1"]
    assert row["cert_expired"] and row["cert_self_signed"] and row["has_hsts"]
    assert len(row["http_title"]) == 200
    assert row["sample_ip_domain_count"] == 3
    assert row["names"][0] == {"source": "cert_cn", "domain": "acme.com"}


def test_malformed_subobjects_do_not_crash():
    row, reason = project(rec(ssl="oops", http=["bad"], cloud=5, opts=None, vulns=[1]), LISTS)
    assert reason == "kept" and row["vulns"] == [] and not row["has_ssl"]


# ---------- extract end to end

def _write_zst(path, records):
    raw = b"".join(orjson.dumps(r) + b"\n" for r in records) + b"{not json\n"
    path.write_bytes(zstandard.ZstdCompressor().compress(raw))


RECORDS = [
    rec(ip_str="198.51.100.1", _shodan={"module": "https", "options": {"hostname": "acme.com"}},
        data="banner", vulns={"CVE-1": {"cvss": 5.0, "summary": "long text", "references": ["u"]}},
        ssl={"chain": ["pem"], "versions": ["TLSv1.2"]}, http={"html": "<x>", "favicon": {"data": "b64"}}),
    rec(ip_str="198.51.100.1", port=3389, _shodan={"module": "rdp"}),
    rec(ip_str="198.51.100.2", hostnames=["a.shared-one.com"]),
    rec(ip_str="198.51.100.2", hostnames=["b.shared-two.com"]),
    rec(ip_str="198.51.100.3", tags=["cdn"]),
    rec(ip_str="198.51.100.4", tags=["honeypot"]),
]


def test_extract_partition_manifest_and_idempotence(tmp_path):
    src = tmp_path / "in.jsonl.zst"
    _write_zst(src, RECORDS)
    m = extract_mod.extract(src, tmp_path / "out", workers=2, batch_lines=2)
    part = tmp_path / "out" / "features" / m["input_sha256"]
    assert (part / "manifest.json").exists()
    assert not list((tmp_path / "out" / "features").glob(".tmp-*"))
    c = m["counts"]
    assert c["records"] == 7 and c["dropped_parse_error"] == 1
    assert c["dropped_honeypot"] == 1 and c["dropped_cdn_edge_unnamed"] == 1 and c["kept"] == 4
    assert m["input_sha256"] == hashlib.sha256(src.read_bytes()).hexdigest()
    table = pq.ParquetDataset(sorted(part.glob("part-*.parquet"))).read()
    assert table.num_rows == 4
    again = extract_mod.extract(src, tmp_path / "out", workers=2)
    assert again["created_at"] == m["created_at"]  # skipped, not rebuilt


def test_extract_refuses_stale_partition(tmp_path, monkeypatch):
    src = tmp_path / "in.jsonl.zst"
    _write_zst(src, RECORDS)
    extract_mod.extract(src, tmp_path / "out", workers=1)
    monkeypatch.setattr(extract_mod, "EXTRACTOR_VERSION", "999")
    with pytest.raises(SystemExit):
        extract_mod.extract(src, tmp_path / "out", workers=1)


# ---------- domain-complete sample

def test_keep_domain_is_stable():
    # Fixed expectation: must not depend on PYTHONHASHSEED or the machine.
    d = "acme.com"
    want = int.from_bytes(hashlib.blake2b(d.encode(), digest_size=8).digest(), "big") % 7 == 0
    assert sample.keep_domain(d, 7) is want
    assert all(sample.keep_domain(x, 1) for x in ("a.com", "b.org"))


def test_sample_carries_full_ip_domain_count(tmp_path):
    src = tmp_path / "in.jsonl.zst"
    _write_zst(src, RECORDS)
    m = extract_mod.extract(src, tmp_path / "out", workers=1)
    part = tmp_path / "out" / "features" / m["input_sha256"]
    out = tmp_path / "sample.jsonl.zst"
    sm = sample.build(src, part, out, modulus=1)  # keep every domain
    lines = zstandard.ZstdDecompressor().stream_reader(io.BytesIO(out.read_bytes())).read().splitlines()
    got = [orjson.loads(x) for x in lines]
    by_ip = {}
    for r in got:
        by_ip.setdefault(r["ip_str"], set()).add(r["_sample"]["ip_domain_count"])
        assert "data" not in r and "html" not in r.get("http", {}) and "favicon" not in r.get("http", {})
        assert "chain" not in r.get("ssl", {})
        assert all("summary" not in v and "references" not in v for v in r.get("vulns", {}).values())
    assert by_ip == {"198.51.100.1": {1}, "198.51.100.2": {2}}
    assert sm["sampled_ips_shared"] == 1
    # The nameless RDP record rides along with its IP.
    assert any(r.get("port") == 3389 for r in got)
    # Schema fields survive the strip.
    acme = next(r for r in got if r.get("vulns"))
    assert acme["vulns"]["CVE-1"]["cvss"] == 5.0 and acme["ssl"]["versions"] == ["TLSv1.2"]
