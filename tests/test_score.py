import duckdb
import orjson
import pytest
import zstandard

from salesintel.pipeline import extract as extract_mod
from salesintel.pipeline import score as sc

CFG = sc.load_config()
FROZEN = "bcc796098f9c"  # D63 (was 6bacfc84480b, D55; 765eef67e0c5, D50)
TS = "2026-10-26T10:00:00.000000"


def row(**kw):
    base = {c: None for c in sc.COLUMNS}
    base.update(domain="acme.com", attribution="direct", source="scan_hostname", ip="203.0.113.1", port=443,
                module="https", timestamp=TS, tags=[], vulns=[], opts_vulns=[], ssl_versions=[], hostnames=[],
                has_ssl=False, has_http=False, has_hsts=False, cert_expired=False, cert_self_signed=False,
                has_docker=False)
    base.update(kw)
    return base


def vuln(cve, cvss=9.8, epss=0.5, kev=False, verified=False):
    return {"cve": cve, "cvss": cvss, "cvss_version": "3.0", "epss": epss, "kev": kev,
            "ransomware": None, "verified": verified}


def total(rows, domain="acme.com"):
    fs = sc.account_findings(domain, rows, CFG)
    return sum(f.points for f in fs), fs


# ---------- worked example from signals-scoring.md section 2

WORKED = {
    "a.com": [
        row(domain="a.com", product="nginx", version="1.18.0", tags=["eol-product"],
            vulns=[vuln("CVE-2021-1001", kev=True)], port=80, module="http"),
        row(domain="a.com", product="OpenSSH", version="7.4", vulns=[vuln("CVE-2021-1002", epss=0.4)],
            port=22, module="ssh"),
        row(domain="a.com", has_ssl=True, cert_expired=True, cert_expires="20260901000000Z",
            ssl_versions=["TLSv1"], has_http=True, has_hsts=True),
    ],
    "b.com": [row(domain="b.com", module="mongodb", port=27017)],
    "c.com": [row(domain="c.com", product="Apache httpd", version="2.4.58", vulns=[vuln("CVE-2024-38475", kev=True)],
                  has_ssl=True, has_http=True, cert_expires="20270101000000Z")],
    "d.com": [row(domain="d.com", product="nginx", version="1.24.0", vulns=[vuln("CVE-2023-44487", kev=True, epss=1.0)],
                  http_server="nginx/1.24.0", has_ssl=True, has_http=True, cert_expires="20270101000000Z")],
    "e.com": [row(domain="e.com", appliance="fortinet", http_title="VPN Login", has_ssl=True,
                  cert_expires="20261107000000Z")],
}


@pytest.mark.parametrize("domain,points,tier", [("a.com", 48, 2), ("b.com", 45, 2), ("c.com", 27, 3),
                                                 ("d.com", 29, 3), ("e.com", 0, 0)])
def test_worked_example(domain, points, tier):
    got, fs = total(WORKED[domain], domain)
    assert got == points
    t1, t2 = CFG.raw["tiers"]["tier1"], CFG.raw["tiers"]["tier2"]
    assert (1 if got >= t1 else 2 if got >= t2 else 3 if got > 0 else 0) == tier


def test_worked_example_markers_and_facts():
    _, fs = total(WORKED["e.com"], "e.com")
    kinds = {f.kind for f in fs}
    assert {"fact_appliance_fortinet", "fact_panel", "marker_cert_expiring"} <= kinds
    assert all(f.points == 0 for f in fs)


# ---------- rules

def test_one_cve_award_per_product_and_cap():
    rows = [row(product="nginx", version="1.18.0", tags=["eol-product"],
                vulns=[vuln("CVE-2021-1", kev=True), vuln("CVE-2021-2", kev=True), vuln("CVE-2021-3")])]
    got, fs = total(rows)
    sw = [f for f in fs if f.kind == "software"]
    assert len(sw) == 1 and sw[0].points == 30  # 25 + 15 capped at 30


def test_software_account_cap_and_neglect_cap():
    rows = [row(product=f"p{i}", version="1", vulns=[vuln(f"CVE-2021-{i}", kev=True)], port=1000 + i) for i in range(4)]
    rows.append(row(has_ssl=True, cert_expired=True, ssl_versions=["SSLv3"], http_server="Apache/2.4.1",
                    has_http=True, cert_self_signed=True, source="cert_cn", cert_cn="acme.com"))
    got, fs = total(rows)
    assert sum(f.points for f in fs if f.family == "software") == 40
    assert sum(f.points for f in fs if f.family == "neglect") == 10
    assert got == 50


def test_exposure_awarded_once_and_by_module_only():
    rows = [row(module="rdp", port=3389), row(module="mysql", port=3306), row(module="https", port=3389)]
    got, fs = total(rows)
    exp = [f for f in fs if f.kind == "exposed_service"]
    assert len(exp) == 2 and sorted(f.points for f in exp) == [0, 45]
    assert got == 45


def test_ubiquitous_cve_awards_nothing_and_no_marker():
    rows = [row(product="Apache httpd", version="2.4.58", vulns=[vuln("CVE-2013-4365", epss=0.14, cvss=7.5)])]
    got, fs = total(rows)
    assert got == 0 and not any(f.kind.startswith("marker_") for f in fs)


def test_exposure_plus_one_more_problem_reaches_tier_1():
    rows = [row(module="rdp", port=3389), row(product="x", version="1", vulns=[vuln("CVE-2021-9", epss=0.4)])]
    got, _ = total(rows)
    assert got == 60 and got >= CFG.raw["tiers"]["tier1"]


def test_frozen_config_version():
    # Weights are frozen before labelling (D28, D50). Changing scoring.toml or the ubiquitous list
    # changes this version and needs a recorded decision.
    assert CFG.version == FROZEN


def test_cve_2026_scores_and_marks():
    rows = [row(product="x", version="1", vulns=[vuln("CVE-2026-999999", epss=0.3, cvss=9.0)])]
    got, fs = total(rows)
    assert got == 15 and any(f.kind == "marker_cve_2026" for f in fs)


def test_verified_wording():
    rows = [row(product="x", version="1", vulns=[vuln("CVE-2020-1", kev=True)], opts_vulns=["CVE-2020-1"])]
    _, fs = total(rows)
    assert "verified match to a known-exploited CVE" in next(f for f in fs if f.kind == "software").sentence
    rows[0]["opts_vulns"] = []
    _, fs = total(rows)
    assert "potential match to a known-exploited CVE" in next(f for f in fs if f.kind == "software").sentence


@pytest.mark.parametrize("expired,expires,state", [
    (True, "20270101000000Z", "expired"),       # flag wins
    (False, "20261001000000Z", "expired"),      # before the scan
    (False, "20261110000000Z", "expiring"),     # 15 days after the scan
    (False, "20270101000000Z", "ok"),
])
def test_cert_states_exclusive(expired, expires, state):
    assert sc.cert_state(row(has_ssl=True, cert_expired=expired, cert_expires=expires), 30) == state


def test_cdn_records_only_add_the_fact():
    rows = [row(infra_class="cdn", org="Incapsula Inc", module="rdp", vulns=[vuln("CVE-2021-1", kev=True)],
                product="x", version="1", tags=["eol-product"])]
    got, fs = total(rows)
    assert got == 0 and [f.kind for f in fs] == ["fact_behind_cdn"]


# ---------- eligibility

@pytest.mark.parametrize("domain,rows,label", [
    ("alice.duckdns.org", [row(domain="alice.duckdns.org")], "likely_non_prospect"),
    ("acme.com", [row(http_title="This domain is for sale")], "likely_non_prospect"),
    ("hoster.net", [row(domain="hoster.net", ip=f"198.51.100.{i}", source="ptr", hostnames=[f"s{1000 + i}.hoster.net"])
                    for i in range(6)], "likely_non_prospect"),
    ("isp.net", [row(domain="isp.net", source="ptr", org="Some Broadband Residential")], "likely_non_prospect"),
    ("uni.edu", [row(domain="uni.edu", source="ptr")], "likely_org"),
    ("walmart.com", [row(domain="walmart.com", source="ptr", org="Wal-Mart Stores, Inc.", ip=f"198.51.100.{i}")
                     for i in range(10)], "likely_org"),
    ("acme.com", [row(cert_o="Acme Widgets Ltd", source="cert_cn")], "likely_org"),
    ("acme.com", [row(cert_o="Plesk", source="cert_cn")], "uncertain"),
])
def test_eligibility(domain, rows, label):
    assert sc.eligibility(domain, rows, CFG)[0] == label


# ---------- end to end: extract -> score -> artifact

def test_score_end_to_end_artifact(tmp_path):
    recs = [
        {"ip_str": "198.51.100.1", "port": 3389, "timestamp": TS, "org": "Acme Corp", "_shodan": {"module": "rdp"}},
        {"ip_str": "198.51.100.1", "port": 443, "timestamp": TS, "org": "Acme Corp",
         "_shodan": {"module": "https", "options": {"hostname": "www.acme.com"}}},
        {"ip_str": "198.51.100.2", "port": 80, "timestamp": TS, "org": "Hetzner Online GmbH",
         "hostnames": ["web.beta.org"], "product": "nginx", "version": "1.18.0", "tags": ["eol-product"],
         "_shodan": {"module": "http"}},
        {"ip_str": "198.51.100.2", "port": 3306, "timestamp": TS, "org": "Hetzner Online GmbH",
         "_shodan": {"module": "mysql"}},  # nameless on a hosting IP: unresolved, never via-IP
    ]
    src = tmp_path / "in.jsonl.zst"
    src.write_bytes(zstandard.ZstdCompressor().compress(b"".join(orjson.dumps(r) + b"\n" for r in recs)))
    m = extract_mod.extract(src, tmp_path / "out", workers=1)
    art = tmp_path / "artifact.duckdb"
    man = sc.score(tmp_path / "out" / "features" / m["input_sha256"], art)
    con = duckdb.connect(str(art), read_only=True)
    accounts = con.execute("SELECT domain, score, tier, rank FROM accounts ORDER BY rank").fetchall()
    assert accounts == [("acme.com", 45, 2, 1), ("beta.org", 15, 3, 2)]
    funnel = dict(((a, c), n) for a, c, n in con.execute("SELECT * FROM funnel").fetchall())
    assert funnel[("via_ip", "customer_or_isp")] == 1 and funnel[("unresolved", "cloud_hosting")] == 1
    keys = dict(con.execute("SELECT key, value FROM manifest").fetchall())
    assert keys["input_sha256"] == m["input_sha256"] and keys["scoring_config_version"] == CFG.version
    assert man["output_bytes"] == art.stat().st_size


# ---------- D55: exposures answered by another service do not count

@pytest.mark.parametrize("module,product,counts", [
    ("rdp", "Remote Desktop Protocol", True),
    ("rdp", None, True),
    ("rdp", "OpenSSH", False),
    ("rdp", "Microsoft Windows RPC over HTTP", False),
    ("telnet", "Cisco router telnetd", True),
    ("telnet", "OpenSSH", False),
    ("mysql", "MariaDB", True),
    ("mysql", "nginx", False),
    ("dnp3", "Ncat http proxy", False),
])
def test_exposure_guard(module, product, counts):
    got, fs = total([row(module=module, port=1, product=product)])
    assert any(f.kind == "exposed_service" for f in fs) is counts
    assert got == (45 if counts else 0)


def test_genuine_exposure_still_scores_when_another_is_false():
    got, fs = total([row(module="rdp", port=3389, ip="203.0.113.1", product="OpenSSH"),
                     row(module="mysql", port=3306, ip="203.0.113.9", product="MySQL")])
    exp = [f for f in fs if f.kind == "exposed_service"]
    assert got == 45 and len(exp) == 1 and exp[0].module == "mysql"


def test_count_false_exposures_script(tmp_path):
    import importlib.util
    from pathlib import Path
    import json as _json

    from salesintel.pipeline.score import write_artifact

    findings = [{"domain": d, "kind": "exposed_service", "family": "exposure", "points": p, "sentence": "s",
                 "ip": "203.0.113.1", "port": 3389, "module": "rdp", "product": prod, "version": None, "cves": "[]",
                 "attribution": "direct", "source": "scan_hostname", "observed_at": TS}
                for d, prod, p in [("a.com", "OpenSSH", 45), ("b.com", "OpenSSH", 45), ("b.com", "MySQL", 0),
                                   ("c.com", "Remote Desktop Protocol", 45)]]
    accounts = [{"domain": d, "rank": i} for i, d in enumerate(["a.com", "b.com", "c.com"], 1)]
    art = tmp_path / "a.duckdb"
    write_artifact(art, {"scoring_config_version": "765eef67e0c5"}, accounts, findings, [("direct", "x", 1)])
    key = tmp_path / "key.json"
    key.write_text(_json.dumps({"key": {
        "L01": {"domain": "a.com", "rank_ours": 1, "rank_cvss": None, "rank_random": None},
        "L02": {"domain": "b.com", "rank_ours": 2, "rank_cvss": None, "rank_random": None},
        "L03": {"domain": "c.com", "rank_ours": None, "rank_cvss": 1, "rank_random": None}}}))
    spec = importlib.util.spec_from_file_location("cfe", Path(__file__).parents[1] / "scripts" / "count_false_exposures.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    res = mod.count(art, key)
    assert res["lists"]["ours"] == {"accounts": 2, "with_false_exposure": 2, "lose_exposure_points": 1,
                                    "awarded_exposure_was_false": 2}
    assert res["lists"]["cvss"]["with_false_exposure"] == 0


# ---------- D63: evidence and labels come from the records that earned the points

def test_software_finding_cites_the_record_with_the_cve():
    rows = [row(product="nginx", version="1.18.0", ip="203.0.113.1", port=80, module="http", tags=["eol-product"]),
            row(product="nginx", version="1.18.0", ip="203.0.113.2", port=8443, module="https",
                vulns=[vuln("CVE-2021-1001", kev=True)])]
    sw = next(f for f in total(rows)[1] if f.kind == "software")
    assert (sw.ip, sw.port, sw.module) == ("203.0.113.2", 8443, "https") and "203.0.113.2" in sw.sentence


def test_eol_only_software_finding_cites_the_eol_record():
    rows = [row(product="nginx", version="1.18.0", ip="203.0.113.1", vulns=[vuln("CVE-2021-1009", epss=0.01)]),
            row(product="nginx", version="1.18.0", ip="203.0.113.2", tags=["eol-product"])]
    sw = next(f for f in total(rows)[1] if f.kind == "software")
    assert sw.ip == "203.0.113.2" and sw.points == 15


def test_attribution_label_from_point_bearing_records():
    rows = [row(source="scan_hostname", ip="203.0.113.1"),  # High link, no points
            row(attribution="via_ip", source=None, ip="203.0.113.2", module="rdp", port=3389)]
    fs = total(rows)[1]
    assert sc.attribution_label(fs, rows) == "Low"
    assert sc.attribution_label(sc.account_findings("acme.com", rows[:1], CFG), rows[:1]) == "High"  # no points


def test_no_via_ip_on_an_ip_with_cloud_records(tmp_path):
    recs = [  # one IP, mixed metadata: the named record is cloud-tagged, the nameless one is not
        {"ip_str": "198.51.100.9", "port": 443, "timestamp": TS, "org": "Example Corp", "cloud": {"provider": "Amazon"},
         "_shodan": {"module": "https", "options": {"hostname": "www.mixed.com"}}},
        {"ip_str": "198.51.100.9", "port": 3389, "timestamp": TS, "org": "Example Corp", "_shodan": {"module": "rdp"}},
        {"ip_str": "198.51.100.10", "port": 443, "timestamp": TS, "org": "Example Corp",
         "_shodan": {"module": "https", "options": {"hostname": "www.plain.com"}}},
        {"ip_str": "198.51.100.10", "port": 3389, "timestamp": TS, "org": "Example Corp", "_shodan": {"module": "rdp"}},
    ]
    src = tmp_path / "in.jsonl.zst"
    src.write_bytes(zstandard.ZstdCompressor().compress(b"".join(orjson.dumps(r) + b"\n" for r in recs)))
    m = extract_mod.extract(src, tmp_path / "out", workers=1)
    con = duckdb.connect()
    sc.attribute(con, tmp_path / "out" / "features" / m["input_sha256"])
    got = dict(con.execute("SELECT ip, attribution FROM attributed WHERE port = 3389").fetchall())
    assert got == {"198.51.100.9": "unresolved", "198.51.100.10": "via_ip"}
