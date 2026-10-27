import csv
import json

import orjson
import pytest
import zstandard

from salesintel.eval import dnscheck, labelpool, sensitivity
from salesintel.pipeline import extract as extract_mod
from salesintel.pipeline import score as sc

TS = "2026-10-26T10:00:00.000000"


def _rec(ip, port, module, org="Example Corp", **kw):
    return {"ip_str": ip, "port": port, "timestamp": TS, "org": org, "_shodan": {"module": module}, **kw}


@pytest.fixture
def scored(tmp_path):
    recs = []
    for i in range(30):
        name = f"org{i:02d}.com"
        recs.append(_rec(f"198.51.100.{i}", 443, "https", _shodan={"module": "https", "options": {"hostname": f"www.{name}"}},
                         product="Apache httpd", version="2.4.58",
                         vulns={f"CVE-2024-{i:04d}": {"cvss": 5.0 + i % 5, "epss": 0.5, "kev": i % 3 == 0}}))
        if i % 4 == 0:
            recs.append(_rec(f"198.51.100.{i}", 3389, "rdp"))
    recs.append(_rec("198.51.100.200", 443, "https", hostnames=["home.alice.duckdns.org"]))  # non-prospect
    src = tmp_path / "in.jsonl.zst"
    src.write_bytes(zstandard.ZstdCompressor().compress(b"".join(orjson.dumps(r) + b"\n" for r in recs)))
    m = extract_mod.extract(src, tmp_path / "out", workers=1)
    feats = tmp_path / "out" / "features" / m["input_sha256"]
    art = tmp_path / "artifact.duckdb"
    sc.score(feats, art)
    return feats, art


def test_label_pool_is_blind_and_evaluates(tmp_path, scored):
    feats, art = scored
    out = tmp_path / "c2"
    meta = labelpool.build(art, feats, out, k=5)
    assert meta["list_sizes"] == {"ours": 5, "cvss": 5, "random": 5}
    rows = list(csv.DictReader(open(out / "labels.csv")))
    assert len(rows) == meta["pooled"] <= 15
    assert all("duckdns" not in r["domain"] for r in rows)  # same eligible set for every list
    sheet = (out / "labels.csv").read_text()
    for leak in ("score", "tier", "rank", "ours", "cvss", "random", "points"):
        assert leak not in sheet.lower().split("evidence")[0]  # header carries no ranking info
    assert "potential CVEs" in sheet and "Linked by" in sheet
    with pytest.raises(SystemExit):
        labelpool.build(art, feats, out, k=5)  # never overwrites a labelled sheet

    for r in rows:  # label: yes for accounts with RDP, else no
        r["worth_a_call"] = "yes" if "rdp" in r["evidence"] else "n"
    with open(out / "labels.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    res = labelpool.evaluate(out)
    assert res["lists"]["ours"]["precision"] == 1.0  # RDP accounts rank first
    assert res["lists"]["ours"]["yes"] + res["lists"]["ours"]["no"] == 5


def test_evaluate_requires_every_label(tmp_path, scored):
    feats, art = scored
    out = tmp_path / "c2"
    labelpool.build(art, feats, out, k=3)
    with pytest.raises(SystemExit):
        labelpool.evaluate(out)


def test_wilson_interval():
    lo, hi = labelpool.wilson(15, 20)
    assert 0.5 < lo < 0.75 < hi < 0.95


def test_dns_check_match_rates(tmp_path, scored):
    feats, _ = scored

    def fake(name: str) -> set[str]:
        # www.orgNN.com resolves to its IP only for even NN; everything else does not resolve.
        if name.startswith("www.org"):
            n = int(name[7:9])
            return {f"198.51.100.{n}"} if n % 2 == 0 else {"192.0.2.1"}
        return set()

    res = dnscheck.run(feats, tmp_path / "c1", per_source=100, resolver=fake)
    g = res["groups"]["source:scan_hostname"]
    assert g["links"] == 30 and g["matched"] == 15 and g["match_rate"] == 0.5
    assert res["misses_for_hand_check"] > 0
    assert (tmp_path / "c1" / "misses.csv").exists()
    assert json.loads((tmp_path / "c1" / "c1_result.json").read_text())["metric"].startswith("forward DNS")


def test_sensitivity_runs_every_weight(tmp_path, scored):
    feats, _ = scored
    res = sensitivity.run(feats, tmp_path / "c4.json")
    assert len(res["runs"]) == 2 * len(sensitivity.WEIGHTS)
    assert 0 <= res["min_top20_overlap"] <= 1 and res["min_spearman"] <= 1
