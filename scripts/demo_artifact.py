"""Build a synthetic demo artifact for documentation screenshots (no real organisations).

Domains use the reserved `.example` TLD (RFC 2606) and IPs come from the documentation ranges
(RFC 5737), so screenshots in git never name a real, possibly vulnerable organisation (NFR5).
Findings come from the real scoring code; only the input records are invented.

    uv run python scripts/demo_artifact.py out/demo/artifact.duckdb
"""

import random
import sys
from datetime import UTC, datetime
from pathlib import Path

import orjson

from salesintel.pipeline.score import account_findings, eligibility, load_config, write_artifact

TS = "2026-10-26T09:30:00.000000"
NAMES = ["northwind-traders", "contoso-health", "fabrikam-logistics", "tailspin-air", "woodgrove-bank",
         "adventure-works", "litware-labs", "proseware-legal", "wingtip-toys", "fourth-coffee",
         "alpine-ski-house", "blue-yonder-air", "coho-winery", "graphic-design-inst", "humongous-insurance",
         "lucerne-publishing", "margies-travel", "nod-publishers", "southridge-video", "trey-research",
         "wide-world-importers", "datum-corp", "relecloud", "bellows-college", "city-power-light"]
PREFIXES = ["192.0.2.", "198.51.100.", "203.0.113."]


def row(domain, ip, port, module, **kw):
    base = dict(domain=domain, attribution="direct", source="scan_hostname", ip=ip, port=port, module=module,
                timestamp=TS, infra_class=None, org=f"{domain.split('.')[0].replace('-', ' ').title()} Ltd",
                tags=[], product=None, version=None, vulns=[], opts_vulns=[], has_ssl=False, cert_expired=False,
                cert_expires=None, cert_self_signed=False, cert_cn=None, cert_o=None, ssl_versions=[],
                has_http=False, has_hsts=False, http_server=None, http_title=None, appliance=None, has_docker=False,
                scan_hostname=f"www.{domain}", http_host=None, hostnames=[])
    base.update(kw)
    return base


def vuln(cve, cvss, epss, kev=False):
    return {"cve": cve, "cvss": cvss, "epss": epss, "kev": kev, "ransomware": None, "verified": False}


def accounts(rng: random.Random) -> dict[str, list[dict]]:
    out = {}
    for i, name in enumerate(NAMES):
        d = f"{name}.example"
        ip = lambda n: f"{PREFIXES[(i + n) % 3]}{(i * 7 + n * 13) % 250 + 1}"  # noqa: E731
        recs = [row(d, ip(0), 443, "https", has_ssl=True, has_http=True, has_hsts=i % 3 == 0,
                    cert_expires="20270301000000Z" if i % 4 else "20261109000000Z",
                    http_server="nginx/1.18.0" if i % 2 else "Apache/2.4.58")]
        if i % 3 == 0:
            recs.append(row(d, ip(1), 3389, "rdp", product="Remote Desktop Protocol"))
        if i % 5 == 1:
            recs.append(row(d, ip(2), 3306, "mysql", product="MySQL", version="5.7.33"))
        if i % 2:
            recs.append(row(d, ip(3), 80, "http", product="nginx", version="1.18.0", tags=["eol-product"],
                            vulns=[vuln("CVE-2021-23017", 7.7, 0.53)]))
        else:
            recs.append(row(d, ip(3), 80, "http", product="Apache httpd", version="2.4.58",
                            vulns=[vuln("CVE-2024-38475", 9.1, 0.99, kev=True)]))
        if i % 4 == 2:
            recs.append(row(d, ip(4), 22, "ssh", product="OpenSSH", version="7.4",
                            vulns=[vuln("CVE-2023-38408", 9.8, 0.35)]))
        if i % 6 == 4:
            recs.append(row(d, ip(5), 443, "https", has_ssl=True, cert_expired=True, cert_expires="20260801000000Z",
                            ssl_versions=["TLSv1", "TLSv1.1"]))
        if i % 7 == 3:
            recs.append(row(d, ip(6), 443, "https", appliance="fortinet", http_title="SSL VPN login",
                            product="FortiGate"))
        out[d] = recs
    return out


def main(out: Path) -> None:
    cfg = load_config()
    t1, t2 = cfg.raw["tiers"]["tier1"], cfg.raw["tiers"]["tier2"]
    accs, finds = [], []
    for domain, recs in accounts(random.Random(7)).items():
        fs = account_findings(domain, recs, cfg)
        total = sum(f.points for f in fs)
        scored = [f for f in fs if f.points > 0]
        elig, why = eligibility(domain, recs, cfg)
        accs.append({
            "domain": domain, "score": total,
            "tier": 1 if total >= t1 else 2 if total >= t2 else 3 if total > 0 else 0,
            "n_findings": len(scored),
            "exposure_points": sum(f.points for f in fs if f.family == "exposure"),
            "software_points": sum(f.points for f in fs if f.family == "software"),
            "neglect_points": sum(f.points for f in fs if f.family == "neglect"),
            "reasons": [f.sentence for f in sorted(scored, key=lambda f: (-f.points, f.sentence))[:3]],
            "why_now": sorted({f.kind.removeprefix("marker_") for f in fs if f.family == "why_now"}),
            "facts": sorted({f.kind.removeprefix("fact_").split("_")[0] for f in fs if f.family == "fact"}),
            "appliances": sorted({f.kind.removeprefix("fact_appliance_") for f in fs if f.kind.startswith("fact_appliance_")}),
            "attribution_label": "High", "eligibility": elig, "eligibility_reason": why,
            "n_ips": len({r["ip"] for r in recs}), "n_records": len(recs),
        })
        finds += [{"domain": domain, **f.__dict__, "cves": orjson.dumps(f.cves).decode()} for f in fs]
    accs.sort(key=lambda a: (-a["score"], -a["n_findings"], a["domain"]))
    for i, a in enumerate(accs, 1):
        a["rank"] = i
    manifest = {"kind": "artifact (synthetic demo)", "input_file": "synthetic-demo.jsonl.zst",
                "input_sha256": "demo" + "0" * 60, "scoring_config_version": cfg.version,
                "snapshot_from": "2026-10-25T18:13:32", "snapshot_to": "2026-10-26T13:06:06",
                "accounts": str(len(accs)), "findings": str(len(finds)),
                "created_at": datetime.now(UTC).isoformat(timespec="seconds")}
    out.parent.mkdir(parents=True, exist_ok=True)
    write_artifact(out, manifest, accs, finds, [("direct", "customer_or_isp", sum(a["n_records"] for a in accs))])
    print(f"{out}: {len(accs)} synthetic accounts")


if __name__ == "__main__":
    main(Path(sys.argv[1] if len(sys.argv) > 1 else "out/demo/artifact.duckdb"))
