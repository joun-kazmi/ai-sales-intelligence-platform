"""Score: feature partition -> artifact (DuckDB) with accounts, findings, funnel, manifest.

Implements signals-scoring.md sections 1b and 2 (D25, D34-D38, D42, D47). Every point comes
from one finding with one sentence and its evidence; an account's score is their sum.

    salesintel-score out/full/features/<sha256> --out out/full/artifact.duckdb
"""

import argparse
import hashlib
import re
import sys
import time
import tomllib
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import cache
from pathlib import Path

import duckdb
import orjson
import pyarrow as pa

from salesintel.pipeline.atomic import atomic_file, code_commit
from salesintel.pipeline.attribute import attribute

HERE = Path(__file__).parent
SCORING_TOML = HERE / "scoring.toml"
UBIQUITOUS_TXT = HERE / "ubiquitous_cves.txt"
SCORER_VERSION = "1"

LABEL = {"scan_hostname": "High", "cert_cn": "High", "http_host": "Medium", "ptr": "Medium", None: "Low"}
LABEL_RANK = {"High": 3, "Medium": 2, "Low": 1}
_VERSION_IN_SERVER = re.compile(r"/\s*\d")


@dataclass(frozen=True)
class Config:
    version: str
    raw: dict
    ubiquitous: frozenset[str]
    panel: re.Pattern
    parked: re.Pattern
    residential: re.Pattern
    vendor_o: re.Pattern

    @property
    def pts(self) -> dict:
        return self.raw["points"]


@cache
def load_config(toml_path: Path = SCORING_TOML, ubiq_path: Path = UBIQUITOUS_TXT) -> Config:
    raw_bytes = toml_path.read_bytes() + ubiq_path.read_bytes()
    raw = tomllib.loads(toml_path.read_text())
    ubiq = frozenset(
        line.split("#", 1)[0].strip() for line in ubiq_path.read_text().splitlines() if line.split("#", 1)[0].strip()
    )
    el = raw["eligibility"]
    return Config(
        version=hashlib.sha256(raw_bytes).hexdigest()[:12],
        raw=raw,
        ubiquitous=ubiq,
        panel=re.compile(raw["facts"]["panel_title"], re.I),
        parked=re.compile(el["parked_title"], re.I),
        residential=re.compile(el["residential_org"], re.I),
        vendor_o=re.compile(el["vendor_cert_o"], re.I),
    )


# ---------------------------------------------------------------- findings

@dataclass
class Finding:
    kind: str  # exposed_service, software, eol_os, cert_expired, ... , marker_*, fact_*
    family: str  # exposure, software, neglect, why_now, fact
    points: int
    sentence: str
    ip: str | None = None
    port: int | None = None
    module: str | None = None
    product: str | None = None
    version: str | None = None
    cves: list[dict] = field(default_factory=list)
    attribution: str | None = None
    source: str | None = None
    observed_at: str | None = None


def _date(ts: str | None) -> str:
    return (ts or "")[:10] or "unknown date"


def _parse_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts[:26]).replace(tzinfo=UTC)
    except ValueError:
        return None


def _parse_cert(ts: str | None) -> datetime | None:
    try:
        return datetime.strptime(ts[:14], "%Y%m%d%H%M%S").replace(tzinfo=UTC) if ts else None
    except ValueError:
        return None


def cert_state(r: dict, expiring_days: int) -> str | None:
    """Exactly one of 'expired' / 'expiring' / 'ok' per certificate (D38); None without a cert."""
    if not r.get("has_ssl") or (r.get("cert_expires") is None and not r.get("cert_expired")):
        return None
    expires, seen = _parse_cert(r.get("cert_expires")), _parse_ts(r.get("timestamp"))
    if r.get("cert_expired") or (expires and seen and expires < seen):
        return "expired"
    if expires and seen and (expires - seen).days <= expiring_days:
        return "expiring"
    return "ok"


def _where(r: dict) -> str:
    return f"{r['ip']}:{r['port']}"


def _cve_entry(v: dict, verified: set[str]) -> dict:
    return {
        "cve": v["cve"], "cvss": v["cvss"], "epss": v["epss"], "kev": v["kev"],
        "ransomware": v["ransomware"], "verified": v["verified"] or v["cve"] in verified,
    }


def software_award(vulns: list[dict], verified: set[str], cfg: Config) -> tuple[int, str, list[dict]]:
    """At most one CVE award per product+version: KEV (25) or likely-exploitable (15) (D25)."""
    p, th = cfg.pts, cfg.raw["thresholds"]
    usable = [v for v in vulns if v["cve"] not in cfg.ubiquitous]
    kev = sorted((v for v in usable if v["kev"]), key=lambda v: (-(v["epss"] or 0), v["cve"]))
    if kev:
        return p["cve_kev"], "kev", [_cve_entry(v, verified) for v in kev[:3]]
    likely = sorted(
        (v for v in usable if (v["epss"] or 0) >= th["likely_epss"] and (v["cvss"] or 0) >= th["likely_cvss"]),
        key=lambda v: (-(v["epss"] or 0), -(v["cvss"] or 0), v["cve"]),
    )
    if likely:
        return p["cve_likely"], "likely", [_cve_entry(v, verified) for v in likely[:3]]
    return 0, "", []


def _cve_text(c: dict) -> tuple[str, str]:
    word = "verified" if c["verified"] else "potential"
    bits = [c["cve"]]
    if c["cvss"] is not None:
        bits.append(f"CVSS {c['cvss']:g}")
    if c["epss"] is not None:
        bits.append(f"EPSS {c['epss']:.2f}")
    return word, ", ".join(bits)


def account_findings(domain: str, records: list[dict], cfg: Config) -> list[Finding]:
    p, th = cfg.pts, cfg.raw["thresholds"]
    modules = cfg.raw["exposure_modules"]
    out: list[Finding] = []
    first: dict[str, Finding] = {}

    def once(kind: str, f: Finding) -> None:
        if kind not in first:
            first[kind] = f

    software: dict[tuple, list[dict]] = defaultdict(list)
    for r in records:
        if r["infra_class"] == "cdn":
            edge = r["org"] or "a CDN"
            once("fact_behind_cdn", Finding("fact_behind_cdn", "fact", 0, f"Website served through {edge} (CDN / WAF edge).",
                                            ip=r["ip"], port=r["port"], attribution=r["attribution"], source=r["source"],
                                            observed_at=r["timestamp"]))
            continue  # edge banners describe the CDN, never the customer (D24)
        base = dict(ip=r["ip"], port=r["port"], module=r["module"], attribution=r["attribution"],
                    source=r["source"], observed_at=r["timestamp"])
        if r["module"] in modules:
            label = modules[r["module"]]
            out.append(Finding("exposed_service", "exposure", 0,
                               f"Exposed {label} on {_where(r)} (detected by Shodan module {r['module']}), observed on {_date(r['timestamp'])}.",
                               product=r["product"], version=r["version"], **base))
        if r["vulns"] or "eol-product" in r["tags"]:
            software[(r["product"], r["version"])].append(r)
        if "eol-os" in r["tags"]:
            once("eol_os", Finding("eol_os", "software", p["eol_os"],
                                   f"End-of-life operating system reported on {_where(r)}, observed on {_date(r['timestamp'])}.", **base))
        state = cert_state(r, th["cert_expiring_days"])
        if state == "expired":
            once("cert_expired", Finding("cert_expired", "neglect", p["cert_expired"],
                                         f"Expired TLS certificate on {_where(r)} (expiry {_date(_cert_iso(r))}), observed on {_date(r['timestamp'])}.", **base))
        elif state == "expiring":
            once("marker_cert_expiring", Finding("marker_cert_expiring", "why_now", 0,
                                                 f"TLS certificate on {_where(r)} expires on {_date(_cert_iso(r))}, within {th['cert_expiring_days']} days of the scan.", **base))
        dep = sorted(set(r["ssl_versions"]) & set(cfg.raw["neglect"]["deprecated_tls"]))
        if dep:
            once("deprecated_tls", Finding("deprecated_tls", "neglect", p["deprecated_tls"],
                                           f"Deprecated TLS ({', '.join(dep)}) accepted on {_where(r)}, observed on {_date(r['timestamp'])}.", **base))
        if r["cert_self_signed"] and r["source"] == "cert_cn":
            once("self_signed_public", Finding("self_signed_public", "neglect", p["self_signed_public"],
                                               f"Self-signed certificate for a public name ({r['cert_cn']}) on {_where(r)}.", **base))
        if r["http_server"] and _VERSION_IN_SERVER.search(r["http_server"]):
            once("version_disclosed", Finding("version_disclosed", "neglect", p["version_disclosed"],
                                              f"Server version disclosed in HTTP headers ({r['http_server']}) on {_where(r)}.", **base))
        if r["has_ssl"] and r["has_http"] and not r["has_hsts"]:
            once("no_hsts", Finding("no_hsts", "neglect", p["no_hsts"], f"HTTPS without HSTS on {_where(r)}.", **base))
        if r["appliance"]:
            once(f"fact_appliance_{r['appliance']}", Finding(f"fact_appliance_{r['appliance']}", "fact", 0,
                                                             f"{r['appliance'].capitalize()} appliance exposed on {_where(r)}.", **base))
        if r["http_title"] and cfg.panel.search(r["http_title"]):
            once("fact_panel", Finding("fact_panel", "fact", 0, f"Login or admin page exposed on {_where(r)}.", **base))
        for v in r["vulns"]:
            if v["cve"] in cfg.ubiquitous:
                continue
            if v["kev"]:
                once("marker_kev", Finding("marker_kev", "why_now", 0,
                                           f"Potential match to a known-exploited CVE ({v['cve']}) on {_where(r)}, observed on {_date(r['timestamp'])}.", **base))
            if v["cve"].startswith("CVE-2026-"):
                once("marker_cve_2026", Finding("marker_cve_2026", "why_now", 0,
                                                f"Potential match to a CVE published in 2026 ({v['cve']}) on {_where(r)}.", **base))

    # One exposure award per account; the remaining exposed services are listed at 0 points.
    exposures = sorted((f for f in out if f.kind == "exposed_service"), key=lambda f: (f.ip, f.port or 0))
    for i, f in enumerate(exposures):
        f.points = p["exposed_service"] if i == 0 else 0

    # Software: one CVE award + EOL per product+version, capped per product (D25).
    sw: list[Finding] = []
    for (product, version), recs in sorted(software.items(), key=lambda kv: (str(kv[0][0]), str(kv[0][1]))):
        verified = {c for r in recs for c in r["opts_vulns"]}
        vulns = {v["cve"]: v for r in recs for v in r["vulns"]}.values()
        pts, how, cves = software_award(list(vulns), verified, cfg)
        eol = any("eol-product" in r["tags"] for r in recs)
        r0 = recs[0]
        name = " ".join(x for x in (product, version) if x) or "Unidentified software"
        parts = []
        if how:
            word, txt = _cve_text(cves[0])
            what = "a known-exploited CVE" if how == "kev" else "a high-severity CVE likely to be exploited"
            if how == "kev" and cves[0]["ransomware"] == "Known":
                what += " used in ransomware campaigns"  # stated, not scored (D25)
            parts.append(f"{word} match to {what} ({txt})")
        if eol:
            pts += p["eol_product"]
            parts.append("end-of-life")
        if not parts:
            continue
        sw.append(Finding("software", "software", min(pts, p["per_product_cap"]),
                          f"{name} on {_where(r0)}: " + "; ".join(parts) + f", observed on {_date(r0['timestamp'])}.",
                          ip=r0["ip"], port=r0["port"], module=r0["module"], product=product, version=version, cves=cves,
                          attribution=r0["attribution"], source=r0["source"], observed_at=r0["timestamp"]))
    out = [f for f in out if f.kind != "exposed_service"] + exposures + sw + list(first.values())

    # Account caps: software family (incl. EOL OS) <= 40, neglect <= 10 (D25). Trim lowest first.
    for family, cap in (("software", p["software_cap"]), ("neglect", p["neglect_cap"])):
        budget = cap
        for f in sorted((f for f in out if f.family == family), key=lambda f: (-f.points, f.sentence)):
            f.points = min(f.points, max(budget, 0))
            budget -= f.points
    return out


def _cert_iso(r: dict) -> str | None:
    d = _parse_cert(r.get("cert_expires"))
    return d.isoformat() if d else None


# ---------------------------------------------------------------- eligibility (D34)

_NUMBERED = re.compile(r"\d{3,}")


def numbered_share(domain: str, records: list[dict]) -> float:
    """Share of the account's own hostnames whose first label carries a 3+ digit run."""
    hosts = set()
    for r in records:
        for h in (r["scan_hostname"], r["cert_cn"], r["http_host"], *r["hostnames"]):
            if h and (h == domain or h.endswith("." + domain)):
                hosts.add(h.lower())
    if not hosts:
        return 0.0
    return sum(1 for h in hosts if _NUMBERED.search(h.split(".", 1)[0])) / len(hosts)


def _label_letters(domain: str) -> str:
    return re.sub(r"[^a-z]", "", domain.split(".")[0])


def eligibility(domain: str, records: list[dict], cfg: Config) -> tuple[str, str]:
    el = cfg.raw["eligibility"]
    if any(domain == s or domain.endswith("." + s) for s in el["dynamic_dns"]):
        return "likely_non_prospect", "dynamic DNS name"
    titles = [r["http_title"] for r in records if r["http_title"]]
    if titles and all(cfg.parked.search(t) for t in titles):
        return "likely_non_prospect", "parked domain"
    sources = {r["source"] for r in records if r["attribution"] == "direct"}
    orgs = {(r["org"] or "") for r in records}
    label = _label_letters(domain)
    org_matches = len(label) >= 4 and any(label in re.sub(r"[^a-z]", "", o.lower()) for o in orgs)
    ips = {r["ip"] for r in records}
    if len(ips) >= el["hoster_min_ips"] and numbered_share(domain, records) >= el["hoster_numbered_share"]:
        return "likely_non_prospect", "hosting provider's customer servers"
    if sources == {"ptr"} and not org_matches:
        if len(ips) >= el["ptr_zone_min_ips"]:
            return "likely_non_prospect", "reverse-DNS zone of an ISP or hoster"
        if any(cfg.residential.search(o) for o in orgs):
            return "likely_non_prospect", "residential or consumer connection"
    if any(domain.endswith("." + t) for t in el["institutional_tld"]):
        return "likely_org", "institutional domain"
    if org_matches:
        return "likely_org", "operates its own network"
    if any(r["cert_o"] and not cfg.vendor_o.search(r["cert_o"]) for r in records):
        return "likely_org", "organisation named in its certificate"
    if "scan_hostname" in sources:
        return "likely_org", "public web property"
    return "uncertain", ""


# ---------------------------------------------------------------- build

def _domain_groups(con: duckdb.DuckDBPyConnection):
    """Yield (domain, records) one account at a time; memory stays at one account's rows."""
    cur = con.execute(f"SELECT {', '.join(COLUMNS)} FROM attributed WHERE domain IS NOT NULL "
        # Total order: which record supplies a finding's evidence must not depend on sort ties.
        "ORDER BY domain, ip, port, transport, module, timestamp, shodan_id, banner_hash")
    domain, group = None, []
    while batch := cur.fetchmany(50_000):
        for row in batch:
            r = dict(zip(COLUMNS, row))
            for k in ("tags", "vulns", "opts_vulns", "ssl_versions", "hostnames"):
                r[k] = r[k] or []
            if r["domain"] != domain and group:
                yield domain, group
                group = []
            domain = r["domain"]
            group.append(r)
    if group:
        yield domain, group


COLUMNS = ["domain", "attribution", "source", "ip", "port", "module", "timestamp", "infra_class", "org", "tags",
           "product", "version", "vulns", "opts_vulns", "has_ssl", "cert_expired", "cert_expires", "cert_self_signed",
           "cert_cn", "cert_o", "ssl_versions", "has_http", "has_hsts", "http_server", "http_title", "appliance",
           "has_docker", "scan_hostname", "http_host", "hostnames"]


def score(features: Path, out: Path, cfg: Config | None = None) -> dict:
    started = time.monotonic()
    cfg = cfg or load_config()
    fmanifest = orjson.loads((features / "manifest.json").read_bytes())
    con = duckdb.connect()
    con.execute("SET enable_progress_bar = false")
    attribute(con, features)
    funnel = con.execute(
        "SELECT attribution, coalesce(infra_class, 'customer_or_isp'), count(*) FROM attributed GROUP BY ALL ORDER BY ALL"
    ).fetchall()

    t1, t2 = cfg.raw["tiers"]["tier1"], cfg.raw["tiers"]["tier2"]
    accounts, findings = [], []
    for domain, recs in _domain_groups(con):
        fs = account_findings(domain, recs, cfg)
        total = sum(f.points for f in fs)
        scored = [f for f in fs if f.points > 0]
        label = max((LABEL[r["source"]] for r in recs if r["attribution"] != "unresolved"), key=LABEL_RANK.get)
        elig, why = eligibility(domain, recs, cfg)
        accounts.append({
            "domain": domain,
            "score": total,
            "tier": 1 if total >= t1 else 2 if total >= t2 else 3 if total > 0 else 0,
            "n_findings": len(scored),
            "exposure_points": sum(f.points for f in fs if f.family == "exposure"),
            "software_points": sum(f.points for f in fs if f.family == "software"),
            "neglect_points": sum(f.points for f in fs if f.family == "neglect"),
            "reasons": [f.sentence for f in sorted(scored, key=lambda f: (-f.points, f.sentence))[:3]],
            "why_now": sorted({f.kind.removeprefix("marker_") for f in fs if f.family == "why_now"}),
            "facts": sorted({f.kind.removeprefix("fact_").split("_")[0] for f in fs if f.family == "fact"}),
            "appliances": sorted({f.kind.removeprefix("fact_appliance_") for f in fs if f.kind.startswith("fact_appliance_")}),
            "attribution_label": label,
            "eligibility": elig,
            "eligibility_reason": why,
            "n_ips": len({r["ip"] for r in recs}),
            "n_records": len(recs),
        })
        for f in fs:
            findings.append({"domain": domain, **f.__dict__, "cves": orjson.dumps(f.cves).decode()})

    # Deterministic order (signals-scoring.md section 2): score desc, findings desc, domain asc.
    accounts.sort(key=lambda a: (-a["score"], -a["n_findings"], a["domain"]))
    for i, a in enumerate(accounts, 1):
        a["rank"] = i

    manifest = {
        "kind": "artifact",
        "scorer_version": SCORER_VERSION,
        "scoring_config_version": cfg.version,
        "ubiquitous_cves": str(len(cfg.ubiquitous)),
        "code_commit": code_commit(),
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "input_file": fmanifest["input_file"],
        "input_sha256": fmanifest["input_sha256"],
        "extractor_version": fmanifest["extractor_version"],
        "blocklist_version": fmanifest["blocklist_version"],
        "psl_version": fmanifest["psl_version"],
        "snapshot_from": con.execute("SELECT min(timestamp) FROM feat").fetchone()[0] or "",
        "snapshot_to": con.execute("SELECT max(timestamp) FROM feat").fetchone()[0] or "",
        "accounts": str(len(accounts)),
        "findings": str(len(findings)),
    }
    write_artifact(out, manifest, accounts, findings, funnel)
    manifest["seconds_total"] = round(time.monotonic() - started, 1)
    manifest["output_bytes"] = out.stat().st_size
    return manifest


def write_artifact(out: Path, manifest: dict, accounts: list[dict], findings: list[dict], funnel: list[tuple]) -> None:
    with atomic_file(out) as tmp:
        tmp.unlink(missing_ok=True)
        con = duckdb.connect(str(tmp))
        con.execute("CREATE TABLE manifest (key VARCHAR, value VARCHAR)")
        con.executemany("INSERT INTO manifest VALUES (?, ?)", [(k, str(v)) for k, v in manifest.items()])
        con.execute("CREATE TABLE funnel (attribution VARCHAR, infra_class VARCHAR, records BIGINT)")
        con.executemany("INSERT INTO funnel VALUES (?, ?, ?)", funnel)
        acc = pa.Table.from_pylist(accounts)  # noqa: F841 (referenced by DuckDB)
        fin = pa.Table.from_pylist(findings)  # noqa: F841
        con.execute("CREATE TABLE accounts AS SELECT * FROM acc ORDER BY rank")
        con.execute("CREATE TABLE findings AS SELECT * FROM fin ORDER BY domain, points DESC, kind")
        con.close()


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("features", type=Path, help="features/<sha256> partition")
    ap.add_argument("--out", type=Path, required=True, help="artifact path (.duckdb, gitignored)")
    args = ap.parse_args(argv)
    m = score(args.features, args.out)
    print(orjson.dumps(m, option=orjson.OPT_INDENT_2).decode())


if __name__ == "__main__":
    sys.exit(main())
