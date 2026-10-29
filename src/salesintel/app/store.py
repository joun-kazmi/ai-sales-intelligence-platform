"""Read-only queries over the artifact for the UI (docs/design/ui.md).

Filter values are checked against fixed lists; every value reaches SQL as a parameter, never as
formatted text. One read-only DuckDB connection; a cursor per request.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

import duckdb

PAGE_SIZE = 50
# Render free tier has 512 MB; DuckDB would otherwise size its memory limit and threads from the
# host, not the container (measured: 325 MB RSS after full-artifact CSV exports).
DUCKDB_CONFIG = {"memory_limit": "256MiB", "threads": 2}

# Plays (use-cases.md UC3): title, buyer role, account filter.
PLAYS = {
    "exposed": ("Exposed remote access / database / ICS",
                "Head of IT / infrastructure manager; CISO where one exists",
                "domain IN (SELECT domain FROM findings WHERE kind = 'exposed_service')"),
    "exploited": ("Potential known-exploited CVEs",
                  "Vulnerability management / security operations lead",
                  """domain IN (SELECT domain FROM findings WHERE kind = 'software' AND cves LIKE '%"kev":true%')"""),
    # Known MVP shortcut: the artifact has no separate EOL flag for products, so match the sentence
    # (ui.md); an end-of-life OS is its own finding kind (D63).
    "eol": ("End-of-life software", "IT operations manager (upgrade and lifecycle owner)",
            "domain IN (SELECT domain FROM findings WHERE kind = 'eol_os' "
            "OR (kind = 'software' AND sentence LIKE '%end-of-life%'))"),
    "certs": ("Expired or soon-expiring certificates", "Web / platform owner or IT operations",
              "domain IN (SELECT domain FROM findings WHERE kind IN ('cert_expired', 'marker_cert_expiring'))"),
    "appliances": ("Edge appliances (Fortinet, SonicWall, Citrix, ...)",
                   "Network security lead / CISO (attack surface; existing spend)",
                   "len(appliances) > 0"),
}
TIERS = {"1": ("tier = 1", []), "2": ("tier = 2", []), "3": ("tier = 3", []), "ranked": ("tier > 0", []), "all": (None, [])}
WHY_NOW = {"any": "len(why_now) > 0", "kev": "list_contains(why_now, 'kev')",
           "cve_2026": "list_contains(why_now, 'cve_2026')", "cert_expiring": "list_contains(why_now, 'cert_expiring')"}
GEAR = {"appliance": "len(appliances) > 0", "cdn": "list_contains(facts, 'behind')",
        "none": "len(appliances) = 0 AND NOT list_contains(facts, 'behind')"}
ELIGIBILITY = {"default": "eligibility != 'likely_non_prospect'", "likely_org": "eligibility = 'likely_org'", "all": None}
WHY_NOW_TEXT = {"kev": "known-exploited CVE", "cve_2026": "CVE published in 2026", "cert_expiring": "cert expiring"}

# Short labels for the list view; the full sentence stays in the title attribute and detail page.
MODULE_SHORT = {"rdp": "RDP", "rdpeudp": "RDP", "smb": "SMB", "telnet": "Telnet", "vnc": "VNC", "mysql": "MySQL",
                "ms-sql": "MS SQL", "postgresql": "PostgreSQL", "mongodb": "MongoDB", "redis": "Redis",
                "memcache": "Memcached", "couchdb": "CouchDB", "oracle-tns": "Oracle DB", "elastic": "Elasticsearch",
                "docker": "Docker API", "modbus": "Modbus", "s7": "Siemens S7", "dnp3": "DNP3",
                "ethernetip": "EtherNet/IP", "bacnet": "BACnet", "fox": "Niagara Fox"}
KIND_SHORT = {"eol_os": "EOL OS", "cert_expired": "expired cert", "deprecated_tls": "old TLS",
              "self_signed_public": "self-signed cert", "version_disclosed": "version leak", "no_hsts": "no HSTS"}


def short_tag(kind: str, module: str | None, product: str | None, version: str | None, cves: str | None,
              sentence: str) -> str:
    if kind == "exposed_service":
        return f"{MODULE_SHORT.get(module or '', module or 'service')} exposed"
    if kind == "software":
        name = " ".join(x for x in (product, version) if x) or "software"
        marks = (["KEV"] if cves and '"kev":true' in cves else []) + (["EOL"] if "end-of-life" in sentence else [])
        return " · ".join([name[:32], *marks])
    return KIND_SHORT.get(kind, kind.replace("_", " "))


LIST_COLUMNS = ["rank", "domain", "score", "tier", "reasons", "why_now", "attribution_label", "eligibility",
                "eligibility_reason", "n_ips"]


class BadFilter(ValueError):
    pass


@dataclass(frozen=True)
class Filters:
    tier: str = "ranked"
    play: str | None = None
    why_now: str | None = None
    gear: str | None = None
    eligibility: str = "default"

    @classmethod
    def parse(cls, q: dict[str, str]) -> "Filters":
        def pick(name: str, allowed: dict, default):
            v = q.get(name) or default
            if v is not None and v not in allowed:
                raise BadFilter(f"unknown {name}: {v[:40]}")
            return v
        f = cls(tier=pick("tier", TIERS, None), play=pick("play", PLAYS, None),
                why_now=pick("why_now", WHY_NOW, None), gear=pick("gear", GEAR, None),
                eligibility=pick("eligibility", ELIGIBILITY, "default"))
        # A play includes unranked accounts (e.g. an appliance with no scored finding) unless asked.
        return cls(f.tier or ("all" if f.play else "ranked"), f.play, f.why_now, f.gear, f.eligibility)

    def where(self) -> str:
        parts = [TIERS[self.tier][0], ELIGIBILITY[self.eligibility]]
        if self.play:
            parts.append(PLAYS[self.play][2])
        if self.why_now:
            parts.append(WHY_NOW[self.why_now])
        if self.gear:
            parts.append(GEAR[self.gear])
        parts = [p for p in parts if p]
        return ("WHERE " + " AND ".join(f"({p})" for p in parts)) if parts else ""

    def query(self, **extra) -> dict[str, str]:
        q = {"tier": self.tier, "play": self.play, "why_now": self.why_now, "gear": self.gear,
             "eligibility": self.eligibility, **extra}
        return {k: str(v) for k, v in q.items() if v not in (None, "")}


@dataclass
class Store:
    path: Path
    con: duckdb.DuckDBPyConnection = field(init=False)

    def __post_init__(self) -> None:
        self.con = duckdb.connect(str(self.path), read_only=True, config=DUCKDB_CONFIG)

    def _cur(self) -> duckdb.DuckDBPyConnection:
        return self.con.cursor()

    def manifest(self) -> dict[str, str]:
        return dict(self._cur().execute("SELECT key, value FROM manifest").fetchall())

    def count(self, f: Filters) -> int:
        return self._cur().execute(f"SELECT count(*) FROM accounts {f.where()}").fetchone()[0]

    def page(self, f: Filters, page: int) -> list[dict]:
        rows = self._cur().execute(
            f"SELECT {', '.join(LIST_COLUMNS)} FROM accounts {f.where()} ORDER BY rank LIMIT ? OFFSET ?",
            [PAGE_SIZE, (page - 1) * PAGE_SIZE]).fetchall()
        return [dict(zip(LIST_COLUMNS, r)) for r in rows]

    def iter_all(self, f: Filters):
        cur = self._cur().execute(f"SELECT {', '.join(LIST_COLUMNS)} FROM accounts {f.where()} ORDER BY rank")
        while batch := cur.fetchmany(5000):
            for r in batch:
                yield dict(zip(LIST_COLUMNS, r))

    def account(self, domain: str) -> tuple[dict | None, list[dict]]:
        cur = self._cur()
        cols = [d[0] for d in cur.execute("SELECT * FROM accounts LIMIT 0").description]
        row = cur.execute("SELECT * FROM accounts WHERE domain = ?", [domain]).fetchone()
        if row is None:
            return None, []
        fcols = ["kind", "family", "points", "sentence", "ip", "port", "module", "product", "version", "cves",
                 "attribution", "source", "observed_at"]
        findings = [dict(zip(fcols, r)) for r in cur.execute(
            f"SELECT {', '.join(fcols)} FROM findings WHERE domain = ? ORDER BY points DESC, family, kind, sentence",
            [domain]).fetchall()]
        for x in findings:
            x["cves"] = json.loads(x["cves"] or "[]")
        return dict(zip(cols, row)), findings

    def tags(self, domains: list[str]) -> dict[str, list[dict]]:
        """Scored findings of the given accounts as short tags (family, label, full sentence)."""
        if not domains:
            return {}
        rows = self._cur().execute(
            """SELECT domain, family, kind, module, product, version, cves, sentence FROM findings
               WHERE points > 0 AND domain IN (SELECT unnest(?)) ORDER BY domain, points DESC, kind, sentence""",
            [domains]).fetchall()
        out: dict[str, list[dict]] = {}
        for d, family, kind, module, product, version, cves, sentence in rows:
            out.setdefault(d, []).append({"family": family, "sentence": sentence,
                                          "label": short_tag(kind, module, product, version, cves, sentence)})
        return out

    def summary(self) -> dict[str, int]:
        """Header strip: tier counts in the default view (likely non-prospects hidden)."""
        return {"tier1": self.count(Filters(tier="1")), "tier2": self.count(Filters(tier="2")),
                "ranked": self.count(Filters(tier="ranked"))}

    def play_counts(self) -> dict[str, int]:
        return {k: self.count(Filters(tier="all", play=k)) for k in PLAYS}
