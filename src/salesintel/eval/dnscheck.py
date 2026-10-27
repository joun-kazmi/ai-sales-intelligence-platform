"""C1: forward-DNS match rate of record -> domain links (signals-scoring.md section 4, D39).

For a seeded sample of links per attribution source, resolve the hostname that produced the link
and the account domain; a link "matches" if either resolves to the record's IP today. A match
supports the link but does not prove ownership; a miss does not disprove it (re-assigned cloud
IPs). Writes c1_result.json and misses.csv (~30 misses to hand-check). Run where DNS is reachable.

    salesintel-dnscheck out/full/features/<sha256> --out out/full/c1
"""

import argparse
import csv
import ipaddress
import json
import random
import socket
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable

import duckdb

from salesintel.pipeline.atomic import code_commit, write_json
from salesintel.pipeline.attribute import attribute

SEED = 20261028
LABEL = {"scan_hostname": "High", "cert_cn": "High", "http_host": "Medium", "ptr": "Medium", "via_ip": "Low"}

Resolver = Callable[[str], set[str]]


def system_resolver(name: str) -> set[str]:
    try:
        infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return set()
    return {str(ipaddress.ip_address(i[4][0].split("%")[0])) for i in infos}


def links(con: duckdb.DuckDBPyConnection, per_source: int, seed: int) -> list[dict]:
    rows = con.execute(
        """
        SELECT DISTINCT domain, ip, coalesce(source, 'via_ip') AS source,
               CASE source WHEN 'scan_hostname' THEN scan_hostname WHEN 'cert_cn' THEN cert_cn
                           WHEN 'http_host' THEN http_host
                           WHEN 'ptr' THEN list_filter(hostnames, lambda h: lower(h) = domain OR ends_with(lower(h), '.' || domain))[1]
               END AS host
        FROM attributed WHERE attribution != 'unresolved'
        ORDER BY source, domain, ip
        """).fetchall()
    by_source: dict[str, list[dict]] = defaultdict(list)
    for d, ip, src, host in rows:
        by_source[src].append({"domain": d, "ip": ip, "source": src, "host": (host or d).lower().split(":")[0]})
    rng = random.Random(seed)
    out = []
    for src in sorted(by_source):
        pool = by_source[src]
        out.extend(rng.sample(pool, min(per_source, len(pool))))
    return out


def check(sample: list[dict], resolver: Resolver, threads: int = 32) -> list[dict]:
    names = sorted({x["host"] for x in sample} | {x["domain"] for x in sample})
    with ThreadPoolExecutor(max_workers=threads) as pool:
        answers = dict(zip(names, pool.map(resolver, names)))
    for x in sample:
        ip = str(ipaddress.ip_address(x["ip"]))
        got = answers[x["host"]] | answers[x["domain"]]
        x["resolved"] = bool(got)
        x["matched"] = ip in got
        x["resolved_ips"] = sorted(got)[:5]
    return sample


def summarize(results: list[dict]) -> dict:
    groups: dict[str, list[dict]] = defaultdict(list)
    for x in results:
        groups[f"source:{x['source']}"].append(x)
        groups[f"label:{LABEL[x['source']]}"].append(x)
    out = {}
    for g, xs in sorted(groups.items()):
        n, res, mat = len(xs), sum(x["resolved"] for x in xs), sum(x["matched"] for x in xs)
        out[g] = {"links": n, "resolved": res, "matched": mat,
                  "match_rate": round(mat / n, 3) if n else None,
                  "match_rate_of_resolved": round(mat / res, 3) if res else None}
    return out


def run(features: Path, out: Path, per_source: int = 300, seed: int = SEED, resolver: Resolver = system_resolver,
        misses: int = 30) -> dict:
    con = duckdb.connect()
    con.execute("SET enable_progress_bar = false")
    attribute(con, features)
    results = check(links(con, per_source, seed), resolver)
    out.mkdir(parents=True, exist_ok=True)
    missed = [x for x in results if not x["matched"]]
    picked = random.Random(seed + 1).sample(missed, min(misses, len(missed)))
    with open(out / "misses.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["domain", "host", "ip", "source", "resolved_ips", "verdict", "notes"])
        for x in picked:
            w.writerow([x["domain"], x["host"], x["ip"], x["source"], " ".join(x["resolved_ips"]), "", ""])
    result = {
        "kind": "c1_dns_match_rate", "metric": "forward DNS match rate (not ownership)",
        "per_source_sample": per_source, "seed": seed, "links": len(results),
        "groups": summarize(results), "misses_for_hand_check": len(picked),
        "code_commit": code_commit(), "checked_at": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    write_json(out / "c1_result.json", result)
    return result


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("features", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--per-source", type=int, default=300)
    args = ap.parse_args(argv)
    print(json.dumps(run(args.features, args.out, args.per_source), indent=2))


if __name__ == "__main__":
    sys.exit(main())
