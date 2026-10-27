"""Domain-complete dev sample (signals-scoring.md section 1, D8, D43).

1. Build the full IP -> candidate-domain index from the full file's feature partition.
2. Keep a domain when blake2b(domain, 8 bytes) % modulus == 0 (stable across runs and machines).
3. Stream the raw file once; write every record of an IP on which a kept domain appears,
   without http.html and raw data, carrying the IP's full candidate-domain count as
   `_sample.ip_domain_count` so shared IPs stay shared in the sample.

    salesintel-sample dataset.json.zst --features out/full/features/<sha256> \\
        --out data/sample/domain_sample.jsonl.zst
"""

import argparse
import hashlib
import re
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import duckdb
import orjson
import zstandard

from salesintel.pipeline.atomic import atomic_file, code_commit, file_sha256, write_json
from salesintel.pipeline.extract import iter_batches

_IP_STR = re.compile(rb'"ip_str"\s*:\s*"([^"]{1,64})"')
_IPV6 = re.compile(rb'"ipv6"\s*:\s*"([^"]{1,64})"')


def keep_domain(domain: str, modulus: int) -> bool:
    digest = hashlib.blake2b(domain.encode(), digest_size=8).digest()
    return int.from_bytes(digest, "big") % modulus == 0


def sampled_ips(features: Path, modulus: int) -> tuple[dict[str, int], dict]:
    """IP -> full candidate-domain count, for IPs on which a sampled domain appears."""
    con = duckdb.connect()
    con.execute(
        f"""
        CREATE TABLE pairs AS
        SELECT DISTINCT ip, n.domain AS domain
        FROM read_parquet('{features}/part-*.parquet'), unnest(names) AS t(n)
        """
    )
    con.execute("CREATE TABLE ip_counts AS SELECT ip, count(*) AS n FROM pairs GROUP BY ip")
    domains = [d for (d,) in con.execute("SELECT DISTINCT domain FROM pairs").fetchall()]
    kept = [d for d in domains if keep_domain(d, modulus)]
    con.execute("CREATE TABLE kept (domain VARCHAR)")
    con.executemany("INSERT INTO kept VALUES (?)", [(d,) for d in kept])
    rows = con.execute(
        """
        SELECT c.ip, c.n FROM ip_counts c
        WHERE c.ip IN (SELECT p.ip FROM pairs p JOIN kept k USING (domain))
        """
    ).fetchall()
    stats = {
        "index_ips": con.execute("SELECT count(*) FROM ip_counts").fetchone()[0],
        "index_domains": len(domains),
        "sampled_domains": len(kept),
        "sampled_ips": len(rows),
        "sampled_ips_shared": sum(1 for _, n in rows if n > 1),
    }
    return dict(rows), stats


def _record_ip(line: bytes) -> str | None:
    m = _IP_STR.search(line) or _IPV6.search(line)
    return m.group(1).decode(errors="replace") if m else None


def build(raw: Path, features: Path, out: Path, modulus: int) -> dict:
    started = time.monotonic()
    fmanifest = orjson.loads((features / "manifest.json").read_bytes())
    raw_hash = file_sha256(raw)
    if raw_hash != fmanifest["input_sha256"]:
        raise SystemExit("raw file does not match the feature partition's input_sha256")

    ips, stats = sampled_ips(features, modulus)
    counts: Counter = Counter()
    with atomic_file(out) as tmp, open(tmp, "wb") as fh:
        with zstandard.ZstdCompressor(level=10).stream_writer(fh) as zw:
            for batch in iter_batches(raw, 10_000):
                for line in batch:
                    counts["records"] += 1
                    ip = _record_ip(line)
                    if ip is None:
                        counts["no_ip_match"] += 1
                        continue
                    if ip not in ips:
                        continue
                    try:
                        rec = orjson.loads(line)
                    except orjson.JSONDecodeError:
                        counts["parse_error"] += 1
                        continue
                    rec.pop("data", None)
                    if isinstance(rec.get("http"), dict):
                        rec["http"].pop("html", None)
                    rec["_sample"] = {"ip_domain_count": ips[ip], "modulus": modulus, "hash": "blake2b-8"}
                    zw.write(orjson.dumps(rec) + b"\n")
                    counts["written"] += 1
    manifest = {
        "kind": "domain_sample",
        "input_file": raw.name,
        "input_sha256": raw_hash,
        "features_manifest": {k: fmanifest[k] for k in ("input_sha256", "extractor_version", "blocklist_version", "psl_version")},
        "modulus": modulus,
        "hash": "blake2b, digest_size=8, big-endian int % modulus == 0",
        "code_commit": code_commit(),
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        **stats,
        "counts": dict(sorted(counts.items())),
        "output_bytes": out.stat().st_size,
        "seconds_total": round(time.monotonic() - started, 1),
    }
    write_json(out.with_name(out.name + ".manifest.json"), manifest)
    return manifest


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("raw", type=Path, help="the full banner file the features were built from")
    ap.add_argument("--features", type=Path, required=True, help="features/<sha256> partition of that file")
    ap.add_argument("--out", type=Path, required=True, help="output .jsonl.zst")
    ap.add_argument("--modulus", type=int, default=20)
    args = ap.parse_args(argv)
    m = build(args.raw, args.features, args.out, args.modulus)
    print(orjson.dumps({k: v for k, v in m.items() if k != "features_manifest"}, option=orjson.OPT_INDENT_2).decode())


if __name__ == "__main__":
    sys.exit(main())
