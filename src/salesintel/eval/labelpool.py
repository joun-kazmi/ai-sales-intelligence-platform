"""C2: blind human labelling of our ranking vs "highest CVSS first" vs random (D28, D37).

build:    pool = our top k + top k by highest CVSS + k random, all from the same eligible set
          (default view: likely non-prospects hidden), deduplicated, shuffled. The label sheet shows
          the same neutral evidence for every account (from the feature layer, not our findings),
          and nothing about score, tier, rank or which list it came from. The key is a separate file.
ai-label: a second rater (Claude) labels the same sheet into ai_labels.csv (D57).
evaluate: precision@k per list from the human or AI sheet, plus human-vs-AI agreement.

    salesintel-labelpool build out/full/artifact.duckdb out/full/features/<sha256> --out out/full/c2
    salesintel-labelpool ai-label out/full/c2
    salesintel-labelpool evaluate out/full/c2 [--rater human|ai]
"""

import argparse
import csv
import json
import math
import random
import sys
from datetime import UTC, datetime
from pathlib import Path

import duckdb

from salesintel.pipeline.atomic import code_commit, write_json
from salesintel.pipeline.attribute import attribute
from salesintel.pipeline.score import cert_state

SEED = 20261028
LABEL_COLUMNS = ["real_org", "own_asset", "credible_opener", "worth_a_call", "notes"]
SOURCE_TEXT = {"scan_hostname": "scanned by name", "cert_cn": "TLS certificate name",
               "http_host": "HTTP host name", "ptr": "reverse DNS name", None: "same IP as a named record"}
MAX_EVIDENCE_LINES = 12


def _pools(con: duckdb.DuckDBPyConnection, k: int, seed: int) -> dict[str, list[str]]:
    eligible = [d for (d,) in con.execute(
        "SELECT domain FROM a.accounts WHERE eligibility != 'likely_non_prospect' ORDER BY domain").fetchall()]
    ours = [d for (d,) in con.execute(
        f"SELECT domain FROM a.accounts WHERE eligibility != 'likely_non_prospect' ORDER BY rank LIMIT {k}").fetchall()]
    # Naive baseline: highest raw CVSS of any CVE on the account's own (non-CDN) records.
    cvss = [d for (d,) in con.execute(
        f"""
        SELECT m.domain FROM (
            SELECT domain, max(v.cvss) AS max_cvss
            FROM attributed, unnest(vulns) AS t(v)
            WHERE domain IS NOT NULL AND coalesce(infra_class, '') != 'cdn' GROUP BY domain
        ) m JOIN a.accounts acc USING (domain)
        WHERE acc.eligibility != 'likely_non_prospect' AND m.max_cvss IS NOT NULL
        -- Many accounts tie at CVSS 10.0: break ties by a seeded hash, not alphabetically.
        ORDER BY m.max_cvss DESC, md5(m.domain || '{seed}'), m.domain LIMIT {k}
        """).fetchall()]
    rnd = random.Random(seed).sample(eligible, min(k, len(eligible)))
    return {"ours": ours, "cvss": cvss, "random": rnd}


def neutral_evidence(con: duckdb.DuckDBPyConnection, domain: str) -> str:
    rows = con.execute(
        """
        SELECT ip, port, module, product, version, attribution, source, infra_class, org, vulns,
               has_ssl, cert_expired, cert_expires, timestamp, ssl_versions, http_server
        FROM attributed WHERE domain = ?
        ORDER BY ip, port, transport, module, timestamp, shodan_id, banner_hash
        """, [domain]).fetchall()
    cols = ["ip", "port", "module", "product", "version", "attribution", "source", "infra_class", "org", "vulns",
            "has_ssl", "cert_expired", "cert_expires", "timestamp", "ssl_versions", "http_server"]
    recs = [dict(zip(cols, r)) for r in rows]
    ips = {r["ip"] for r in recs}
    how = sorted({SOURCE_TEXT[r["source"]] for r in recs})
    lines = [f"Linked by: {', '.join(how)}; {len(recs)} records on {len(ips)} IPs."]
    edges = sorted({r["org"] or "a CDN" for r in recs if r["infra_class"] == "cdn"})
    if edges:
        lines.append(f"Served through CDN / WAF: {', '.join(edges)}.")
    for r in [r for r in recs if r["infra_class"] != "cdn"][:MAX_EVIDENCE_LINES]:
        parts = [f"{r['ip']}:{r['port']} {r['module'] or ''}".strip()]
        if r["product"]:
            parts.append(" ".join(x for x in (r["product"], r["version"]) if x))
        if r["http_server"]:
            parts.append(f"server header '{r['http_server']}'")
        state = cert_state(r, 30)
        if state:
            parts.append(f"cert {state}")
        if r["ssl_versions"]:
            parts.append("TLS " + "/".join(r["ssl_versions"]))
        vulns = sorted(r["vulns"] or [], key=lambda v: (-(v["cvss"] or 0), v["cve"]))[:3]
        if vulns:
            parts.append("potential CVEs: " + "; ".join(
                f"{v['cve']} CVSS {v['cvss']}" + (" KEV" if v["kev"] else "") +
                (f" EPSS {v['epss']:.2f}" if v["epss"] is not None else "") for v in vulns))
        lines.append(" | ".join(parts))
    hidden = len([r for r in recs if r["infra_class"] != "cdn"]) - MAX_EVIDENCE_LINES
    if hidden > 0:
        lines.append(f"... {hidden} more records.")
    return "\n".join(lines)


def build(artifact: Path, features: Path, out: Path, k: int = 20, seed: int = SEED) -> dict:
    con = duckdb.connect()
    con.execute("SET enable_progress_bar = false")
    con.execute(f"ATTACH '{artifact}' AS a (READ_ONLY)")
    attribute(con, features)
    pools = _pools(con, k, seed)
    pooled = sorted({d for p in pools.values() for d in p})
    random.Random(seed + 1).shuffle(pooled)

    manifest = dict(con.execute("SELECT key, value FROM a.manifest").fetchall())
    acc = {d: (s, t) for d, s, t in con.execute("SELECT domain, score, tier FROM a.accounts").fetchall()}
    out.mkdir(parents=True, exist_ok=True)
    sheet = out / "labels.csv"
    if sheet.exists():
        raise SystemExit(f"{sheet} exists; refusing to overwrite labels")
    key = {}
    with open(sheet, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "domain", "evidence", *LABEL_COLUMNS])
        for i, d in enumerate(pooled, 1):
            lid = f"L{i:02d}"
            w.writerow([lid, d, neutral_evidence(con, d), *([""] * len(LABEL_COLUMNS))])
            key[lid] = {"domain": d, "score": acc[d][0], "tier": acc[d][1],
                        **{f"rank_{n}": (p.index(d) + 1 if d in p else None) for n, p in pools.items()}}
    meta = {
        "kind": "c2_label_pool", "k": k, "seed": seed, "pooled": len(pooled),
        "list_sizes": {n: len(p) for n, p in pools.items()},
        "overlap_ours_cvss": len(set(pools["ours"]) & set(pools["cvss"])),
        "scoring_config_version": manifest.get("scoring_config_version"),
        "artifact_input_sha256": manifest.get("input_sha256"),
        "code_commit": code_commit(), "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    write_json(out / "key.json", {"meta": meta, "key": key})
    write_json(out / "pool_manifest.json", meta)
    return meta


# ---------------------------------------------------------------- evaluate

def _norm(v: str) -> str | None:
    v = (v or "").strip().lower()
    return {"y": "yes", "yes": "yes", "n": "no", "no": "no", "?": "unknown", "u": "unknown",
            "unknown": "unknown"}.get(v)


def wilson(yes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = yes / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    r = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - r) / d, (c + r) / d)


SHEETS = {"human": "labels.csv", "ai": "ai_labels.csv"}
CATEGORIES = ("yes", "no", "unknown")


def _read_sheet(out: Path, rater: str) -> dict[str, dict]:
    with open(out / SHEETS[rater], newline="") as fh:
        return {r["id"]: r for r in csv.DictReader(fh)}


def cohen_kappa(a: list[str], b: list[str]) -> float | None:
    n = len(a)
    if n == 0:
        return None
    po = sum(x == y for x, y in zip(a, b)) / n
    pe = sum((a.count(c) / n) * (b.count(c) / n) for c in CATEGORIES)
    return 1.0 if pe == 1 else (po - pe) / (1 - pe)


def agreement(out: Path) -> dict | None:
    """Human vs AI on worth_a_call, over the rows the human has labelled (partial sheet allowed)."""
    if not (out / SHEETS["ai"]).exists():
        return None
    human, ai = _read_sheet(out, "human"), _read_sheet(out, "ai")
    pairs = [(_norm(h["worth_a_call"]), _norm(ai[i]["worth_a_call"])) for i, h in human.items()
             if _norm(h["worth_a_call"]) is not None and i in ai]
    a, b = [x for x, _ in pairs], [y for _, y in pairs]
    k = cohen_kappa(a, b)
    return {
        "question": "worth_a_call", "rows_compared": len(pairs), "rows_in_pool": len(human),
        "percent_agreement": round(sum(x == y for x, y in pairs) / len(pairs), 3) if pairs else None,
        "cohen_kappa": round(k, 3) if k is not None else None,
        "confusion_human_by_ai": {h: {c: sum(1 for x, y in pairs if x == h and y == c) for c in CATEGORIES}
                                  for h in CATEGORIES},
    }


def evaluate(out: Path, rater: str = "human") -> dict:
    key = json.loads((out / "key.json").read_text())
    labels = _read_sheet(out, rater)
    result = {"meta": key["meta"], "rater": rater, "agreement": agreement(out), "lists": {}}
    missing = [i for i, r in labels.items() if _norm(r["worth_a_call"]) is None]
    if missing:
        if result["agreement"] is not None:
            print(json.dumps({"agreement": result["agreement"]}, indent=2), file=sys.stderr)
        raise SystemExit(f"{rater} worth_a_call missing or not yes/no/unknown for: {', '.join(missing)} "
                         "(precision needs every row; agreement above uses the labelled rows)")
    for lst in ("ours", "cvss", "random"):
        ids = [i for i, k in key["key"].items() if k[f"rank_{lst}"] is not None]
        vals = [_norm(labels[i]["worth_a_call"]) for i in ids]
        yes, no = vals.count("yes"), vals.count("no")
        lo, hi = wilson(yes, yes + no)
        sub = {q: sum(_norm(labels[i][q]) == "yes" for i in ids) for q in ("real_org", "own_asset", "credible_opener")}
        result["lists"][lst] = {
            "accounts": len(ids), "yes": yes, "no": no, "unknown": vals.count("unknown"),
            "precision": round(yes / (yes + no), 3) if yes + no else None,
            "wilson95": [round(lo, 3), round(hi, 3)], "sub_questions_yes": sub,
        }
    write_json(out / f"c2_result_{rater}.json", result)
    return result


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("artifact", type=Path)
    b.add_argument("features", type=Path)
    b.add_argument("--out", type=Path, required=True)
    b.add_argument("--k", type=int, default=20)
    e = sub.add_parser("evaluate")
    e.add_argument("out", type=Path)
    e.add_argument("--rater", choices=sorted(SHEETS), default="human")
    a = sub.add_parser("ai-label", help="second rater: label the pool with Claude (needs ANTHROPIC_API_KEY)")
    a.add_argument("out", type=Path)
    a.add_argument("--provider", choices=["anthropic", "openai"], default="anthropic",
                   help="openai = any OpenAI-compatible endpoint (LLM_BASE_URL, LLM_API_KEY)")
    a.add_argument("--model", default=None, help="anthropic: default latest Claude Sonnet; openai: required")
    a.add_argument("--price-in", type=float, help="USD per million input tokens, if the provider reports no cost")
    a.add_argument("--price-out", type=float, help="USD per million output tokens")
    a.add_argument("--force", action="store_true", help="overwrite ai_labels.csv")
    args = ap.parse_args(argv)
    if args.cmd == "build":
        res = build(args.artifact, args.features, args.out, args.k)
    elif args.cmd == "evaluate":
        res = evaluate(args.out, args.rater)
    else:
        from salesintel.eval import ailabel

        if (args.price_in is None) != (args.price_out is None):
            raise SystemExit("--price-in and --price-out go together")
        res = ailabel.run(args.out, model=args.model, force=args.force, provider=args.provider,
                          price_in=args.price_in, price_out=args.price_out)
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    sys.exit(main())
