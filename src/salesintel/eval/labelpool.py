"""C2: blind human labelling of our ranking vs "highest CVSS first" vs random (D28, D37).

build:    pool = our top k + top k by highest CVSS + k random, all from the same eligible set
          (default view: likely non-prospects hidden), deduplicated, shuffled. The label sheet shows
          the same neutral evidence for every account (from the feature layer, not our findings),
          and nothing about score, tier, rank or which list it came from. The key is a separate file.
ai-label: a second rater (Claude) labels the same sheet into ai_labels.csv (D57).
evaluate: precision@k per list from the human or AI sheet, plus human-vs-AI agreement.

    salesintel-labelpool build out/full/artifact.duckdb out/full/features/<sha256> --out out/full/c2
    salesintel-labelpool build ... --out out/full/c2v2 --from out/full/c2   (evidence v2, D59)
    salesintel-labelpool ai-label out/full/c2
    salesintel-labelpool evaluate out/full/c2 [--rater human|ai]
"""

import argparse
import csv
import json
import math
import random
import re
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import duckdb

from salesintel.pipeline.atomic import code_commit, write_json
from salesintel.pipeline.attribute import attribute
from salesintel.pipeline.score import cert_state, load_config

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


def _record_line(r: dict) -> str:
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
            (f" EPSS {v['epss']:.2f}" if v["epss"] is not None else "") +
            (" (verified)" if v.get("verified") else "") for v in vulns))
    return " | ".join(parts)


def _worst_first(r: dict, risky: frozenset[str]) -> tuple:
    """Fixed evidence order (D59), independent of scoring weights: any KEV CVE, then highest CVSS,
    then a risky exposed service (remote admin / database / ICS module), then an expired cert,
    then IP and port."""
    vulns = r["vulns"] or []
    return (not any(v["kev"] for v in vulns), -max((v["cvss"] or 0 for v in vulns), default=0),
            r["module"] not in risky, cert_state(r, 30) != "expired", r["ip"], r["port"] or 0)


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
    risky = frozenset(load_config().raw["exposure_modules"])  # the module list, not the weights
    own = sorted((r for r in recs if r["infra_class"] != "cdn"), key=lambda r: _worst_first(r, risky))
    counts: dict[str, int] = {}
    for r in own:  # collapse identical lines, keeping worst-first order
        line = _record_line(r)
        counts[line] = counts.get(line, 0) + 1
    shown = list(counts.items())[:MAX_EVIDENCE_LINES]
    lines += [f"{line} (x{n})" if n > 1 else line for line, n in shown]
    hidden = len(own) - sum(n for _, n in shown)
    if hidden > 0:
        lines.append(f"... {hidden} more records.")
    return "\n".join(lines)


def _evidence_content(evidence: str) -> tuple[Counter, bool]:
    """Record lines as a multiset (order-free, counts expanded) and whether it was truncated."""
    lines, truncated = Counter(), False
    for line in evidence.splitlines():
        if line.startswith(("Linked by:", "Served through CDN")):
            continue
        if line.startswith("... ") and line.endswith(" more records."):
            truncated = True
            continue
        m = re.fullmatch(r"(.*) \(x(\d+)\)", line)
        lines[m.group(1) if m else line] += int(m.group(2)) if m else 1
    return lines, truncated


def evidence_changed(old: str, new: str) -> bool:
    """True if the evidence differs beyond ordering / collapsing (then the row is relabelled)."""
    (a, ta), (b, tb) = _evidence_content(old), _evidence_content(new)
    return ta or tb or a != b


def build(artifact: Path, features: Path, out: Path, k: int = 20, seed: int = SEED,
          from_dir: Path | None = None) -> dict:
    con = duckdb.connect()
    con.execute("SET enable_progress_bar = false")
    con.execute(f"ATTACH '{artifact}' AS a (READ_ONLY)")
    attribute(con, features)
    out.mkdir(parents=True, exist_ok=True)
    sheet = out / "labels.csv"
    if sheet.exists():
        raise SystemExit(f"{sheet} exists; refusing to overwrite labels")
    manifest = dict(con.execute("SELECT key, value FROM a.manifest").fetchall())

    if from_dir is not None:
        # Re-run of an earlier pool (D59): same pools, ids and order; earlier labels kept where the
        # evidence did not change. The earlier folder is only read.
        if from_dir.resolve() == out.resolve():
            raise SystemExit("--from must differ from --out")
        prev_key = json.loads((from_dir / "key.json").read_text())
        with open(from_dir / "labels.csv", newline="") as fh:
            prev = {r["id"]: r for r in csv.DictReader(fh)}
        ids = sorted(prev_key["key"])
        reset, kept = [], []
        with open(sheet, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["id", "domain", "evidence", *LABEL_COLUMNS])
            for lid in ids:
                d = prev_key["key"][lid]["domain"]
                ev = neutral_evidence(con, d)
                if evidence_changed(prev[lid]["evidence"], ev):
                    reset.append(lid)
                    w.writerow([lid, d, ev, *([""] * len(LABEL_COLUMNS))])
                else:
                    kept.append(lid)
                    w.writerow([lid, d, ev, *(prev[lid].get(c, "") for c in LABEL_COLUMNS)])
        meta = {**prev_key["meta"], "kind": "c2_label_pool", "evidence_version": 2, "from": str(from_dir),
                "rows_reset_for_relabelling": reset, "rows_labels_copied": len(kept),
                "code_commit": code_commit(), "created_at": datetime.now(UTC).isoformat(timespec="seconds")}
        write_json(out / "key.json", {"meta": meta, "key": prev_key["key"]})
        write_json(out / "pool_manifest.json", {k: v for k, v in meta.items()})
        return meta

    pools = _pools(con, k, seed)
    pooled = sorted({d for p in pools.values() for d in p})
    random.Random(seed + 1).shuffle(pooled)
    acc = {d: (s, t) for d, s, t in con.execute("SELECT domain, score, tier FROM a.accounts").fetchall()}
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
        "kind": "c2_label_pool", "evidence_version": 2, "k": k, "seed": seed, "pooled": len(pooled),
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


QUESTIONS = ("worth_a_call", "own_asset", "real_org", "credible_opener")


def _agree(human: dict, ai: dict, q: str) -> dict:
    pairs = [(_norm(h[q]), _norm(ai[i][q])) for i, h in human.items() if _norm(h.get(q, "")) is not None and i in ai]
    a, b = [x for x, _ in pairs], [y for _, y in pairs]
    k = cohen_kappa(a, b)
    return {
        "rows_compared": len(pairs),
        "percent_agreement": round(sum(x == y for x, y in pairs) / len(pairs), 3) if pairs else None,
        "cohen_kappa": round(k, 3) if k is not None else None,
        "confusion_human_by_ai": {h: {c: sum(1 for x, y in pairs if x == h and y == c) for c in CATEGORIES}
                                  for h in CATEGORIES},
    }


def agreement(out: Path) -> dict | None:
    """Human vs AI per question, over the rows the human answered (partial sheet allowed)."""
    if not (out / SHEETS["ai"]).exists():
        return None
    human, ai = _read_sheet(out, "human"), _read_sheet(out, "ai")
    per_q = {q: _agree(human, ai, q) for q in QUESTIONS}
    # Top-level keys keep the worth_a_call figures (the headline question).
    return {"question": "worth_a_call", "rows_in_pool": len(human), **per_q["worth_a_call"], "per_question": per_q}


def _precision(vals: list[str | None]) -> tuple[int, int]:
    return vals.count("yes"), vals.count("no")


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
        yes, no = _precision(vals)
        lo, hi = wilson(yes, yes + no)
        sub = {q: sum(_norm(labels[i][q]) == "yes" for i in ids) for q in ("real_org", "own_asset", "credible_opener")}
        entry = {
            "accounts": len(ids), "yes": yes, "no": no, "unknown": vals.count("unknown"),
            "precision": round(yes / (yes + no), 3) if yes + no else None,
            "wilson95": [round(lo, 3), round(hi, 3)], "sub_questions_yes": sub,
        }
        # Stricter hit (D59): worth a call AND evidence on their own asset. Unknown own_asset is not
        # yes. Reported only when own_asset is filled for every account in the list.
        own = [_norm(labels[i]["own_asset"]) for i in ids]
        if all(o is not None for o in own):
            both = sum(v == "yes" and o == "yes" for v, o in zip(vals, own))
            lo2, hi2 = wilson(both, yes + no)
            entry["precision_worth_and_own_asset"] = round(both / (yes + no), 3) if yes + no else None
            entry["wilson95_worth_and_own_asset"] = [round(lo2, 3), round(hi2, 3)]
        else:
            entry["precision_worth_and_own_asset"] = None
            entry["note"] = "own_asset not filled for every account; strict precision not computed"
        result["lists"][lst] = entry
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
    b.add_argument("--from", dest="from_dir", type=Path,
                   help="earlier pool folder: same pools and ids; labels copied where evidence is unchanged")
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
    a.add_argument("--max-tokens", type=int, default=4000,
                   help="openai: max output tokens per call (reasoning models need room before the JSON)")
    a.add_argument("--no-thinking", action="store_true",
                   help="openai: send chat_template_kwargs enable_thinking=false (e.g. NVIDIA Nemotron)")
    a.add_argument("--force", action="store_true", help="overwrite ai_labels.csv")
    args = ap.parse_args(argv)
    if args.cmd == "build":
        res = build(args.artifact, args.features, args.out, args.k, from_dir=args.from_dir)
    elif args.cmd == "evaluate":
        res = evaluate(args.out, args.rater)
    else:
        from salesintel.eval import ailabel

        if (args.price_in is None) != (args.price_out is None):
            raise SystemExit("--price-in and --price-out go together")
        res = ailabel.run(args.out, model=args.model, force=args.force, provider=args.provider,
                          price_in=args.price_in, price_out=args.price_out, max_tokens=args.max_tokens,
                          no_thinking=args.no_thinking)
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    sys.exit(main())
