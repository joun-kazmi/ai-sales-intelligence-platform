"""C4: is the ranking fragile? Perturb each point weight by +/-25% and compare (D28, D37).

Weights that round back to themselves at +/-25% move by +/-1 point instead (D54).

Reports, per perturbation, the overlap of the default-view top 20 (and top 100) with the frozen
ranking, and the Spearman correlation of scores over all default-view accounts. Attribution and
eligibility run once; only points change. Tie-break as in scoring (score, findings, domain).

    salesintel-sensitivity out/domain_sample/features/<sha256> --sample-modulus 20 --out out/c4.json
"""

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path

import duckdb

from salesintel.pipeline.atomic import code_commit, write_json
from salesintel.pipeline.attribute import attribute
from salesintel.pipeline.sample import keep_domain
from salesintel.pipeline.score import _domain_groups, account_findings, eligibility, load_config

WEIGHTS = ["exposed_service", "cve_kev", "cve_likely", "eol_product", "eol_os", "cert_expired",
           "deprecated_tls", "self_signed_public", "version_disclosed", "no_hsts"]


def _ranking(groups, cfg) -> list[tuple[str, int]]:
    scored = []
    for domain, recs in groups:
        fs = account_findings(domain, recs, cfg)
        scored.append((domain, sum(f.points for f in fs), sum(1 for f in fs if f.points > 0)))
    scored.sort(key=lambda x: (-x[1], -x[2], x[0]))
    return [(d, s) for d, s, _ in scored]


def _spearman(a: dict[str, int], b: dict[str, int]) -> float:
    keys = sorted(a)

    def ranks(scores: dict[str, int]) -> dict[str, float]:
        order = sorted(keys, key=lambda k: -scores[k])
        out, i = {}, 0
        while i < len(order):
            j = i
            while j + 1 < len(order) and scores[order[j + 1]] == scores[order[i]]:
                j += 1
            for k in order[i:j + 1]:
                out[k] = (i + j) / 2 + 1
            i = j + 1
        return out

    ra, rb = ranks(a), ranks(b)
    n = len(keys)
    ma, mb = sum(ra.values()) / n, sum(rb.values()) / n
    cov = sum((ra[k] - ma) * (rb[k] - mb) for k in keys)
    va = sum((ra[k] - ma) ** 2 for k in keys) ** 0.5
    vb = sum((rb[k] - mb) ** 2 for k in keys) ** 0.5
    return cov / (va * vb) if va and vb else 1.0


def run(features: Path, out: Path, sample_modulus: int | None = None, delta: float = 0.25) -> dict:
    base = load_config()
    con = duckdb.connect()
    con.execute("SET enable_progress_bar = false")
    attribute(con, features)
    groups = []
    for domain, recs in _domain_groups(con):
        if sample_modulus and not keep_domain(domain, sample_modulus):
            continue  # partial accounts of non-sampled domains on shared IPs
        if eligibility(domain, recs, base)[0] != "likely_non_prospect":
            groups.append((domain, recs))
    ref = _ranking(groups, base)
    ref_scores = dict(ref)
    top = {k: [d for d, _ in ref[:k]] for k in (20, 100)}
    rows = []
    for w in WEIGHTS:
        for sign in (-1, 1):
            raw = json.loads(json.dumps(base.raw))
            old = raw["points"][w]
            new = round(old * (1 + sign * delta))
            change = f"{sign * delta:+.0%}"
            if new == old:
                # Small weights (2 points) round back to themselves at +/-25%: move them by one
                # point instead so the run tests something.
                new, change = old + sign, f"{sign:+d} pt"
            raw["points"][w] = new
            got = _ranking(groups, replace(base, raw=raw))
            rows.append({
                "weight": w, "change": change, "value": new,
                "top20_overlap": len(set(top[20]) & {d for d, _ in got[:20]}) / 20,
                "top100_overlap": len(set(top[100]) & {d for d, _ in got[:100]}) / 100,
                "spearman_all": round(_spearman(ref_scores, dict(got)), 4),
            })
    result = {
        "kind": "c4_sensitivity", "scoring_config_version": base.version, "delta": delta,
        "accounts_default_view": len(groups), "sample_modulus": sample_modulus,
        "min_top20_overlap": min(r["top20_overlap"] for r in rows),
        "min_spearman": min(r["spearman_all"] for r in rows),
        "runs": rows, "code_commit": code_commit(),
    }
    write_json(out, result)
    return result


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("features", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--sample-modulus", type=int, help="only domains kept by the sample hash (dev sample)")
    args = ap.parse_args(argv)
    r = run(args.features, args.out, args.sample_modulus)
    print(json.dumps({k: v for k, v in r.items() if k != "runs"}, indent=2))


if __name__ == "__main__":
    sys.exit(main())
