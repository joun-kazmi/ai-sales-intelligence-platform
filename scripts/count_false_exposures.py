"""Count false exposures (D55) in an artifact scored before the fix, per C2 list.

A false exposure is an exposed-service finding whose identified product is a generic SSH / FTP /
HTTP / proxy server (`is_other_service`). For each list in a C2 key (ours / cvss / random) it
reports how many accounts carry one, and how many would lose their exposure points because none of
their exposure findings is genuine. Reads only; prints JSON.

    uv run python scripts/count_false_exposures.py out/full/artifact.duckdb out/full/c2/key.json
"""

import json
import sys
from collections import defaultdict
from pathlib import Path

import duckdb

from salesintel.pipeline.score import is_other_service, load_config


def count(artifact: Path, key_path: Path) -> dict:
    cfg = load_config()
    key = json.loads(key_path.read_text())["key"]
    domains = sorted({k["domain"] for k in key.values()})
    con = duckdb.connect(str(artifact), read_only=True)
    rows = con.execute(
        "SELECT domain, product, points FROM findings WHERE kind = 'exposed_service' AND domain IN (SELECT unnest(?))",
        [domains]).fetchall()
    per = defaultdict(lambda: {"false": 0, "genuine": 0, "awarded_false": False})
    for d, product, points in rows:
        false = is_other_service(product, cfg)
        per[d]["false" if false else "genuine"] += 1
        per[d]["awarded_false"] |= false and points > 0
    out = {"artifact_config": dict(con.execute("SELECT key, value FROM manifest").fetchall()).get("scoring_config_version"),
           "guard_config": cfg.version, "lists": {}}
    for lst in ("ours", "cvss", "random"):
        accs = [k["domain"] for k in key.values() if k[f"rank_{lst}"] is not None]
        with_false = [d for d in accs if per[d]["false"]]
        loses = [d for d in with_false if per[d]["genuine"] == 0]
        out["lists"][lst] = {"accounts": len(accs), "with_false_exposure": len(with_false),
                             "lose_exposure_points": len(loses),
                             "awarded_exposure_was_false": sum(per[d]["awarded_false"] for d in accs)}
    return out


if __name__ == "__main__":
    print(json.dumps(count(Path(sys.argv[1]), Path(sys.argv[2])), indent=2))
