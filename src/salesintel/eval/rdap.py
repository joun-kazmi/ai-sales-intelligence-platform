"""C1 hand-check helper: pre-fill `ip_owner` in misses.csv from RDAP (run where the network is open).

For each distinct IP, asks rdap.org (which redirects to the responsible registry) for the network
and its registrant, and writes "<organisation> (<network name>, <country>)". Existing verdict and
notes columns are kept; rows that already have an owner are skipped unless --force. One request
per second; the file is rewritten atomically.

    salesintel-rdap out/full/c1/misses.csv
"""

import argparse
import csv
import sys
import time
from pathlib import Path

import httpx

from salesintel.pipeline.atomic import atomic_file

RDAP = "https://rdap.org/ip/{ip}"
OWNER_ROLES = ("registrant", "administrative", "technical")


def _vcard_name(entity: dict) -> str | None:
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] in ("fn", "org") and item[3]:
            return str(item[3])
    return None


def owner_from_rdap(doc: dict) -> str:
    org = None
    for role in OWNER_ROLES:
        for e in doc.get("entities") or []:
            if role in (e.get("roles") or []) and (org := _vcard_name(e)):
                break
        if org:
            break
    name, country = doc.get("name"), doc.get("country")
    detail = ", ".join(x for x in (name, country) if x)
    if org and detail:
        return f"{org} ({detail})"
    return org or detail or "unknown"


def lookup(client: httpx.Client, ip: str, pause: float) -> str:
    for attempt in range(2):
        r = client.get(RDAP.format(ip=ip))
        if r.status_code == 429 and attempt == 0:
            time.sleep(max(pause, 5))
            continue
        if r.status_code != 200:
            return f"rdap error {r.status_code}"
        try:
            return owner_from_rdap(r.json())
        except ValueError:
            return "rdap error: not JSON"
    return "rdap error 429"


def fill(path: Path, client: httpx.Client | None = None, pause: float = 1.0, force: bool = False) -> dict:
    with open(path, newline="") as fh:
        reader = csv.DictReader(fh)
        rows, fields = list(reader), list(reader.fieldnames or [])
    if "ip_owner" not in fields:
        fields.insert(fields.index("resolved_ips") + 1 if "resolved_ips" in fields else len(fields), "ip_owner")
    own = client is None
    client = client or httpx.Client(timeout=15, follow_redirects=True,
                                    headers={"Accept": "application/rdap+json, application/json"})
    cache: dict[str, str] = {}
    looked = 0
    try:
        for r in rows:
            if r.get("ip_owner") and not force:
                continue
            if r["ip"] not in cache:
                if looked:
                    time.sleep(pause)
                cache[r["ip"]] = lookup(client, r["ip"], pause)
                looked += 1
            r["ip_owner"] = cache[r["ip"]]
    finally:
        if own:
            client.close()
    with atomic_file(path) as tmp, open(tmp, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    return {"rows": len(rows), "lookups": looked}


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("misses", type=Path, help="out/full/c1/misses.csv")
    ap.add_argument("--force", action="store_true", help="refill rows that already have an owner")
    args = ap.parse_args(argv)
    print(fill(args.misses, force=args.force))


if __name__ == "__main__":
    sys.exit(main())
