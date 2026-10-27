"""Extract: one banner file (.jsonl.zst) -> feature layer partition (architecture.md step 1).

Output: <out>/features/<file sha256>/part-NNNNN.parquet + manifest.json, published atomically.
Idempotent: a partition whose manifest exists is skipped unless --force.

    salesintel-extract data/sample/sample.jsonl.zst --out out/sample
"""

import argparse
import io
import multiprocessing
import os
import sys
import time
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, Future, ProcessPoolExecutor, wait
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterator

import orjson
import pyarrow as pa
import pyarrow.parquet as pq
import zstandard

from salesintel.pipeline import infra, names
from salesintel.pipeline.atomic import atomic_dir, code_commit, file_sha256, write_json
from salesintel.pipeline.project import COLUMNS, SCHEMA, project

EXTRACTOR_VERSION = "1"
BATCH_LINES = 2000


def iter_batches(path: Path, batch_lines: int) -> Iterator[list[bytes]]:
    with open(path, "rb") as f:
        reader = io.BufferedReader(zstandard.ZstdDecompressor().stream_reader(f), buffer_size=1 << 20)
        batch: list[bytes] = []
        for line in reader:
            batch.append(line)
            if len(batch) >= batch_lines:
                yield batch
                batch = []
        if batch:
            yield batch


def process_batch(index: int, lines: list[bytes], part_dir: str) -> tuple[int, Counter]:
    """Worker: parse, project, write one Parquet part. Returns (rows, counters)."""
    lists = infra.load()
    counts: Counter = Counter()
    cols: dict[str, list] = {c: [] for c in COLUMNS}
    for line in lines:
        counts["records"] += 1
        try:
            rec = orjson.loads(line)
        except orjson.JSONDecodeError:
            counts["dropped_parse_error"] += 1
            continue
        row, reason = project(rec, lists)
        if row is None:
            counts[f"dropped_{reason}"] += 1
            continue
        counts["kept"] += 1
        if row["names"]:
            counts["kept_named"] += 1
        counts[f"kept_class_{row['infra_class'] or 'customer_or_isp'}"] += 1
        for c in COLUMNS:
            cols[c].append(row[c])
    if counts["kept"]:
        table = pa.Table.from_pydict(cols, schema=SCHEMA)
        pq.write_table(table, Path(part_dir) / f"part-{index:05d}.parquet", compression="zstd")
    return counts["kept"], counts


def extract(src: Path, out: Path, workers: int, force: bool = False, batch_lines: int = BATCH_LINES) -> dict:
    started = time.monotonic()
    file_hash = file_sha256(src)
    target = out / "features" / file_hash
    lists = infra.load()
    versions = {
        "extractor_version": EXTRACTOR_VERSION,
        "blocklist_version": lists.version,
        "psl_version": names.psl_version(),
    }
    if (target / "manifest.json").exists() and not force:
        existing = orjson.loads((target / "manifest.json").read_bytes())
        if all(existing.get(k) == v for k, v in versions.items()):
            print(f"skip: {src.name} already extracted ({file_hash[:12]})", file=sys.stderr)
            return existing
        raise SystemExit(f"{target} was built with different versions; re-run with --force")
    hash_seconds = time.monotonic() - started

    totals: Counter = Counter()
    rows = 0
    with atomic_dir(target, replace=force) as tmp:
        # forkserver: forking a process that already runs pyarrow / DuckDB threads can deadlock.
        ctx = multiprocessing.get_context("forkserver")
        with ProcessPoolExecutor(max_workers=workers, mp_context=ctx) as pool:
            pending: set[Future] = set()
            for i, batch in enumerate(iter_batches(src, batch_lines)):
                # Bounded in-flight work keeps memory flat on a 123 GB stream.
                if len(pending) >= workers * 2:
                    done, pending = wait(pending, return_when=FIRST_COMPLETED)
                    for fut in done:
                        n, c = fut.result()
                        rows += n
                        totals.update(c)
                pending.add(pool.submit(process_batch, i, batch, str(tmp)))
            for fut in pending:
                n, c = fut.result()
                rows += n
                totals.update(c)
        seconds = time.monotonic() - started
        manifest = {
            "kind": "features",
            "input_file": src.name,
            "input_bytes": src.stat().st_size,
            "input_sha256": file_hash,
            **versions,
            "code_commit": code_commit(),
            "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "workers": workers,
            "rows": rows,
            "parts": sorted(p.name for p in tmp.glob("part-*.parquet")),
            "counts": dict(sorted(totals.items())),
            "seconds_total": round(seconds, 1),
            "seconds_hashing": round(hash_seconds, 1),
            "records_per_second": round(totals["records"] / max(seconds - hash_seconds, 1e-9)),
            "output_bytes": sum(p.stat().st_size for p in tmp.glob("part-*.parquet")),
        }
        write_json(tmp / "manifest.json", manifest)
    return manifest


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", type=Path, help="Shodan banner file, .jsonl.zst")
    ap.add_argument("--out", type=Path, required=True, help="output root (gitignored)")
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    ap.add_argument("--force", action="store_true", help="re-extract even if the partition exists")
    args = ap.parse_args(argv)
    m = extract(args.input, args.out, args.workers, args.force)
    summary = {k: m[k] for k in ("input_sha256", "rows", "seconds_total", "records_per_second", "output_bytes")}
    print(orjson.dumps({**summary, "counts": m["counts"]}, option=orjson.OPT_INDENT_2).decode())


if __name__ == "__main__":
    main()
