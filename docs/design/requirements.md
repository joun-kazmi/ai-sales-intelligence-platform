# Requirements

Status: agreed 2026-10-27, revised the same day after external review. Derived from
`use-cases.md` (UC1-UC4) and `docs/ASSIGNMENT.md`. Decisions D9-D14, D23-D41 in `docs/DECISIONS.md`. **[M]** measured, **[H]** hypothesis.

Priority: **Must** = in the MVP due Fri 2026-10-30. **Nice** = only if time allows.
**Design** = specified and shown in the architecture, not built in the MVP.

## Functional: hosted app

| ID | Requirement | UC | Priority |
|---|---|---|---|
| FR1 | Ranked account list: domain, research-priority score, tier, top 2-3 reasons in plain English, "why now" marker, attribution label, prospect-eligibility label. Deterministic order (score, findings count, domain), paged. | UC1 | Must |
| FR2a | Filters, minimal set: score / tier, signal type, has "why now" evidence, security gear present / absent, prospect eligibility (default hides likely non-prospects; `signals-scoring.md` 1b). | UC1, UC3 | Must |
| FR2b | Further filter: attribution label. (Country filter cut, D29.) | UC1 | Nice |
| FR2c | Partial industry filter (TLD + title keywords; LLM option decided in step 3). | UC1 | Nice, depends on step 3 |
| FR3 | Account detail: each finding in plain English with evidence (host / IP, port, module, product + version, CVE ID + CVSS + KEV / EPSS, worded "potential match to a known-exploited CVE, observed on <date>", or **verified** when Shodan verified it; cert expiry; observed-at). Score breakdown that sums to the total. Attribution per finding (direct + source, or via-IP). Display name only if it passes the name filter. | UC2 | Must |
| FR4 | Plays: preset finding-based views, each naming its buyer role (`use-cases.md` UC3): exposed remote access / DB, EOL software, potential known-exploited CVEs, expired / expiring certs, edge appliances. Built on FR2a. | UC3 | Must |
| FR5 | CSV export of the current filtered list (domain, score, tier, reasons, why-now, evidence summary). | UC3 | Must |
| FR6 | Snapshot date and source file shown on every view. | all | Must |

## Functional: offline pipeline

| ID | Requirement | Priority |
|---|---|---|
| FR7 | Stream one banner file into a per-domain findings table, applying the infrastructure-class policy of `signals-scoring.md` section 1: drop honeypot and noise; drop shared CDN / WAF edge records unless they name the domain (then only the "behind <edge>" fact); cloud / hosting IPs get no via-IP attribution; customer appliances kept as facts. Tag each finding direct or via-IP; via-IP only for IPs with exactly one domain and a non-CDN, non-cloud/hosting org; IPs with 2+ domains are unresolved. Count findings per domain + product / version, not per record. | Must |
| FR8 | Deterministic scoring from a versioned config; every score can be rebuilt from its stored evidence. | Must |
| FR9 | Record a funnel for every run: records -> kept -> linked to a domain -> accounts, with counts per drop reason. Feeds the write-up. | Must |
| FR10 | Evaluation: C1 forward-DNS match rate, C2 blind human labels with precision@20 vs highest-CVSS and random (weights frozen first), C4 sensitivity (`signals-scoring.md` section 4). | Must |
| FR11 | Coverage-aware merge of each new file into existing accounts, with `first_seen` / `last_seen` per finding. Invariants: `architecture.md`, "FR11 merge invariants". | Design |

## Non-functional
**NFR1. Volume: hundreds to thousands of files per month.**
Each file is processed independently and in parallel, idempotently (keyed by the file's content
hash, so a re-run or duplicate delivery is a no-op), then merged by domain.
Evidence [M], full file (14,608,407 records, 17.6 GB zstd), owner's machine, 8 cores / 7
workers, extractor at `c61315d`: **9 min 07 s wall, ~26.7k records/s, peak RSS ~0.5 GB**, feature
layer **1.03 GB** (0.84% of the 122.8 GB raw, 5.9% of the compressed input). Memory stays flat
(bounded in-flight batches), so files can run side by side on one machine as RAM allows. Storage
is the real cost: ~17.6 TB compressed input and ~1 TB of feature layer per 1,000 files (size
arithmetic from these measurements). The MVP processes one file locally; scale-out is design
only.

Scoring the full feature layer [M] (`e519275`, config `6cf3bc33da1a`): 2 min 21 s wall, **peak RSS
13.5 GB** on the 15 GB machine, artifact 44.8 MB. Too close to OOM: attribution materialized the
whole feature layer twice. Fixed (D51): streamed views plus a DuckDB `memory_limit` (default 6 GB)
with a spill directory; on the sample the peak fell from 1,094 to 750 MB with identical output.
Re-measured on the full file [M] (`2576298`, config `765eef67e0c5`): **1 min 20 s wall, peak RSS
2.8 GB** (from 13.5 GB), artifact 46.4 MB.

**NFR2. Raw retention is a trade-off.** Deleting raw files after extraction is cheapest, but
then a new signal cannot be backfilled. Production answer: keep raw in cheap cold object storage
for N days (N set by cost; backfill is possible only within that window), and store an extracted
feature layer rich enough to **re-score without reprocessing**: all filtered records with the
fields in the feature schema (`signals-scoring.md` section 3, D30). Changing weights or rules
re-runs only scoring; adding a new extractor needs raw. Size of the feature layer: measured on
Wednesday [H: much smaller than raw, because `http.html` and raw `data` are dropped].

**NFR3. Hosting.** Free tier. The app serves a precomputed, read-only scored dataset with a **hard
cap of 100 MB** (publish fails above it; fallback: Tier 1-2 accounts plus counts) and no paid
database. Target <1 s per page when warm; a slow first load after the free
host sleeps is accepted and stated in the README.

Measured on the full `data-v1` artifact [M] (owner's machine, `feature/ui` `61d93dc`, via
`ARTIFACT_PATH`): `/` 15 ms, page 500 of `tier=all` 96 ms, `play=exploited` 99 ms, `play=eol`
129 ms, `/plays` 179 ms, account page 39 ms. `/export.csv` of the default view: 169,285 rows,
34 MB in 2.0 s (`tier=all&eligibility=all`: 44 MB, 3.0 s), streamed. After those exports the
server held 325 MB, too close to Render's 512 MB, because DuckDB sizes its memory limit and
threads from the host, not the container: the app's read-only connection is now capped at
256 MiB and 2 threads (D56), checked by a test.

**NFR4. Access.** HTTP basic auth over the host's HTTPS. Sample reviewer credentials are set as
host environment variables and given **only in the submission note**; the README says
"credentials provided separately". No user management.

**NFR5. Safety of the app itself.** The app lists vulnerable organisations with evidence. Escape
all record-derived text, never render banner HTML, never show raw banners. Basic auth on every
route, plus no-index (`X-Robots-Tag: noindex`, `robots.txt`).

**NFR6. Development data.** Domain-level features and scoring are developed on the
domain-complete sample (D8); the 1-in-160 line sample is for dataset-wide questions only. No raw
data, `.env`, `*.duckdb` or `*.parquet` in git.

**NFR7. Reproducibility.** Every output has a manifest: input file hash, extractor version,
infra blocklist version, PSL snapshot version, scoring config version, code commit, row counts.
All outputs are written atomically (temp file, fsync, rename).

**NFR8. LLM use.** One use in the MVP: the C2 AI second rater (D57), offline, never in scoring or the app. Accuracy and cost per run are measured and reported.
Inputs are short sanitized fields, never raw banners or HTML (prompt-injection risk). Outputs are
constrained to a schema. Results are cached per domain, so cost scales with new domains, not
with files.
