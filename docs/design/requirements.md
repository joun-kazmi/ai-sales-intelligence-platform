# Requirements

Status: agreed 2026-10-27. Derived from `use-cases.md` (UC1-UC4) and `docs/ASSIGNMENT.md`.
Decisions D9-D14 in `docs/DECISIONS.md`. **[M]** measured, **[H]** hypothesis.

Priority: **Must** = in the MVP due Fri 2026-10-30. **Nice** = only if time allows.
**Design** = specified and shown in the architecture, not built in the MVP.

## Functional: hosted app
| ID | Requirement | UC | Priority |
|---|---|---|---|
| FR1 | Ranked account list: domain, score, tier, top 2-3 reasons in plain English, "why now" marker, resolution confidence. Sorted by score, paged. | UC1 | Must |
| FR2a | Filters, minimal set: score / tier, signal type, has "why now" evidence, security gear present / absent. | UC1, UC3 | Must |
| FR2b | Further filters: resolution confidence, country (source labelled: IP of non-edge assets or ccTLD). | UC1 | Nice |
| FR2c | Partial industry filter (TLD + title keywords; LLM option decided in step 3). | UC1 | Nice, depends on step 3 |
| FR3 | Account detail: each finding in plain English with evidence (host / IP, port, product + version, CVE ID + CVSS + KEV / EPSS, labelled "potential"; cert expiry; observed-at). Score breakdown that sums to the total. Resolution method + confidence. Display name only if it passes the name filter. | UC2 | Must |
| FR4 | Plays: preset finding-based views (exposed remote access / DB, EOL software, actively exploited potential CVEs, expired / expiring certs, exposed edge appliances), built on FR2a. | UC3 | Must |
| FR5 | CSV export of the current filtered list (domain, score, tier, reasons, why-now, evidence summary). | UC3 | Must |
| FR6 | Snapshot date and source file shown on every view. | all | Must |

## Functional: offline pipeline
| ID | Requirement | Priority |
|---|---|---|
| FR7 | Stream one banner file into a per-domain findings table. Drop honeypot, CDN-edge and ISP-PTR records first. Count each finding once per domain + product/version (+ CVE), not per record. | Must |
| FR8 | Deterministic scoring from a versioned config; every score can be rebuilt from its stored evidence. | Must |
| FR9 | Record a funnel for every run: records -> kept -> linked to a domain -> accounts, with counts per drop reason. Feeds the write-up. | Must |
| FR10 | Evaluation step that measures ranking quality (method in step 3). The brief asks how we measured whether it works. | Must |
| FR11 | Coverage-aware merge of a new file into existing accounts. Each finding carries `first_seen` / `last_seen`, and on each new file is one of: **new**, **still present**, **resolved** (the file scanned the same IP:port and the finding is absent), **not observed** (the file did not scan that IP:port). Missing is never read as fixed. Coverage is the set of scanned IP:port for IPs linked to accounts. | Design |

## Non-functional
**NFR1. Volume: hundreds to thousands of files per month.**
Each file is processed independently and in parallel, idempotently (keyed by the file's content
hash, so a re-run or duplicate delivery is a no-op), then merged by domain.
Evidence: one file = 14.6M records, 17.6 GB zstd, 754 s on 8 cores (7 workers), ~19k records/s
[M]. At that rate:
| Files / month | Compute (8-core hours) | Share of one 8-core machine-month | Compressed input |
|---|---|---|---|
| 1,000 | ~210 h | ~29% | ~17.6 TB |
| 3,000 | ~630 h | ~86% | ~53 TB |
Compute scales linearly and is not the bottleneck; storage and I/O are. The MVP processes one
file locally; scale-out is design only.

**NFR2. Raw retention is a trade-off.** Deleting raw files after extraction is cheapest, but
then a new signal cannot be backfilled. Production answer: keep raw in cheap cold object storage
for N days (N set by cost; backfill is possible only within that window), and store an extracted
feature layer rich enough to **re-score without reprocessing** (per kept record: IP, port,
timestamp, domain keys and resolution method, product / version, CVE IDs with CVSS / EPSS / KEV,
cert dates and flags, TLS versions, security-header flags, tags, filtered title). Changing weights
or rules re-runs only scoring; adding a new extractor needs raw. Size of the feature layer: to be
measured on the domain-complete sample [H: a small fraction of raw, because only ~9% of records
link to a domain].

**NFR3. Hosting.** Free tier. The app serves a precomputed, read-only scored dataset (target
<100 MB) with no paid database. Target <1 s per page when warm; a slow first load after the free
host sleeps is accepted and stated in the README.

**NFR4. Access.** HTTP basic auth over the host's HTTPS. Sample reviewer credentials are set as
host environment variables and given **only in the submission note**; the README says
"credentials provided separately". No user management.

**NFR5. Safety of the app itself.** The app lists vulnerable organisations with evidence. Escape
all record-derived text, never render banner HTML, never show raw banners. Basic auth on every
route, plus no-index (`X-Robots-Tag: noindex`, `robots.txt`).

**NFR6. Development data.** Domain-level features and scoring are developed on the
domain-complete sample (D8); the 1-in-160 line sample is for dataset-wide questions only. No raw
data, `.env`, `*.duckdb` or `*.parquet` in git.

**NFR7. Reproducibility.** Every output records the input file hash, code version and scoring
config version.

**NFR8. LLM use, if any** (decided in step 3). Accuracy and cost per run are measured and reported.
Inputs are short sanitized fields, never raw banners or HTML (prompt-injection risk). Outputs are
constrained to a schema. Results are cached per domain, so cost scales with new domains, not
with files.
