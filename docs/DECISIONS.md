# Decisions

One entry per decision: decision, options considered, why, date.

## D1. Primary user and use cases (2026-10-27)
- **Decision**: The primary user is the SDR. There are four use cases: UC1 work my ranked list,
  UC2 understand why an account ranks, UC3 run a play, UC4 see what's new. UC4 is designed but
  not demoed. Details: `docs/design/use-cases.md`.
- **Options**: SDR vs AE vs sales manager as primary user; region/territory as the organising
  idea of UC1.
- **Why**: SDRs do the research and first contact, which is where a ranked, evidenced list pays
  off. Territory is not in the brief and the data supports it poorly (D4). UC4 needs two
  snapshots and we have one.

## D2. "Why now" in a single snapshot (2026-10-27)
- **Decision**: The MVP shows timing evidence from the one file: cert expiring within 30 days,
  KEV-flagged (actively exploited) potential CVEs, and, if they pass validation in step 3,
  recently published CVEs and recently-EOL products. Production adds `first_seen` / `last_seen`
  per finding for "new since last scan".
- **Options**: change-over-time only (impossible with one file); simulate a second snapshot
  (rejected as misleading); in-snapshot timing signals.
- **Why**: These are true "act now" reasons that exist today. The record has no CVE publication
  date, and CVE-2026-* IDs look inflated (39k of 127k hits in sample), so CVE recency stays
  [H]. EOL recency needs a static lifecycle reference (EOL dates are not in the file).

## D3. Account key and naming (2026-10-27)
- **Decision**: The account is the registrable domain, shown with a resolution-confidence label
  (scan hostname > non-wildcard cert CN > named PTR > `http.host`). A display name is shown only
  when it passes a filter (not an error/default title, not a vendor cert `O`); otherwise none.
  No external company enrichment.
- **Options**: `org` field; cert `O` / page title as name; external enrichment (WHOIS, firmographic
  APIs).
- **Why**: `org` is the customer on at most ~5-13% of records. Cert `O` is on 1.5% and mostly
  vendors. ~20% of titles are error/default pages. The brief makes the dataset the core, and
  enrichment adds cost and a dependency.

## D4. Country filter, not territory (2026-10-27)
- **Decision**: Add a simple "country" filter with its source labelled: IP country of the
  account's self-hosted (non-CDN/cloud-edge) assets, or ccTLD. It is not part of UC1's headline.
- **Options**: territory as UC1's organising idea; ccTLD first; cut entirely.
- **Why**: Region is not in the brief. Most domains are `.com`, so the ccTLD rarely helps. Raw IP
  geo is skewed by CDN/cloud edges (SG 30.6% of records). After edge exclusion, IP country is a
  reasonable proxy.

## D5. Hand-off and out-of-scope features (2026-10-27)
- **Decision**: Include CSV export of the filtered list. Exclude CRM push, external enrichment,
  contact discovery and outreach drafting.
- **Options**: each of the above.
- **Why**: Export is tiny and completes UC3. The rest are outside the brief, or (outreach
  drafting) explicitly called not the interesting part.

## D6. Evidence rules (2026-10-27)
- **Decision**: Label CVEs "potential". Exclude CDN/shared-infrastructure records before
  counting findings. Treat WAF/CDN as a weak security-spend signal. Treat enterprise
  security/edge gear (Fortinet, SonicWall, Citrix) as a stronger spend signal and as attack
  surface.
- **Options**: count CVEs as-is; treat any WAF/CDN as "already buys security".
- **Why**: Verified CVEs (`opts.vulns`) are 0.03% of records. Identical CVE lists repeat across
  ~131k edge records and describe the CDN. A free Cloudflare plan says little about budget.

## D7. Industry label (2026-10-27)
- **Decision**: Use a partial industry label from TLD (`.edu`, `.gov`, `.ac.uk`, `.bank`) and
  title keywords. LLM classification is an open option for step 3, to be judged on measured
  accuracy and cost.
- **Options**: no industry; rules only; LLM classification.
- **Why**: Industry is a core ICP filter and partly derivable from the file. An LLM would show
  "how we know it's right and what it costs", but only if it measurably beats rules.

## D8. Development data (2026-10-27)
- **Decision**: Develop domain-level features and scoring on a **domain-complete sample**: the
  owner regenerates it locally once the record -> domain key is fixed, by hash-sampling ~1 in 20
  domains, keeping all of their records and dropping `http.html` and raw `data`. The existing
  1-in-160 line sample stays for dataset-wide questions only.
- **Options**: keep the line sample; full file for everything.
- **Why**: The line sample has ~1.7 records per domain, so domain-level aggregates computed on it
  are truncated. The full file takes ~13 min per pass and stays on the owner's machine.

## D9. Scale model: per-file, parallel, idempotent, then merge (2026-10-27)
- **Decision**: Each file is processed independently and in parallel, keyed by its content hash
  (re-runs and duplicate deliveries are no-ops), then merged by domain. The MVP runs one file
  locally; scale-out is design only.
- **Options**: one big batch over all files; streaming per record into a central store.
- **Why**: Files are independent. Measured 754 s per file on 8 cores means 1,000 files/month is
  ~210 machine-hours (~29% of one 8-core machine-month); compute scales linearly. Storage
  (~17.6 TB compressed per 1,000 files) is the real cost.

## D10. Raw retention (2026-10-27)
- **Decision**: In production, keep raw in cold object storage for N days and keep an extracted
  feature layer rich enough to re-score without reprocessing.
- **Options**: delete raw after extraction; keep all raw.
- **Why**: Deleting raw makes new signals impossible to backfill; keeping all raw costs tens of
  TB per month. A feature layer makes scoring changes cheap; the N-day window bounds backfill
  cost.

## D11. Coverage-aware merge (2026-10-27)
- **Decision**: On each new file a finding is new, still present, resolved (same IP:port was
  scanned and the finding is absent) or not observed (IP:port not scanned). Missing never means
  fixed.
- **Options**: treat absence as resolved; keep findings forever.
- **Why**: Each file is a partial scan. Without coverage, "resolved" would mostly mean "not
  scanned this time" and UC4 would report false improvements.

## D12. Reviewer credentials (2026-10-27)
- **Decision**: Sample credentials live in host environment variables and the submission note
  only. The README says "credentials provided separately".
- **Options**: credentials in the README.
- **Why**: The app lists vulnerable organisations with evidence; the repository may be public.

## D13. MVP priority per requirement (2026-10-27)
- **Decision**: Must: FR1, FR2a (score/tier, signal type, why-now, security gear), FR3-FR10.
  Nice: FR2b (confidence, country), FR2c (industry, depends on step 3). Design only: FR11.
- **Options**: full filter set in the MVP.
- **Why**: Deadline Fri 2026-10-30. Signals, scoring and measurement matter more than filters.

## D14. Down-weighting everywhere-CVEs (2026-10-27)
- **Decision**: Weight CVEs by EPSS and by prevalence across accounts. Prevalence is what
  handles CVE-2023-44487.
- **Options**: CVSS only; EPSS only; a hand-kept list of commodity CVEs.
- **Why**: Measured on the sample: CVE-2023-44487 sits on 1,133 of 2,909 vuln records with EPSS
  ~1.0 and KEV True, so EPSS alone would *raise* it. EPSS does down-weight the 2009-2013
  Apache list repeated on 801 records (EPSS 0.007-0.14). Formula in step 3.
