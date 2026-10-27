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

## D2. "Why now" in a single snapshot (2026-10-27, amended after step 3)
- **Status**: CVE-2026 handling superseded by D42 (2026-10-27).
- **Status**: partly superseded by D25 (cert expiring is a marker with 0 points) (2026-10-27, external review).
- **Decision**: The MVP's why-now markers are: cert expiring within 30 days (+5 points) and a
  KEV-flagged (actively exploited) potential CVE (marker only; its points count once, under
  Exposure, D16). "Published this year" (CVE-2026-* IDs) is off, with 0 points, until a spot-check
  against cve.org confirms the IDs; if they are real it comes back. "Recently went end-of-life"
  is cut: the MVP shows "end-of-life" as a finding only. Production adds `first_seen` /
  `last_seen` per finding for "new since last scan" (D11).
- **Options**: change-over-time only (impossible with one file); simulate a second snapshot
  (rejected as misleading); in-snapshot timing signals; CVE recency via an NVD join; an EOL
  lifecycle table.
- **Why**: These are true "act now" reasons that exist in the file. Records have no CVE
  publication date. An ID's year is its reservation year, so CVE-2026 is a valid one-sided
  marker, but 31% of CVE hits carry such IDs with numbers up to ~110,000 and they are not yet
  verified. EOL dates are not in the file, 90% of EOL tags are nginx, and versions are on 6.5% of
  records, so "recently EOL" would add a reference table for little coverage.

## D3. Account key and naming (2026-10-27)
- **Status**: resolver order superseded by D29 (2026-10-27, external review).
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
- **Status**: superseded by D29 (country filter cut) (2026-10-27, external review).
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
- **Status**: sampling method superseded by D43 (2026-10-27).
- **Status**: sample key refined by D23 (2026-10-27, external review).
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
- **Status**: superseded by D26 (2026-10-27, external review).
- **Decision**: Weight CVEs by EPSS and by prevalence across accounts. Prevalence is what
  handles CVE-2023-44487.
- **Options**: CVSS only; EPSS only; a hand-kept list of commodity CVEs.
- **Why**: Measured on the sample: CVE-2023-44487 sits on 1,133 of 2,909 vuln records with EPSS
  ~1.0 and KEV True, so EPSS alone would *raise* it. EPSS does down-weight the 2009-2013
  Apache list repeated on 801 records (EPSS 0.007-0.14). Formula in step 3.

## D15. Entity resolution (2026-10-27)
- **Status**: superseded by D23 and D24 (2026-10-27, external review).
- **Decision**: Two passes. Pass 1 picks candidate names per record (scan hostname > cert CN >
  `http.host` > non-IP-like PTR), reduces them to registrable domains and drops infrastructure
  domains (seeded list + "PTR embeds the IP" rule). Pass 2 assigns each IP with one surviving
  domain, with all its records, to that account. Shared-hosting IPs (> K domains) and CDN edges
  give tenants no findings. Confidence: High / Medium / Low by method. Details:
  `docs/design/signals-scoring.md` section 1.
- **Options**: per-record assignment only; `org` as the key; external enrichment.
- **Why**: Per-record assignment loses nameless banners (RDP, DB) on named IPs. Shared and CDN
  IPs would attribute the host's exposure to every tenant.

## D16. Scoring model (2026-10-27)
- **Status**: superseded by D25 (2026-10-27, external review).
- **Decision**: Transparent additive points per finding type (Exposure 8-30, Neglect capped at
  15, cert-expiring +5). KEV counts once, under Exposure, and also shows as a why-now marker.
  CVE-2026 IDs score 0 until verified. Prevalence discount 0.2x above ~10% of CVE-bearing
  accounts. No WAF/CDN discount. Fixed tier thresholds (start: T1 >= 40, T2 20-39).
- **Options**: ML model; CVSS-sum; percentile tiers; WAF discount.
- **Why**: No labels to train on. Every point must be explainable to a prospect. Fixed thresholds
  keep tiers comparable across monthly files. CDN-fronted accounts are under-observed, not safe.

## D17. Measurement plan (2026-10-27)
- **Status**: superseded by D28 (2026-10-27, external review).
- **Decision**: C1 forward-DNS confirmation of IP->domain links (automated, audit only) plus ~30
  hand checks. C2 pooled labelling and precision@50 vs max-CVSS, CVE-count and random baselines
  (headline). C3 KEV lift of a KEV-free score. C4 ±25% weight sensitivity. C5 design only. One
  `eval` command gates scoring changes.
- **Options**: manual audit of links; labelling only our own top-k; no baselines.
- **Why**: DNS removes most manual checking. Pooling lets every ranking be judged on the same
  labels. Beating "highest CVSS first" is the evidence that the signal work added value.

## D18. LLM use (2026-10-27)
- **Status**: superseded by D28 (2026-10-27, external review).
- **Decision**: MVP uses one LLM: the C2 labelling assistant (`claude-opus-5-5`), measured by
  Cohen's kappa against 60 owner labels, cost from real token usage. The account classifier is
  design only; MVP uses TLD/keyword rules; build the LLM version only if time remains. No LLM in
  scoring; never raw banners to a model.
- **Options**: labelling assistant + classifier; classifier only; no LLM.
- **Why**: One well-measured use answers "how you know it's right and what it costs". The
  classifier adds build and evaluation work before Friday.

## D19. Pipeline architecture and feature layer (2026-10-27)
- **Decision**: Offline pipeline extract -> resolve -> score -> eval, run locally in the MVP. In
  production: extract per file on stateless workers, then merge -> resolve -> score on merged
  state. The feature layer keeps all filtered records (nameless ones too) with projected fields,
  no `http.html` / raw `data`. CDN edge records without a non-infra name are dropped at extract.
  Details: `docs/design/architecture.md`.
- **Options**: resolve per file; keep only domain-linked records in the feature layer.
- **Why**: An IP's cert and its RDP banner can arrive in different files, so per-file resolve
  would miss links. Nameless records join accounts through their IP. Edge IPs are shared and never
  assigned by IP, so their nameless records can never join an account. Feature-layer size vs raw
  is [H] until measured on Wednesday.

## D20. Hosting and artifact delivery (2026-10-27)
- **Decision**: Render free web service from the private repo. The scored artifact is a private
  GitHub Release asset, downloaded at app startup with a fine-grained read-only token for this
  repo, kept in Render env vars. Never in git. The README notes that Render's free disk is
  ephemeral, so each cold start re-downloads the artifact. A bare deploy (hello world, basic auth,
  noindex) goes live first, on Wed AM.
- **Options**: artifact in git or in the Docker image; public release; other free hosts.
- **Why**: The artifact lists vulnerable organisations (NFR5); keeping it out of git holds even
  with a private repo and reviewers as collaborators. Deploying early removes hosting risk before
  the app exists.

## D21. MVP scope (2026-10-27)
- **Decision**: In scope and cuts as listed in `docs/design/mvp.md`.
- **Options**: wider filters, LLM classifier, production orchestration in the MVP.
- **Why**: Deadline Fri 2026-10-30. Signals, scoring and measurement come first (brief).

## D22. Implementation order (2026-10-27)
- **Decision**: Hosting first (bare deploy), then the record -> domain key (it unblocks the owner's
  sample build), then scoring, eval, the full app, the full run, write-up.
- **Options**: pipeline first, deploy on Thursday.
- **Why**: Hosting and the sample build are the two dependencies outside the code; both are
  cleared on Wednesday.

## D23. Attribution: direct vs via-IP (2026-10-27, external review)
- **Decision**: Every finding is tagged **direct** (the record itself names the domain) or
  **via-IP**. Via-IP counts only if the IP has exactly one domain and its org is not CDN or
  cloud / hosting. IPs with 2+ domains are unresolved for nameless records. No shared-hosting
  threshold K. The dev sample keeps every record of IPs on which a sampled domain appears directly.
- **Options**: assign whole IPs to a dominant domain; a K-domain shared-hosting threshold.
- **Why**: A K threshold has no principled value, and a wrong IP link puts another company's
  exposure on an account. Requiring a single domain and a non-hosting org keeps via-IP links to
  the cases where they are most likely right; C1 measures them.

## D24. Three infrastructure classes (2026-10-27, external review)
- **Decision**: Shared CDN / WAF edge: dropped unless the record names the domain, and then only a
  "behind <edge>" fact, never findings. Cloud / hosting org: direct findings count, no via-IP.
  Customer appliance: kept as a fact, 0 points. The same policy in `architecture.md`, FR7 and
  `signals-scoring.md`.
- **Options**: one "infra" class dropped wholesale; per-doc variants.
- **Why**: The three cases differ: edge banners describe the CDN; hosting IPs carry real customer
  software but are shared and re-assigned; appliances are customer-owned facts. One stated policy
  removes contradictions between docs.

## D25. Scoring revision (2026-10-27, external review)
- **Status**: extended by D35, D36, D38 (2026-10-27, second external review).
- **Status**: tier thresholds superseded by D50 (2026-10-28).
- **Decision**: Exposed remote access / DB / ICS detected by Shodan module (not port) scores 45
  and reaches Tier 1 alone. Per product + version: at most one CVE award (potential KEV 25, or
  EPSS >= 0.1 and CVSS >= 7 15) plus EOL 15, capped at 30 per product; software total capped at
  40 per account. Neglect capped at 10. Appliances, login / admin panels: 0 (filters and plays).
  Cert expiry and KEV are why-now markers with 0 extra points. Tiers T1 >= 45, T2 25-44, T3 1-24;
  deterministic tie-break. CVE wording: "potential match to a known-exploited CVE, observed on
  <date>". Worked 5-account example in `signals-scoring.md`.
- **Options**: the D16 point table; port-based detection; per-CVE awards.
- **Why**: Per-CVE awards let one long version-matched list dominate. Ports alone mislabel
  services. Appliances and panels are attack surface and sales facts, not evidence of need. The
  40 software cap is our addition: without it, an outdated server running three products
  outranks an exposed database on unverified matches alone.

## D26. Ubiquitous CVEs (2026-10-27, external review)
- **Decision**: Replace the 10% prevalence rule with a documented ubiquitous-CVE list (award 0).
  Provisional: CVE-2023-44487. Measure each CVE's share of attributed CVE-bearing accounts on
  Wednesday; extend the list only with measured outliers, recorded in DATA_NOTES.
- **Options**: 10% prevalence discount; IDF weighting.
- **Why**: Prevalence must be measured after attribution (before it, CDN duplicates dominate).
  If one CVE is the problem, a named list is simpler to explain than a threshold.

## D27. Vendor assumption and buyer roles (2026-10-27, external review)
- **Decision**: Assume the vendor sells external attack surface / vulnerability management. The
  score is a "research priority" for that product. Each play names a buyer role (`use-cases.md`
  UC3).
- **Options**: leave the product unstated.
- **Why**: External scan data can only evidence external exposure; naming the product makes the
  score's meaning and the plays' audience explicit.

## D28. Evaluation revision (2026-10-27, external review)
- **Status**: pool and k superseded by D37; C1 metric renamed by D39 (2026-10-27, second external review).
- **Decision**: Freeze weights before labelling. Up to 60 human labels: union of the top 15 from
  our ranking, top 15 by max CVSS, top 15 by CVE count, plus 15 random; shown blind, "unknown"
  allowed. Report precision@15 per ranking. Keep C1 (forward DNS) and C4 (±25% at k=15,
  deterministic tie-breaks). Cut the LLM labeller and C3. No LLM in the MVP.
- **Options**: D17/D18 (pooled top 50, LLM labeller with kappa, C3 lift).
- **Why**: Labels collected after tuning would measure the tuning, not the ranking. A small blind
  human set is cleaner than LLM labels calibrated against 60 human ones. Precision@15 matches the
  label budget.

## D29. Country filter cut; one resolver order (2026-10-27, external review)
- **Decision**: Cut the country filter. Name-source order everywhere: scan hostname >
  non-wildcard cert CN > `http.host` > named PTR.
- **Options**: keep country as a nice-to-have; DATA_NOTES' earlier order (PTR before
  `http.host`).
- **Why**: Country is not in the brief. Docs disagreed on the order. `http.host` was requested by
  the scan; PTR is set by the IP owner (often the hoster) and caused most ISP false positives.

## D30. Feature schema (2026-10-27, external review)
- **Decision**: The feature layer keeps exactly the fields mapped to scoring rules in
  `signals-scoring.md` section 3 (including `http.server`, verification flags, CVSS version and
  module).
- **Options**: an informal field list.
- **Why**: Re-scoring without reprocessing (D10) only works if every rule's inputs are retained.

## D31. Comparable re-probe for "resolved" (2026-10-27, external review)
- **Status**: the single statement of FR11 rules now lives in `architecture.md` (D40) (2026-10-27, second external review).
- **Decision**: FR11 (design only): a finding is "resolved" only if the new file re-probed the same
  IP:port with the same module and got a banner; otherwise "not observed".
- **Options**: D11's "same IP:port scanned".
- **Why**: A timeout or a different module on the same port says nothing about the finding.

## D32. Manifest and atomic writes (2026-10-27, external review)
- **Decision**: Every output carries a manifest (input file hash, extractor, blocklist, PSL
  snapshot and scoring config versions, code commit, row counts) and is written atomically (temp
  file, fsync, rename).
- **Options**: version stamps only on the final artifact.
- **Why**: Idempotent per-file processing (D9) needs to know exactly what produced each partition,
  and a crash must not leave partial outputs that look complete.

## D33. Plan revision (2026-10-27, external review)
- **Decision**: Wednesday includes the full-file extraction run and a deploy through the real
  artifact-download path. Only measured throughput is quoted. Hosted artifact hard cap 100 MB.
  Cut order if slipping: industry / display-name heuristics, extra filters, weaker signals; never
  attribution quality, evidence, the human eval, the hosted list or the write-up.
- **Options**: D22's order (full run and real deploy on Thursday).
- **Why**: Both are the largest schedule risks; finding problems on Wednesday leaves time to fix
  them.

## D34. Prospect eligibility label (2026-10-27, second external review)
- **Decision**: A rule-based label per account: likely org / uncertain / likely non-prospect
  (hoster, ISP, dynamic DNS, personal, parked). Shown in the list and used as a filter (default
  hides likely non-prospects); never part of the research-priority score. Rules:
  `signals-scoring.md` 1b.
- **Options**: fold eligibility into the score; rely on the blocklist alone.
- **Why**: "Is this a company we can sell to" and "how much does it need help" are different
  questions. Mixing them hides why an account ranks. The blocklist cannot catch every ISP, dynamic
  DNS or parked domain that survives attribution.

## D35. Verified CVE label (2026-10-27, second external review)
- **Decision**: A CVE in `opts.vulns` or with `verified: true` is labelled "verified" instead of
  "potential". Points unchanged.
- **Options**: extra points for verified CVEs; ignore the flag.
- **Why**: The wording must be true. Verified hits are rare (44 of 126,814 in the line sample), so
  extra points would add a rule for almost no accounts.

## D36. Docker API exposure and EOL OS (2026-10-27, second external review)
- **Decision**: Exposed Docker API (port 2375) counts as an exposure (45) only when the Shodan
  module confirms it. `eol-os` scores 5 once per account, inside the software cap.
- **Options**: port-only Docker detection; `eol-os` at the EOL-product weight.
- **Why**: An unauthenticated Docker API is remote code execution, but the port alone is not
  evidence. `eol-os` is rare (0.04%) and usually inferred from banners, so it gets a low weight.

## D37. Evaluation pool at k=20 (2026-10-27, second external review)
- **Decision**: Precision@20. Pool = our top 20 + top 20 by highest CVSS + 20 random,
  deduplicated, at most 60 blind human labels, all from the same eligible account set. C4 at k=20.
  The most-CVEs baseline is dropped.
- **Options**: D28 (top 15 of three rankings + 15 random).
- **Why**: The same label budget gives a larger k for the two comparisons that matter: does our
  ranking beat "highest CVSS first", and does either beat random.

## D38. Mutually exclusive certificate states (2026-10-27, second external review)
- **Decision**: Each certificate is exactly one of expired (neglect, 5) / expires within 30 days
  of the scan (why-now marker) / ok.
- **Options**: independent flags (a cert could be both "expired" and "expiring").
- **Why**: One cert must not count twice or show contradictory evidence.

## D39. C1 reports a forward-DNS match rate (2026-10-27, second external review)
- **Decision**: C1's metric is "forward DNS match rate" per attribution label and source, not
  "confirmed ownership".
- **Options**: call a DNS match a confirmed link.
- **Why**: A match does not prove ownership (shared hosting), and a miss does not disprove it
  (re-assigned cloud IPs). The name must say what was measured.

## D40. One statement of the FR11 merge invariants (2026-10-27, second external review)
- **Decision**: FR11 rules live in one paragraph in `architecture.md` ("FR11 merge invariants");
  FR11 in `requirements.md` points there.
- **Options**: restate them in requirements, architecture and decisions.
- **Why**: Repeated copies drifted once already (D11 vs D31).

## D41. DATA_NOTES section 6 superseded (2026-10-27, second external review)
- **Decision**: DATA_NOTES section 6 ("Recommended pipeline implications") is marked superseded
  by this file.
- **Options**: edit it item by item.
- **Why**: It predates the design. DATA_NOTES stays the record of measured facts; decisions live
  here.

## D42. CVE-2026 IDs scored like any other CVE (2026-10-27)
- **Decision**: CVE-2026-* IDs score through the record's own CVSS / EPSS / KEV like any other CVE,
  and show a 0-point "CVE published in 2026" why-now marker.
- **Options**: keep them at 0 points (D2); trust them without checking.
- **Why**: The owner checked four high-volume IDs via the official CVE API: all four are real,
  published 2026-10-01 to 2026-10-21 (Apache HTTP Server, OpenSSH, PHP), 5-25 days before the
  scan (DATA_NOTES 5b). The large CVE-2026 share is newly published CVEs matched against old
  versions, which is exactly the "newly vulnerable" signal. Widespread ones are handled by the
  ubiquitous-CVE list (D26), not by excluding the year.

## D43. Domain-complete sample: full index first, stable hash, carried IP counts (2026-10-27)
- **Decision**: Build the full IP -> candidate-domain index from the full feature layer first;
  sample domains with `hashlib.blake2b` (8-byte digest, `% 20 == 0`); write every record of IPs
  where a kept domain appears directly; carry each IP's full candidate-domain count into the
  sample (`_sample.ip_domain_count`), and attribution uses it.
- **Options**: D8 as written (`hash(domain) % 20`, counts computed inside the sample).
- **Why**: Python's `hash()` is salted per process, so the sample would change on every run.
  Counting domains inside the sample would make shared IPs look single-domain whenever only one
  of their domains was sampled, which would wrongly allow via-IP attribution.

## D44. Public Suffix List with the private section (2026-10-27)
- **Decision**: Registrable domains use the PSL snapshot bundled with tldextract, **including the
  private section**, offline. Infra suffixes are matched against the full hostname before PSL
  reduction.
- **Options**: ICANN section only.
- **Why**: ICANN-only reduces `alice.duckdns.org` and `shop.herokuapp.com` to `duckdns.org` and
  `herokuapp.com`, merging unrelated users into one fake account. With the private section each
  tenant stays separate, and D34's eligibility label marks dynamic-DNS hosts as non-prospects.
  Cloud PTR names (`*.compute-1.amazonaws.com`) are still dropped by the infra suffix match.

## D45. Domain-complete sample drops large non-schema fields (2026-10-27)
- **Decision**: Besides `http.html` and raw `data`, the sample builder drops large fields the
  feature schema (D30) never reads: CVE `summary` / `references`, `ssl.chain` and related TLS
  handshake detail, `http.favicon` / `sitemap` / `robots` / `securitytxt` / `components`, `tcp`.
  If the sample is still over ~45 MB, it is rebuilt with modulus 40.
- **Options**: keep full records minus html/data (D43 as written).
- **Why**: Measured on the line sample: 2,486 -> 511 compressed bytes per sampled record. The
  sample has to reach the development sandbox through git, and the full-file sample would
  otherwise be roughly 300+ MB [H]. Re-extraction from the sample still works because every
  schema field is kept.

## D46. Sample builder applies the extractor's drop rules; long-window zstd (2026-10-27)
- **Decision**: The sample builder runs every candidate record through the extractor's own
  `project()` and skips what the extractor would drop (CDN edge without a name, honeypot, noise
  modules). It writes zstd level 19 with a 2^27 window and long-distance matching, and refuses
  to run if the blocklist changed since the features were extracted.
- **Options**: re-implement the drop rules in the builder; keep level 10.
- **Why**: Measured on the full file: 308,034 of 520,923 sampled records (59%) were unnamed CDN
  edge records on sampled edge IPs, which the extractor drops anyway. Calling `project()` keeps
  the two rule sets identical by construction. The 2^27 window is the default decoder limit,
  so readers need no flags.

## D47. Ubiquitous-CVE list: version-independent CVEs (2026-10-27)
- **Status**: CVE-2023-44487 taken off the list by D49 (2026-10-28).
- **Decision**: The ubiquitous-CVE list (award 0, no marker) is every CVE that matches >= 90% of
  the observed CVE-bearing versions of a product with >= 50 attributed accounts, measured on the
  domain-complete sample (54 CVEs), plus CVE-2023-44487 (provisional). The list is a versioned
  file (`ubiquitous_cves.txt`) folded into the scoring config version.
- **Options**: CVE-2023-44487 only (D26 provisional); a share-of-accounts cut-off (e.g. 20%).
- **Why**: Measured after attribution: CVE-2023-44487 is not the only everywhere-CVE (the
  2009-2013 Apache module list sits on 39% of CVE-bearing accounts, the CVE-2026 Apache batch on
  33%+). But prevalence falls smoothly with no gap, and many prevalent CVEs that award points
  are real patch lag (CVE-2024-38475, KEV, on 58% of Apache accounts). A version-independent CVE
  says only "runs Apache"; a version-dependent one says "is behind on patches". Open: whether
  CVE-2023-44487 (61% of nginx accounts) stays on the list, since CVE-2024-38475 is similar and
  scores.

## D48. Attribution to the primary name; hoster eligibility rule (2026-10-27)
- **Decision**: A record naming several domains belongs to its first (highest-priority) name.
  Eligibility adds a "hosting provider's customer servers" rule (5+ IPs, at least half the
  account's own hostnames numbered) ahead of the likely-org rules, and "operates its own
  network" (domain name found in its IPs' org) as a likely-org rule.
- **Options**: attribute a record to every name it carries; leave hosters to the human eval.
- **Why**: Counting one banner under several accounts would double-count evidence. On the sample
  the top-ranked accounts were VPS providers whose own domain names hundreds of numbered customer
  servers (e.g. 750 IPs, 97% numbered hostnames); they own their network, so the org-match rule
  alone marked them likely-org. The hoster rule moved 28 of them out of the default Tier 1 view
  (276 -> 248).

## D49. CVE-2023-44487 scores like any other CVE (2026-10-28)
- **Decision**: Take CVE-2023-44487 off the ubiquitous-CVE list (owner's call). The list is now
  the 54 measured version-independent CVEs only.
- **Options**: keep it listed (D26 provisional).
- **Why**: It is version-dependent (nginx < 1.25.3, 61% of nginx accounts), exactly like
  CVE-2024-38475 for Apache (58%), which scores; listing one and not the other was inconsistent.
  Measured effect (sample, old tiers): Tier 2 +40%, half of Tier 2 resting on this CVE alone,
  which D50 addresses.

## D50. Tier thresholds 55 / 40, tuned once and frozen (2026-10-28)
- **Decision**: Tier 1 >= 55, Tier 2 40-54, Tier 3 1-39. Tier 1 = an observed exposure plus at
  least one more problem; Tier 2 = an exposure alone or several independent problems; Tier 3 = a
  single patch-lag match and minor findings. Points are unchanged. This was the one tuning round;
  the scoring config is **frozen at `765eef67e0c5`** (scoring.toml + ubiquitous list) before
  labelling, and a test pins that version.
- **Options**: 45 / 25 (D25): Tier 1 ~5,000 and Tier 2 ~45,000 on the full file; 55 / 30: Tier 2
  still ~35,000, mostly "one known-exploited match on end-of-life software"; 50 / 30.
- **Why**: With 45 / 25, Tier 1 was 6,070 accounts on the full file, too many to be a top tier
  for an SDR, and Tier 2 was "one web server behind on a patch". 55 / 40 gives ~1,100 / ~6,000 on
  the full file [H, x20 from the sample], and each tier has one plain meaning. An exposure still
  reaches Tier 1 with corroboration; unverified software matches alone never do, consistent with
  the software cap.

## D51. Bounded memory for scoring (2026-10-28)
- **Decision**: Attribution uses views streamed from Parquet instead of materialized tables, and
  scoring runs DuckDB with `memory_limit` (default 6 GB, `--memory-limit`) and a spill directory
  (`<out dir>/.duckdb_tmp`, gitignored under `out/`).
- **Options**: buy headroom with a bigger machine; score in chunks of domains.
- **Why**: The full-file score peaked at 13.5 GB on a 15 GB machine: the feature layer was held
  in memory twice. On the sample the change cut the peak from 1,094 to 750 MB with identical
  output; the full-file peak is re-measured on the next run.

## D52. C2 label pool: neutral evidence, hashed tie-break, built from the full artifact (2026-10-28)
- **Decision**: The blind sheet shows the same neutral evidence for every pooled account, built
  from the feature layer (services, products / versions, top CVEs by CVSS with KEV / EPSS, cert
  state, TLS, how the domain was linked), never our finding sentences, score, tier, rank or list.
  The "highest CVSS" baseline breaks its many CVSS-10.0 ties by a seeded hash, not alphabetically.
  The pool is built from the published full-file artifact (`data-v1`) with the frozen config.
  The key is a separate file; the sheet is never overwritten once created.
- **Options**: show our findings; sort ties by domain; build from the sample.
- **Why**: Our sentences are curated by the pipeline under test, so showing them would favour our
  list. Alphabetical ties would skew the baseline. The shipped ranking is the full-file one.

## D53. C4 measured on the domain-complete sample (2026-10-28)
- **Decision**: Run C4 (each point weight +/-25%) on the sampled domains of the domain-complete
  sample, default view, frozen config.
- **Options**: run on the full file (20 rescoring runs over 1.4M attributed rows).
- **Why**: Attribution and eligibility do not depend on point weights, so the sample answers the
  question in 34 s. Result [M]: top-20 overlap >= 0.85 and Spearman >= 0.9993 in every run
  (DATA_NOTES 5c). Caveat: the 2-point weights round back to 2 at +/-25%, so those runs are
  no-ops.

## D54. C4 moves small weights by one point (2026-10-28)
- **Decision**: In C4, a weight that rounds back to itself at +/-25% (the 2-point `version_disclosed`
  and `no_hsts`) is moved by +/-1 point instead; each run records which rule applied.
- **Options**: report the no-op runs as they were; use fractional points.
- **Why**: A perturbation that changes nothing tests nothing. Points are integers in the config, so
  one point is the smallest real change. Result: top-20 overlap >= 0.95 and Spearman >= 0.9971 for
  those runs (DATA_NOTES 5c).

## D55. Exclude false exposures, after the evaluation (2026-10-28, planned)
- **Decision**: An exposed-service finding counts only when Shodan's identified product is absent
  or is not a generic SSH / FTP / HTTP / proxy server (e.g. `rdp` answered by OpenSSH does not
  count). Applied **after** the C2 labels are evaluated against the frozen `data-v1`, as an
  evidence-correctness fix with a new config version; the owner rescores and publishes `data-v2`.
  The write-up reports how many of our top 20 had a false exposure.
- **Options**: fix now (would change the ranking under a pool already being labelled); leave it.
- **Why**: About 3.4% of exposure findings on the sample name a service that did not answer
  (DATA_NOTES 5c). Evidence must be true, but the evaluation must measure the ranking that was
  frozen before labelling.

## D56. App DuckDB connection capped at 256 MiB and 2 threads (2026-10-28)
- **Decision**: The app's read-only connection uses `memory_limit = 256MiB`, `threads = 2`; a test
  checks both settings.
- **Options**: default settings; a smaller artifact.
- **Why**: Measured 325 MB RSS after full-artifact CSV exports on the owner's machine; DuckDB sizes
  its defaults from host RAM and cores, not the 512 MB Render container.
