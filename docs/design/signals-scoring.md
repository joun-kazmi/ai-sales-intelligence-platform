# Signals, scoring and measurement

Status: agreed 2026-10-27, revised after two external reviews (D23-D41 in
`docs/DECISIONS.md`). **[M]** measured, **[H]** hypothesis. Data facts: `DATA_NOTES.md` 4, 5, 5b.

The score is a **research priority**: how strongly the externally observed evidence says this
account is worth an SDR's research time for an external attack surface / vulnerability management
product (vendor assumption: `use-cases.md`). It is not a breach probability.

## 1. Records to accounts (attribution)
**Name sources, in this order everywhere:** `_shodan.options.hostname` > non-wildcard
`ssl.cert.subject.CN` > `http.host` (when a name) > named PTR (`hostnames[]` that are not IP-like).
Each is reduced to its registrable domain with a pinned offline Public Suffix List snapshot, and
infrastructure domains are dropped (seeded suffix list + "PTR embeds the IP's octets" rule).
`http.host` ranks above PTR because a name there was requested by the scan; PTR is set by the IP
owner, often the hoster, and produced most ISP false positives (DATA_NOTES 4b).

**Infrastructure classes (one policy, also used by FR7 and `architecture.md`):**

| Class | Detected by | Policy |
|---|---|---|
| Shared CDN / WAF edge | `cdn` tag or org in the CDN list (Imperva / Incapsula, Cloudflare, Akamai, Fastly, CloudFront, ...) | **Dropped** unless the record itself names a non-infra domain. A kept record only adds the fact "behind <edge>" to that account; it never produces findings (its banner and CVEs describe the edge). |
| Cloud / hosting | `cloud.provider` / `cloud` tag, or org in the hosting list (Hetzner, OVH, DigitalOcean, Contabo, ...) | Direct findings count. **No via-IP attribution** (IPs are re-assigned and shared). |
| Customer appliance | Appliance list (Fortinet, SonicWall, Citrix, Ivanti, Palo Alto, F5) matched on product, title, server or cert `O` | Kept as a **fact** for filters and plays; 0 points. |

**Attribution of each kept record:**
- **direct**: the record itself names the domain (any source above). Findings count. Tagged with
  the source. A record naming several domains belongs to its first (highest-priority) one (D48).
- **via-IP**: the record names no domain, the IP has **exactly one** domain across its direct
  records, and the IP's org is neither CDN nor cloud / hosting. Findings count, tagged via-IP.
- **unresolved**: a nameless record on an IP with 2+ domains, or on a cloud / hosting IP. Not
  attributed; counted in the funnel. Direct records on such IPs still count for the domain they
  name.

**Attribution label shown in the app:** High = direct via scan hostname or cert CN; Medium =
direct via `http.host` or PTR; Low = via-IP. C1 (section 4) measures each label.

**Domain-complete dev sample (D8, D43).** Built in three steps, by `salesintel-sample`:
1. Build the **full IP -> candidate-domain index** from the full file's feature layer (every
   non-infra candidate domain named by any record on each IP).
2. Sample domains with a **stable hash**: keep a domain when
   `int.from_bytes(blake2b(domain, digest_size=8)) % 20 == 0` (`hashlib.blake2b`; Python's
   `hash()` is salted per process and is not reproducible).
3. Write every record of any IP on which a kept domain appears directly, minus `http.html` and raw
   `data`, and **carry each IP's full candidate-domain count** from the index into each sampled
   record (`_sample.ip_domain_count`). Attribution uses the carried count, so an IP that is shared
   in the full file stays shared (unresolved for via-IP) in the sample even when only one of its
   domains was sampled.

## 1b. Prospect eligibility (a filter, not part of the score; D34)
Each account gets one rule-based label, shown in the list and used as a filter. The default view
hides **likely non-prospect**. It never changes the research-priority score.

| Label | Rules (first match wins) |
|---|---|
| Likely non-prospect | Dynamic DNS suffix (`duckdns.org`, `no-ip.*`, `ddns.net`, `synology.me`, `myfritz.net`, ...); parked (every title is a parking page); **hosting provider's customer servers** (5+ IPs and at least half of the account's own hostnames are numbered, e.g. `s1760765.<hoster>`); reverse-DNS zone (named only by PTR, 5+ IPs, and no IP's org matches the domain); residential / consumer (named only by PTR on a residential or mobile network) |
| Likely org | Institutional TLD (`.edu`, `.gov`, `.mil`, `.ac.uk`, `.gov.uk`, ...); operates its own network (the domain's name appears in its IPs' org, e.g. walmart.com on "Wal-Mart Stores"); cert `O` that is not a vendor default; linked through the scan hostname (a public web property) |
| Uncertain | Everything else |

Thresholds and lists live in `src/salesintel/pipeline/scoring.toml`. Measured on the sample: 72%
of accounts stay "uncertain"; the rules only settle the clear cases (DATA_NOTES 5c).

## 2. Signals and points
Points count once per finding type per account unless stated. Evidence wording for CVEs:
"potential match to a known-exploited CVE (CVE-…) in nginx 1.18.0, observed on 2026-10-26". A CVE
that Shodan verified (listed in `opts.vulns`, or `verified: true`; 44 of 126,814 hits in the line
sample [M]) is labelled **verified** instead of "potential" (D35). Points are the same.

| Family | Finding | Points |
|---|---|---|
| Exposure | Exposed remote access / database / ICS service, detected by **Shodan module**, never port alone. Modules seen in the sample [M]: `rdp`, `rdpeudp`, `smb`, `telnet`, `mysql`, `ms-sql`, `postgresql`, `mongodb`, `redis`, `memcache`, `couchdb`, `oracle-tns`, `modbus`, `s7`, `dnp3`, `ethernetip`, `bacnet`, `fox`. Also the **Docker API (port 2375), only when the module confirms it**. VNC / Elasticsearch / Docker module names to confirm on the full run. Not counted when the identified product is a generic SSH / FTP / HTTP / proxy server (D55). | 45 (Tier 2 alone; Tier 1 with one more finding, D50) |
| Software, **per product + version** | At most one CVE award: potential known-exploited CVE (`kev` true) **25**, OR potential CVE with EPSS >= 0.1 and CVSS >= 7 **15**. Plus end-of-life (`eol-product`) **15**. Capped at **30 per product**. | 0-30 per product |
| Software, OS | End-of-life operating system (`eol-os` tag; 0.04% of records [M]) | 5, once per account, inside the account cap |
| Software, account cap | Sum over products capped at **40** (potential, unverified matches never outweigh more than one observed exposure plus a little) | <= 40 |
| Neglect (cap 10) | Expired cert 5; deprecated TLS 3; self-signed cert on a public name 3; server version disclosed 2; HTTPS without HSTS 2 | <= 10 |
| Facts, 0 points | Customer appliance; login / admin / DevOps panel; behind CDN / WAF | filters and plays only |
| Why-now markers, 0 points | Potential known-exploited CVE; CVE published in 2026 (CVE-2026-* ID); cert expires within 30 days of the scan | shown, not scored |

Rules:
- **Ubiquitous CVEs** (D26, D47) award 0 and trigger no marker. The documented list is
  `src/salesintel/pipeline/ubiquitous_cves.txt`: every CVE that matches >= 90% of the observed
  CVE-bearing versions of a product with >= 50 attributed accounts (version-independent: it only
  says "runs this product"), measured on the domain-complete sample (54 CVEs: the 2009-2013
  Apache module list, the newest CVE-2026 Apache / OpenSSH batch). CVE-2023-44487 was on it
  provisionally and was taken off (D49): it is version-dependent (61% of nginx accounts), like
  CVE-2024-38475 for Apache. A share-of-accounts cut-off was rejected: prevalence
  falls smoothly and the prevalent CVEs that award points are mostly real patch lag.
- **CVE-2026-\* IDs** are scored like any other CVE, from the record's own CVSS / EPSS / KEV
  (spot-checked as genuine, DATA_NOTES 5b, D42). They also show a 0-point why-now marker,
  "CVE published in 2026" (the ID year is the reservation year, so it cannot predate 2026).
- **Certificate state** is exactly one of: **expired** (neglect, 5) / **expires within 30 days of
  the scan** (why-now marker, 0) / **ok**. Per certificate; an account shows the expired finding if
  any cert is expired and the marker if any cert is in the 30-day window (D38).
- **Tiers (tuned once, frozen, D50):** Tier 1 >= 55, Tier 2 40-54, Tier 3 1-39; 0 = not ranked
  (reachable through plays). Tier 1 = an observed exposure plus at least one more problem; Tier 2 =
  an exposure alone, or several independent problems (software at the 40 cap, or a known-exploited
  match on end-of-life software plus heavy neglect); Tier 3 = a single patch-lag match and minor
  findings. Fixed thresholds, so tiers mean the same in every monthly file.
- **Deterministic order:** score desc, then number of distinct findings desc, then domain asc. The
  baselines in section 4 use the same tie-break.
- Every finding renders one sentence with its points and evidence; the breakdown sums to the score.
- Weights live in a versioned config (FR8). They are **frozen before labelling** (section 4).

**Worked example (hypothetical accounts; shows the tier order is sensible):**

| Account | Evidence | Points | Score | Tier |
|---|---|---|---|---|
| A | nginx 1.18.0 with a potential known-exploited CVE (25) and EOL (15) -> 30; OpenSSH 7.4 with a likely-exploitable potential CVE (15); software cap 40; expired cert (5), deprecated TLS (3) | 40 + 8 | 48 | 2 |
| B | Exposed MongoDB (module `mongodb`), nothing else | 45 | 45 | 2 |
| B+ | B plus OpenSSH 7.4 with a likely-exploitable potential CVE | 45 + 15 | 60 | 1 |
| C | Apache 2.4.58 with a potential known-exploited CVE; HTTPS without HSTS | 25 + 2 | 27 | 3 |
| D | nginx 1.24.0 whose only strong CVE is CVE-2023-44487 (KEV, version-dependent); version disclosed, no HSTS | 25 + 4 | 29 | 3 |
| E | Fortinet appliance, VPN login page, cert expiring in 12 days | 0 (facts + marker) | 0 | not ranked; in the edge-appliance play with a why-now marker |

Why this order is sensible: B+ is the only Tier 1, because an observed exposure is corroborated
by a second, independent problem. A (several potential exploitable matches plus neglect) and B (one
observed exposure) are strong but single-kind evidence: Tier 2. C and D are each one web server
behind on a patch: Tier 3, ordered by their small neglect findings. E is a sales fact (attack
surface, existing security spend), not evidence of need, so it lives in a play.

## 3. Feature schema: scoring rules to retained fields
The feature layer keeps these fields per filtered record (no `http.html`, no raw `data`).

| Rule | Retained fields |
|---|---|
| Attribution (section 1) | `ip_str` / `ipv6`, `_shodan.options.hostname`, `ssl.cert.subject.CN`, `http.host`, `hostnames[]`, `domains[]`, `org`, `isp`, `asn`, `cloud.provider`, `tags` |
| Exposed service | `_shodan.module`, `port`, `transport`, `tags` (`honeypot` excluded upstream), `docker` sub-object if present |
| Software awards | `product`, `version`, `cpe23`, `vulns{CVE: cvss, cvss_version, epss, kev, ransomware_campaign, verified}`, `opts.vulns` (verified list) |
| End-of-life | `tags` (`eol-product`, `eol-os`), `product`, `version` |
| Neglect | `ssl.cert.expired`, `ssl.cert.expires`, `ssl.cert.issued`, `ssl.cert.subject` / `issuer` (self-signed), `tags` (`self-signed`), `ssl.versions`, `http.headers` (HSTS flag only), `http.server` (version disclosure) |
| Why-now markers | `vulns.*.kev`, `ssl.cert.expires`, `timestamp` |
| Prospect eligibility | name candidates and sources, `hostnames[]`, `org`, `isp`, `http.title` (filtered, truncated), `http.server`, `ssl.cert.subject.O`, `tags` |
| Facts (appliance, panel, CDN / WAF) | `product`, `http.title` (filtered, truncated), `http.server`, `ssl.cert.subject.O`, `http.waf`, `tags` (`cdn`) |
| Provenance and coverage | `timestamp`, `_shodan.id`, `_shodan.crawler`, `_shodan.module`, `hash`, input file hash |

## 4. Measuring whether it works (FR10)

| # | Question | Method | Manual work |
|---|---|---|---|
| C1 | How often do links agree with DNS? | **Forward DNS match rate, automated**: share of links where the domain or hostname resolves to the record's IP today, per attribution label and source. A match supports a link but does not prove ownership (shared hosting); a miss does not disprove it (re-assigned cloud IPs). Hand-check ~30 misses. Audit only, run on the owner's machine (D39). | ~30 checks |
| C2 | Does the ranking beat a simpler sort? (headline) | **Weights frozen first** (config version recorded). Pool = our top 20 + top 20 by highest CVSS + 20 random accounts, deduplicated (<= 60), all drawn from the same eligible set (default eligibility filter), so the comparison isolates the scoring. Shown **blind** (shuffled; evidence only, no score, rank or source). Label: worth a call / not / unknown. Report **precision@20** for ours, highest-CVSS and random (unknowns excluded and counted) (D37). | Owner labels <= 60 |
| C4 | Is the ranking fragile? | Perturb each weight ±25%; report top-20 overlap and rank correlation, with the deterministic tie-break. | none |
| C5 | Does this month's score predict next month's new exposures? | Needs FR11 and two files. | Design only |

Cut: C3 (KEV lift), the LLM labeller (D28) and the most-CVEs baseline (D37).

**Evidence v2 (D59).** Run 1 showed that evidence ordered by IP hid the decisive records of large
accounts. The sheet now orders records worst-first by a fixed rule independent of our weights (any
KEV CVE, highest CVSS, risky exposed service from the module list, expired cert, then IP / port),
collapses identical lines with a count, and keeps the 12-line cap and "potential" / "verified"
wording. `build --from <run 1>` keeps run 1's pools, ids and order, copies labels where the
evidence is unchanged up to ordering, and blanks the rest for relabelling. `evaluate` adds a strict
precision (worth_a_call AND own_asset = yes) and human-vs-AI agreement per question.

## 5. LLM use
**One use, in evaluation only (D57): an AI second rater for C2.** `salesintel-labelpool ai-label`
sends each pooled account's neutral evidence (from `labels.csv`, never `key.json`) to the latest
Claude Sonnet with the same four-question rubric, through structured output. The evidence is
delimited as untrusted data and the model is told to ignore instructions inside it. It writes
`ai_labels.csv` and `ai_run.json` (model, prompt hash, tokens, cost in USD). `evaluate --rater
human|ai` reports precision@20 from either sheet, plus human-vs-AI agreement on worth_a_call
(percent agreement, Cohen's kappa) over the rows the human labelled. Server-side refusal fallbacks
are off so the rater's model never changes mid-run; a refusal is counted and labelled "unknown".
The AI cannot browse, while the human may look a domain up: an asymmetry stated with the result.
A second provider (D58), `--provider openai`, calls any OpenAI-compatible endpoint (OpenRouter by
default, NVIDIA, ...) with the same rubric, delimiting and injection handling, `temperature 0` and
`response_format: json_schema` (falling back to `json_object` plus Pydantic validation when a
provider rejects it). Cost is OpenRouter's reported `usage.cost` when present, else computed from
`--price-in/--price-out`, else recorded as unknown. Both providers retry 429 / 5xx with backoff and
save progress after every row; a rerun resumes.

**Nothing in the pipeline or the app.** The account classifier (display name, industry,
real business vs ISP / hoster / personal / parked) stays design only; the MVP uses TLD and keyword
rules, which are first in the cut order if time slips. If it is ever built: measure accuracy on free
TLD labels (`.edu`, `.gov`, `.ac.uk`, `.mil`, TLD hidden) plus owner checks, log real token cost,
cache per domain. Never raw banners to a model; never an LLM inside scoring.
