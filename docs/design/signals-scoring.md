# Signals, scoring and measurement

Status: agreed 2026-10-27. Decisions D15-D18 in `docs/DECISIONS.md` (D2, D14 also apply).
**[M]** measured, **[H]** hypothesis. Sample facts: `DATA_NOTES.md` sections 4, 5, 5b.

## 1. Records to accounts (entity resolution, D15)
The account key is the registrable domain (D3). Two streaming passes over a file.

**Pass 1, per record: candidate names.**
1. Candidates, best first: `_shodan.options.hostname` > non-wildcard `ssl.cert.subject.CN` >
   `http.host` when it is a name > `hostnames[]` that are not IP-like.
2. Reduce each to its registrable domain with a pinned offline Public Suffix List snapshot.
3. Drop infrastructure domains:
   - a seeded list of CDN / cloud / hosting / ISP suffixes (from the top `org` values and PTR
     zones in DATA_NOTES 4);
   - data-driven: a domain whose hostnames mostly embed the IP's own octets is an ISP / hoster
     PTR zone.
4. Pre-filter records: `honeypot` tag, noise modules (`nodata-tcp`, `x11`,
   `language-server-protocol`, `ike`).

**Pass 2, per IP: assignment.**
- An IP with exactly one surviving domain belongs to that account, **with all its records** (a
  nameless RDP banner joins through the same IP's certificate).
- An IP with more than K distinct domains is **shared hosting**. Its findings belong to the hoster;
  tenants get a "hosted on a shared server" note and no findings from it. K is set from the
  distribution on the domain-complete sample.
- CDN / WAF edge records (CDN org class or `cdn` tag) contribute only "behind WAF/CDN", never
  CVEs or ports.

**Confidence label.**
| Label | Rule |
|---|---|
| High | scan hostname or cert CN, on an IP no other domain uses |
| Medium | named PTR, on an IP no other domain uses |
| Low | `http.host` only, or a dominant-but-not-sole domain on the IP |

**Domain-complete dev sample (D8).** Keep a domain when `hash(domain) % 20 == 0`, together with
every record of the IPs assigned to it; drop `http.html` and raw `data`. Built by the owner
locally with the pass 1 + pass 2 code (about 2 x 13 min). Expected 5-15k accounts [H].

## 2. Signals and points (D16)
Points count **once per finding type per account**, not per record. A finding on an outdated
product counts once per product + version, whatever the length of its CVE list (2,909 vuln records
collapse to 291 product-version pairs in the sample [M]).

| Family | Finding | Points |
|---|---|---|
| Exposure | Exposed remote access / database / ICS: RDP, SMB, Telnet, VNC, WinRM, MySQL, MSSQL, Postgres, Mongo, Redis, Elasticsearch, Memcached, Modbus, S7 | 30 |
| Exposure | Actively exploited potential CVE (`kev` true), after the prevalence discount | 25, +5 if `ransomware_campaign` = Known |
| Exposure | Outdated product with a likely-exploitable potential CVE (EPSS >= 0.1 and CVSS >= 7) | 15 |
| Exposure | End-of-life product (`eol-product` tag) | 15 |
| Exposure | Exposed edge / security appliance (Fortinet, SonicWall, Citrix, Ivanti, Palo Alto, F5) | 10 |
| Exposure | Exposed admin / login / DevOps panel | 8 |
| Neglect (family capped at 15) | Expired cert; deprecated TLS; self-signed cert on a public name; server version disclosed; HTTPS without HSTS | 3-5 each |
| Why now | Cert expires within 30 days of the scan | +5 |

Rules:
- **KEV counts once.** A KEV CVE earns its Exposure points (25 / 30) and shows the why-now
  marker, with no extra why-now points.
- **CVE-2026-\* IDs score 0** and show no marker until verified (D2, DATA_NOTES 5b).
- **Prevalence discount (D14).** A CVE present on more than ~10% of the accounts that have any
  CVE keeps 0.2x its weight. This is what handles CVE-2023-44487 (EPSS ~1.0, KEV, on 1,133 of
  2,909 vuln records [M]); EPSS handles the long tail.
- **No WAF/CDN discount.** WAF/CDN is a filter and a coverage note ("partly hidden behind a CDN"):
  edge records are excluded, so CDN-fronted accounts are under-observed, not safe. Edge /
  security appliances are both attack surface (points) and a spend signal (filter).
- **Score** = sum of points. **Tiers** use fixed thresholds, not percentiles, so a tier means the
  same in every monthly file. Starting values [H, to be checked on the sample distribution]:
  Tier 1 >= 40, Tier 2 20-39, Tier 3 < 20.
- **Explanation**: each finding produces one plain-English sentence plus its points and evidence.
  The breakdown sums to the score (FR3).
- Weights live in a versioned config (FR8). They are a hand-set start, tuned once against
  section 3.
- No ML model: there are no labels to train on.

## 3. Measuring whether it works (FR10, D17)
| # | Question | Method | Manual work |
|---|---|---|---|
| C1 | Is the IP really theirs? | **Forward DNS, automated.** If the domain or hostname resolves to the record's IP, the link is confirmed. Report the confirmed share per matching method (this measures the confidence labels). Hand-check ~30 ambiguous cases (no match, e.g. rotated cloud IPs). Runs on the owner's machine for the audit only; not a production enrichment. | ~30 checks |
| C2 | Does the ranking beat simpler sorts? (headline) | Label pool = top 50 of our ranking ∪ top 50 by max CVSS ∪ top 50 by CVE count ∪ 50 random (<= 200 accounts). Rubric: real organisation? evidence true and on their asset? credible, specific opener? All yes = "worth a call". Report precision@50 per ranking. | Owner labels 60 |
| C3 | Does neglect predict exploitable exposure? | Score without the KEV signal; measure KEV lift in the top tiers vs the rest. No labels. | none |
| C4 | Is the ranking fragile? | Perturb each weight ±25%; report rank correlation and overlap of the top 1,000. | none |
| C5 | Does this month's score predict next month's new exposures? | Needs FR11 and two files. | Design only |

All of C1-C4 run from one `eval` command on every scoring change; a change is kept only if C2
does not drop. This is the development loop.

## 4. LLM use (D18)
**MVP: one use, the C2 labelling assistant.**
- Claude labels the whole pool with the same rubric, from sanitized evidence only (domain, filtered
  title, findings as text). Never raw banners or HTML.
- The owner labels 60 of the pool independently, stratified across the pool. We report Cohen's
  kappa between owner and LLM. If kappa is high (~0.7+), precision@50 is computed on LLM labels
  for the full pool, with the owner-only result alongside; if not, on the owner's 60 only, with
  wide intervals stated.
- Model: `claude-opus-5-5` (small volume, quality matters). Structured output: one JSON object per
  account.
- Cost: logged from real `usage` on every call. Estimate [H]: <= 200 accounts x ~1.5k input / ~0.5k
  output tokens at $4 / $20 per MTok (claude-api skill table, cached 2026-10-06) is ~$3-5 per eval
  run.

**Design only: account classifier** (display name, industry, real business vs ISP / hoster /
personal / parked). The MVP uses TLD and keyword rules for industry and display name. Build the
LLM classifier only if time remains. If built: measure accuracy on free TLD labels (`.edu`, `.gov`,
`.ac.uk`, `.mil`, TLD hidden from the model) plus owner checks; Haiku 5.5 at $0.10 / $0.50 per MTok
is ~$15-30 per full file [H]; cache per domain so monthly cost follows new domains, not files.

**Not used:** an LLM inside scoring (non-deterministic, breaks FR8, costs on every re-score).
