# Signals, scoring and measurement

Status: agreed 2026-10-27, revised the same day after external review (D23-D33 in
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
  the source.
- **via-IP**: the record names no domain, the IP has **exactly one** domain across its direct
  records, and the IP's org is neither CDN nor cloud / hosting. Findings count, tagged via-IP.
- **unresolved**: a nameless record on an IP with 2+ domains, or on a cloud / hosting IP. Not
  attributed; counted in the funnel. Direct records on such IPs still count for the domain they
  name.

**Attribution label shown in the app:** High = direct via scan hostname or cert CN; Medium =
direct via `http.host` or PTR; Low = via-IP. C1 (section 4) measures each label.

**Domain-complete dev sample (D8).** Keep a domain when `hash(domain) % 20 == 0`, plus every
record of any IP on which a kept domain appears directly (so attribution runs on real IP context).
Drop `http.html` and raw `data`.

## 2. Signals and points
Points count once per finding type per account unless stated. Evidence wording for CVEs:
"potential match to a known-exploited CVE (CVE-…) in nginx 1.18.0, observed on 2026-10-26".

| Family | Finding | Points |
|---|---|---|
| Exposure | Exposed remote access / database / ICS service, detected by **Shodan module**, never port alone. Modules seen in the sample [M]: `rdp`, `rdpeudp`, `smb`, `telnet`, `mysql`, `ms-sql`, `postgresql`, `mongodb`, `redis`, `memcache`, `couchdb`, `oracle-tns`, `modbus`, `s7`, `dnp3`, `ethernetip`, `bacnet`, `fox`. VNC / Elasticsearch module names to confirm on the full run. | 45 (reaches Tier 1 alone) |
| Software, **per product + version** | At most one CVE award: potential known-exploited CVE (`kev` true) **25**, OR potential CVE with EPSS >= 0.1 and CVSS >= 7 **15**. Plus end-of-life (`eol-product`) **15**. Capped at **30 per product**. | 0-30 per product |
| Software, account cap | Sum over products capped at **40** (potential, unverified matches never outweigh more than one observed exposure plus a little) | <= 40 |
| Neglect (cap 10) | Expired cert 5; deprecated TLS 3; self-signed cert on a public name 3; server version disclosed 2; HTTPS without HSTS 2 | <= 10 |
| Facts, 0 points | Customer appliance; login / admin / DevOps panel; behind CDN / WAF | filters and plays only |
| Why-now markers, 0 points | Potential known-exploited CVE; cert expires within 30 days of the scan | shown, not scored |

Rules:
- **Ubiquitous CVEs.** CVEs on a documented ubiquitous-CVE list award 0. Provisional list:
  CVE-2023-44487 (HTTP/2 Rapid Reset; EPSS ~1.0, KEV, on 1,133 of 2,909 vuln records in the line
  sample [M]). On Wednesday, after attribution works, measure each CVE's share of attributed
  CVE-bearing accounts: if only CVE-2023-44487 stands out, the list stays as is; otherwise extend
  it with the measured outliers and record them in DATA_NOTES. (Replaces the 10% rule, D26.)
- **CVE-2026-\* IDs** award 0 until the owner's spot-check (D2).
- **Tiers:** Tier 1 >= 45, Tier 2 25-44, Tier 3 1-24; 0 = not ranked (reachable through plays).
  Fixed thresholds, so tiers mean the same in every monthly file.
- **Deterministic order:** score desc, then number of distinct findings desc, then domain asc. The
  baselines in section 4 use the same tie-break.
- Every finding renders one sentence with its points and evidence; the breakdown sums to the score.
- Weights live in a versioned config (FR8). They are **frozen before labelling** (section 4).

**Worked example (hypothetical accounts; shows the tier order is sensible):**
| Account | Evidence | Points | Score | Tier |
|---|---|---|---|---|
| A | nginx 1.18.0 with a potential known-exploited CVE (25) and EOL (15) -> 30; OpenSSH 7.4 with a likely-exploitable potential CVE (15); software cap 40; expired cert (5), deprecated TLS (3) | 40 + 8 | 48 | 1 |
| B | Exposed MongoDB (module `mongodb`), nothing else | 45 | 45 | 1 |
| C | Apache 2.4.58 with a potential known-exploited CVE; HTTPS without HSTS | 25 + 2 | 27 | 2 |
| D | nginx 1.24.0 whose only strong CVE is CVE-2023-44487 (ubiquitous, 0); version disclosed, no HSTS | 0 + 4 | 4 | 3 |
| E | Fortinet appliance, VPN login page, cert expiring in 12 days | 0 (facts + marker) | 0 | not ranked; in the edge-appliance play with a why-now marker |

Why this order is sensible: A and B both reach Tier 1, from several potential exploitable matches
plus neglect, and from one observed exposure. C is a single unverified match. D only has the
everywhere-CVE, which says nothing specific about the account. E is a sales fact (attack surface,
existing security spend), not evidence of need, so it lives in a play.

## 3. Feature schema: scoring rules to retained fields
The feature layer keeps these fields per filtered record (no `http.html`, no raw `data`).
| Rule | Retained fields |
|---|---|
| Attribution (section 1) | `ip_str` / `ipv6`, `_shodan.options.hostname`, `ssl.cert.subject.CN`, `http.host`, `hostnames[]`, `domains[]`, `org`, `isp`, `asn`, `cloud.provider`, `tags` |
| Exposed service | `_shodan.module`, `port`, `transport`, `tags` (`honeypot` excluded upstream) |
| Software awards | `product`, `version`, `cpe23`, `vulns{CVE: cvss, cvss_version, epss, kev, ransomware_campaign, verified}`, `opts.vulns` (verified list) |
| End-of-life | `tags` (`eol-product`, `eol-os`), `product`, `version` |
| Neglect | `ssl.cert.expired`, `ssl.cert.expires`, `ssl.cert.issued`, `ssl.cert.subject` / `issuer` (self-signed), `tags` (`self-signed`), `ssl.versions`, `http.headers` (HSTS flag only), `http.server` (version disclosure) |
| Why-now markers | `vulns.*.kev`, `ssl.cert.expires`, `timestamp` |
| Facts (appliance, panel, CDN / WAF) | `product`, `http.title` (filtered, truncated), `http.server`, `ssl.cert.subject.O`, `http.waf`, `tags` (`cdn`) |
| Provenance and coverage | `timestamp`, `_shodan.id`, `_shodan.crawler`, `_shodan.module`, `hash`, input file hash |

## 4. Measuring whether it works (FR10)
| # | Question | Method | Manual work |
|---|---|---|---|
| C1 | Is the account link right? | **Forward DNS, automated.** If the domain or hostname resolves to the record's IP, the link is confirmed. Report the confirmed share per attribution label and source. Hand-check ~30 ambiguous cases. Audit only, run on the owner's machine. | ~30 checks |
| C2 | Does the ranking beat simpler sorts? (headline) | **Weights frozen first** (config version recorded). Pool = union of the top 15 of our ranking, top 15 by max CVSS, top 15 by CVE count, plus 15 random accounts (<= 60). Shown **blind** (shuffled; evidence only, no score, rank or source). Label: worth a call / not / unknown. Report **precision@15** per ranking (unknowns excluded and counted). | Owner labels <= 60 |
| C4 | Is the ranking fragile? | Perturb each weight ±25%; report top-15 overlap and rank correlation, with the deterministic tie-break. | none |
| C5 | Does this month's score predict next month's new exposures? | Needs FR11 and two files. | Design only |

Cut: C3 (KEV lift) and the LLM labeller (D28).

## 5. LLM use
**None in the MVP pipeline or evaluation** (D28). The account classifier (display name, industry,
real business vs ISP / hoster / personal / parked) stays design only; the MVP uses TLD and keyword
rules, which are first in the cut order if time slips. If it is ever built: measure accuracy on free
TLD labels (`.edu`, `.gov`, `.ac.uk`, `.mil`, TLD hidden) plus owner checks, log real token cost,
cache per domain. Never raw banners to a model; never an LLM inside scoring.
