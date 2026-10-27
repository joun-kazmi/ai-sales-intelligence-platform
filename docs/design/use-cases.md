# Users and use cases

Status: agreed 2026-10-27, amended after step 3. Decisions D1-D8 (D2 amended) and D18 in `docs/DECISIONS.md`.
Legend as in `DATA_NOTES.md`: **[M]** measured, **[H]** hypothesis / not yet validated.

## How B2B sales teams prospect (the model we design for)
- **ICP (Ideal Customer Profile)**: the kind of company you sell best to (industry, size, region,
  technology). Every list gets filtered against it.
- **SDR/BDR** (Sales / Business Development Rep): researches accounts and makes first contact.
  **AE** (Account Executive): takes qualified conversations and closes.
- **Tiering**: a rep can research only a handful of accounts deeply per day, so accounts are split
  into Tier 1 (research properly), Tier 2 (light touch), Tier 3 (not now). Ranking exists to make
  that cut.
- **Trigger / "why now"**: something true about the account that makes this the right moment.
  Specific, true triggers get replies; generic pitches don't.
- **Hook**: the opening line that proves you looked ("your VPN gateway runs end-of-life firmware").
- **Play / campaign**: one outreach motion aimed at every account sharing one problem.
- **CRM** (Salesforce, HubSpot): where reps actually work; lists get exported into it.

## Primary user
The **SDR** building this week's outreach list for a cybersecurity vendor. Not the AE, not a
manager, not the security team of the prospect.

## What the data can and cannot say about an account
| Can | Cannot |
|---|---|
| Externally visible security posture of a domain: potential CVEs, EOL software, exposed remote access / databases, TLS and certificate neglect [M, DATA_NOTES 5] | Company legal name: cert `O` on 1.5% of records, top values are vendors [M] |
| Enterprise security / edge gear in use (Fortinet, SonicWall, Citrix, ...) [M, DATA_NOTES 2, 5] | Headcount, revenue: only weak size proxies (IP/host count per domain) [H] |
| Rough footprint size: IPs, hosts, ports per domain | Contacts / buyer persona: `security.txt` on 0.06% of records [M] |
| Timing evidence inside one snapshot (see "Why now" below) | Change over time: one ~19 h snapshot [M] |
| Partial industry label from TLD (`.edu`, `.gov`, `.ac.uk`, `.bank`) and title keywords [H] | Full industry classification from the file alone |

## Use cases
### UC1. Work my ranked list
"Show me the accounts most likely to need help, best first, so I can pick this week's Tier 1."
- Each row: domain (the account), score and tier, top 2-3 reasons in plain English, a "why now"
  marker when timing evidence exists, and the domain-resolution confidence.
- Filters: minimum score / tier, signal type, "has why-now evidence", security gear present /
  absent, resolution confidence, partial industry label, and **country** (a simple filter, not
  the headline; see D4).

### UC2. Understand why an account ranks where it does
"Before I reach out, show me the evidence, so my opener is specific and true."
- Every finding in plain English plus its raw evidence: host / IP, port, product and version,
  CVE ID with CVSS and the record's KEV flag, cert expiry date, observed-at timestamp.
- CVEs are labelled **"potential"**: they come from banner-version matching, not verification
  (verified `opts.vulns` is 0.03% of records [M]).
- A score breakdown that adds up to the total, and how the IPs were tied to the domain (scan
  hostname > non-wildcard cert CN > named PTR > `http.host`) with a confidence label.
- A display name only if it passes a filter (not an error/default page title, not a vendor cert
  `O`); otherwise none, just the domain.

### UC3. Run a play
"Give me every account with problem X, and let me take the list to my CRM."
- The same list as UC1, pivoted by finding instead of score: exposed remote access / databases,
  EOL software, KEV-flagged potential CVEs, expired or soon-expiring certs, exposed edge
  appliances (Fortinet/SonicWall/Citrix: presence only, their banners rarely carry versions or
  CVEs [M, DATA_NOTES 5b]).
- **CSV export** of the current filtered list. This is the only hand-off to other tools (D5).

### UC4. See what's new (designed, not demoed in the MVP)
"Which accounts got worse since the last file?" This is the strongest "right now" trigger in
production, where hundreds to thousands of files arrive each month. The data model keeps
`first_seen` / `last_seen` per finding so later files can produce "new since last scan". The MVP
has one file, so it cannot show this, and we will not fake a second snapshot.

## "Why now" inside one snapshot (MVP)
Timing evidence used in UC1-UC3. Sample figures are the 1-in-160 sample, record level, before
CDN/infra exclusion, so they only show that a field exists and roughly how common it is.
| Evidence | What is in the file | Notes |
|---|---|---|
| Cert expiring within 30 days | `ssl.cert.expires` vs record `timestamp` | 273 of 6,262 certs in sample (4.4%); already expired 332 (5.3%) [M]. Measured against scan time, not today. |
| Actively exploited CVE | `vulns[CVE].kev` (CISA Known Exploited Vulnerabilities flag), `ransomware_campaign` (`Known`/`Unknown`), `epss` | Not in DATA_NOTES; found 2026-10-27. 58 distinct KEV CVEs in sample. The most common is CVE-2023-44487 (HTTP/2 Rapid Reset, on most nginx). Only 647 of 2,909 vuln records have a KEV CVE besides it [M]. Near-universal CVEs need down-weighting (step 3). |
| Published this year (CVE-2026-*) | No publication date; the ID year is when the ID was reserved, so a CVE-2026 ID cannot predate 2026 (one-sided marker) | 39k of 127k CVE hits in sample (31%), 539 distinct IDs up to ~110,000 [M]. **Off (0 points, no marker) until a spot-check against cve.org confirms the IDs** (DATA_NOTES 5b, D2). |
| End-of-life (not "recently") | `eol-product` tag only, **no EOL date** | 90% of tagged records are nginx; version on 6.5% of records [M]. The MVP shows "end-of-life" as a finding, not as a why-now marker (D2). |

## Evidence rules carried into requirements and scoring
- Exclude CDN / shared-infrastructure records **before** counting any finding: identical CVE lists
  repeat across ~131k edge records and describe the CDN, not the customer [M, DATA_NOTES 3].
  Records with CVEs sit mostly on hosting providers (Aliyun, Hetzner, Amazon, DigitalOcean) [M].
- WAF/CDN presence is a **weak** sign of security spend (a free Cloudflare plan counts).
  Enterprise security / edge gear (Fortinet, SonicWall, Citrix) is a **stronger** sign of spend,
  and is also attack surface (frequent critical CVEs).
- Industry and display name: TLD / keyword rules in the MVP. An LLM account classifier is design
  only, built only if time remains (D18).

## Out of scope (decided, D5)
CRM push, external company enrichment, contact discovery, outreach drafting.
Region/territory is not in the brief: it survives only as the country filter.
