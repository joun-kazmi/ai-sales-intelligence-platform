# DATA_NOTES: Shodan banner dump profile

Legend: **[M]** = measured (full pass over all records, or on the 0.625% systematic sample where stated); **[H]** = hypothesis / not yet validated.
Artifacts: `data/sample/profile.json` (full-pass aggregates), `data/sample/sample.jsonl.zst` (every 160th line, 91,303 records, 94 MB zst at level 19 / 800 MB raw),
`data/sample/entity_probe.json` + `entity_probe2.json` (entity-resolution probes on the sample).

## 1. What the data is [M]
- `dataset.json.zst`: 17.6 GB zstd, 122.8 GB raw JSON, **14,608,406 records** (1 line failed to parse: lone UTF-16 surrogate), avg 8.4 KB/record. Full pass: **754 s** (7 worker procs, orjson).
- One record = one Shodan banner for one IP:port (`_shodan.module` says which crawler module). Timestamps span **2026-10-25 18:13 to 2026-10-26 13:06 UTC** (about 19 h), i.e. a single-day snapshot, no history/time-series.
- Distinct IPs ~**4.99M** (HLL), distinct ip:port ~13.2M, so ~2.9 records per IP. Distinct `org` ~83k, `isp` ~42k, distinct `domains[]` values ~**488k**, distinct `hostnames[]` ~3.8M, distinct cert CNs ~351k.
- 97% TCP / 3% UDP. IPv6 only 2.1%. Country: US 37.7%, **SG 30.6%** (Google Cloud Singapore + Imperva), CN 5.6%, GB 3.0%, DE 2.9%, JP 1.6%, IL 1.5%, KR 1.4%, FR 1.2%, HK 1.1%.
- Not a random Internet sample. It is heavily biased to CDN/cloud edge IPs (see 4). Treat it as "hosted web infrastructure + long tail of exposed services".
- Contents are untrusted (banners, HTML, titles). Never execute or render them.

## 2. Schema and fill rates [M] (% of 14.6M records)

| Field | Fill | Notes |
|---|---|---|
| `ip`/`ip_str` | 97.9 | IPv6 records have `ipv6` instead (2.1%) |
| `port`, `timestamp`, `transport`, `location.*`, `_shodan.{module,id,crawler}`, `hash`, `asn` | ~100 | `location.region_code` 98.9 |
| `org`, `isp` | 99.99 | `org == isp` in 75% of records |
| `domains[]`, `hostnames[]` | 74.1 | always filled together; **mostly reverse-DNS (PTR) derived** (see 4) |
| `tags[]` | 71.0 | `cdn` 40.2, `cloud` 28.5, `pqc` 2.4, `honeypot` 1.7, `eol-product` 1.67, `self-signed` 0.9, `vpn` 0.9, `proxy` 0.4, `database` 0.11, `eol-os` 0.04, `iot` 0.2 |
| `data` (raw banner) | 43.6 | big; skip for ML features |
| `http` | 29.5 | `http.html` 25.1, `title` 17.1, `server` 19.3, `components` 18.7, `waf` 10.7, `headers` 28.4, `favicon` 3.5, `securitytxt` 0.06 |
| `cloud.provider` | 28.5 | Google 19.9, Amazon 4.9, Alibaba 1.7, Azure 0.67, DigitalOcean 0.38, Linode 0.36, Vultr 0.24, Tencent 0.21, Oracle 0.19 |
| `cpe`/`cpe23` | 20.9 | cpe has no versions in most; product+version in `product`/`version` (17.9 / 6.5) |
| `opts` (`heartbleed`, `raw`, `vulns`) | 12.6 | |
| `ssl` | 6.8 | `ssl.cert` 6.8, `cert.subject.CN` 6.7, `cert.subject.O` **1.46**, `subject.OU` 0.6, `ssl.versions` only 4.3, `ssl.jarm`/`ja3s` ~6.8 |
| `os` | 4.1 | |
| `vulns{CVE: {cvss, verified, summary}}` | **3.2** | dict keyed by CVE; `opts.vulns` (verified list) only 0.03 |
| `ssh` 0.66, `snmp` 1.2, `isakmp` 0.75, `ntlm` 0.2, `rdp_encryption` 0.17, `hikvision` 0.31, `mysql` 0.07, `vnc` 0.05, `kubernetes` 0.02 | | service-specific sub-objects; ~150 distinct top-level module keys exist |
| `_shodan.options.hostname` | 5.75 | scan was explicitly done against a hostname (best entity signal) |

Top modules: `auto` 52.2% (generic/unparsed), `http` 15.0, `http-simple-new` 8.1, `https` 5.6, `https-simple-new` 4.9, `language-server-protocol` 1.9, `snmp_v3` 1.2, `ike` 1.0, `nodata-tcp` 0.7, `ssh` 0.6, `x11` 0.5, `dahua-dvr` 0.4, `rtsp-tcp` 0.4, `rdp` 0.35.
Top ports: 80 14.8%, 443 5.2%, 2087 2.1% (cPanel/WHM SSL), 161 1.2%, 8085, 500, 7547 (TR-069) 0.9, 9000, 22 0.6.
Top org: Incapsula (Imperva) **31.9%**, Google LLC 21.7, Cloudflare 3.8, Aliyun 3.5 (two spellings), Amazon 4.1 (two spellings), Korea Telecom 1.1, Akamai 1.0, Hetzner 0.7, Microsoft 0.65.
Top products: nginx 5.2, Apache httpd 1.9, CloudFront 1.5, AkamaiGHost 1.1, OpenSSH 0.9, AWS ELB 0.8, OpenResty 0.6, IIS 0.5, Hikvision cam 0.3.

## 3. Quirks [M unless noted]
- **Edge-IP dominance**: 1/3 of records are Imperva/Incapsula edge IPs, 1/5 Google LLC. Their `domains`/`hostnames` are CDN/PTR names (`incapdns.net`, `googleusercontent.com`), and their banners/CVEs describe the CDN, not the customer.
- **`vulns` are heavily duplicated**: the same CVE list (e.g. CVE-2013-4365, CVE-2012-3526, ... on 131,415 records each; CVE-2023-44487 on 173k; CVE-2025-23419 on 174k) fires on shared edge infrastructure. IDs like `CVE-2026-9xxxx` have high numbers but are genuine (spot-checked, see 5b). CVSS buckets across all CVE hits: 7.x 7.4M, 5.x 4.0M, 9.x 3.1M, 10 59k.
- **Missing versions**: `vulns` come from banner version matching (not verified); `opts.vulns` (verified) is 0.03%.
- `ssl.versions` lists unsupported protocols as `-TLSv1.3`; I counted only non-negated.
- `ssl.cert.expired` is a precomputed bool (used as-is). `ssl.cert.subject`==`issuer` used for self-signed (also tag `self-signed`).
- `http.headers` names are mixed case; compare case-insensitively. Only 24% of http records are HTTPS (`ssl` present).
- `honeypot` tag 1.7% and CouchDB 5984 (26.7k hits) look like honeypot/decoy noise; exclude `honeypot` tag.
- Many records are junk/protocol noise (`nodata-tcp`, `x11`, `language-server-protocol`, `ike`).
- ~20% of http titles are error pages ("301 Moved", "404", "Invalid URL", "400 Bad Request", "Welcome to nginx!"). Titles identify a company on only a small fraction of records.
- Records are not ordered by IP; a systematic sample (every 160th line) is representative of the file order.

## 4. Entity resolution: IP/banner to company
Measured on the 91,303-record sample (heuristic regex classification of `org`; error margin a few points).

**4a. `org`/`isp` is rarely the customer.**

| org class | share of records |
|---|---|
| cloud / hosting / CDN (Imperva, Google, Cloudflare, Amazon, Alibaba, Akamai, Hetzner ...) | **76.2%** |
| ISP / telecom | 10.2% |
| legal-form-looking business or institution (`Inc`, `LLC`, `GmbH`, `Ltd`, university ...) | 5.2% |
| other / unclassified (many are still ISPs or shells: "ACE", "IP pools", "Meteverse", "Private Customer") | 8.4% |
So at most roughly **5-13% of records** have an `org` that could plausibly be the end business, and even there it is often a vendor/ISP (Avago, Bitly, Proofpoint, Level 3, Palo Alto Networks). `org` alone is a bad company key.

**4b. Name signals available** (% of sample records; domain/hostname share is higher for cloud orgs, but those are PTR names):
- `domains[]`/`hostnames[]` non-empty: 74.0%, but in **84%** of those, every hostname is IP-like or provider rDNS (`ec2-1-2-3-4...`, `*.googleusercontent.com`, `*.incapdns.net`). 
- Registrable domain that is not infrastructure ("vanity"): only **9.2% of records** carry one from a non-IP-like PTR, scan-hostname, `http.host` or cert CN. Sources of the 8,884 vanity domains: PTR named 6,711, `_shodan.options.hostname` 2,017, cert CN 192, `http.host` 28.
- `ssl.cert.subject.CN` 6.8% (a hostname, useful when not a wildcard / CDN cert), `subject.O` (a real legal name) **1.5%** (top values are vendors: Google, Microsoft, Proofpoint, Fortinet, Huawei, SonicWall, Plesk, "Acme Co"), `http.title` 17% (mostly error/default text; branded titles are a small slice).
- Records with `_shodan.options.hostname` (scan was run against a known name): 5.1% in sample, 2,029 distinct domains. This is the cleanest "company" link in the file.
- Even many "vanity" domains are ISP/host customers' PTRs (`virginm.net`, `rima-tde.net`, `sakura.ne.jp`, `stratoserver.net`), i.e. the domain identifies the ISP/host, not a company. Needs a blocklist of ISP/hoster domains.

**4c. Domain cardinality.**
- Full file: ~488k distinct `domains[]` values (HLL), ~350k distinct cert CNs. Sample: 10.4k non-infra registrable domains vs 8.9k after infra filtering; 85% of vanity domains appear in exactly one sample record (`domains_seen_once` 7,532 of 8,884), median 1, p90 2, p99 10 records/domain. Long-tailed: the top 100 domains hold ~69% of domain-linked records (infra-heavy). Extrapolating (sample is 0.625%, so a domain with 1 hit probably has ~5-150 in full file): **estimate on the order of 100-300k real vanity domains in the full file [H]**, likely at most 1-3 hundred thousand companies after dedupe of ISPs/hosters.

**Verdict**: IP -> company resolution is *weak*. Workable path: key records by registrable domain (scan hostname > cert CN non-wildcard > `http.host` > named PTR; order fixed in D29), drop CDN/hosting/ISP rDNS domains and CDN-edge records, then enrich domains externally (WHOIS/company names, LinkedIn-like lookup). Expect roughly **1 in 11 records** to join to a candidate company; the rest are infrastructure or consumer/IoT. Company names must come from outside the file (only 1.5% have cert `O`).

## 5. Candidate "needs cybersecurity help" signals
Prevalence: "% records" = full pass [M]; "% vanity domains" = sample, domain-level OR across that domain's records, n=8,884 [M]; "no-CDN" = vanity domains without WAF/CDN tag (n=4,849). Domain-level percentages are biased by few records per domain (1.7 avg), so true per-domain prevalence is probably higher.

| # | Signal | % records | % vanity domains | % no-CDN domains | Strength [H] |
|---|---|---|---|---|---|
| 1 | Banner-matched CVE with CVSS>=7 (`vulns`) | 2.96 | 7.6 | **13.3** | high, but must drop CDN/shared infra duplicates |
| 1b | CVSS>=9 | 1.67 | 4.1 | 7.1 | high |
| 2 | `eol-product` tag (EOL software) | 1.67 | 4.7 | 8.3 | high, easy story; `eol-os` 0.04% rare |
| 3 | HTTPS site without HSTS | 4.5 (of all recs) / 77% of https recs | 51.5 | 31.8 | medium (hygiene) |
| 4 | Missing CSP / X-Frame-Options (http recs) | 95% / 87% of http recs | 83 / 78 | 75 / 70 | weak alone (near-universal) |
| 5 | Server version disclosed (`Server: nginx/1.18.0`, ...) | 5.6 | 16.2 | 24.8 | medium, pair with CVE age |
| 6 | Deprecated TLS (SSLv2/3, TLS1.0/1.1) | 0.97 (21% of recs with `versions`) | 8.3 | 7.0 | medium |
| 7 | Expired cert | 0.37 (5.5% of ssl recs) | 6.1 | 5.9 | medium-high (operational neglect) |
| 8 | Self-signed cert | 0.96 (14% of ssl recs) | 2.5 | 4.3 | low-medium (also internal/IoT) |
| 9 | Exposed remote-access / DB (RDP 3389, SMB 445, Telnet 23, FTP 21, VNC, MySQL, Postgres, MSSQL, Mongo, Redis, ES, Memcached, Couch, Oracle) | 1.24 | 1.2 | 2.1 | **very high** but rare, many are consumer/honeypot |
| 10 | Weak crypto: sig SHA1/MD5, RSA-1024 | 0.13 / 0.055 | 0.25 / 0.18 | 0.33 / 0.31 | low prevalence |
| 11 | Cert expiring within 30 days | 0.28 | n/a | n/a | sales trigger, not risk |
| 12 | Basic-auth / 401 on exposed admin | 0.82 | 1.3 | 2.1 | low-medium |
| 13 | Composite: >=2 / >=3 of the 8 core signals (CVSS>=7, expired cert, deprecated TLS, no HSTS, exposed remote/DB, EOL, self-signed, version disclosed) | | 23.4 / 7.2 | | best ranking feature |
Absence-of-defence signals (negative for "needs help" or "already buys"): WAF present 10.7% of records, 42% of vanity domains (Imperva/Cloudflare/CloudFront/Akamai/FortiWeb/SonicWall). Domains already behind a WAF/CDN likely already spend on security [H]; "has Imperva/FortiWeb/Cloudflare" is also a competitive-displacement or upsell flag.

### 5b. CVE metadata inside `vulns` [M, 1-in-160 sample, 2026-10-27]
Each `vulns[CVE]` entry has: `cvss`, `cvss_version`, `cvss_v2`, `epss`, `ranking_epss`, `summary`, `references`, `verified`, and (on ~1.8% of CVE hits) `kev` + `ransomware_campaign`. Sample: 2,909 records with `vulns`, 126,814 CVE hits, 4,134 distinct CVEs.
- `verified`: True on 44 of 126,814 hits. CVEs are banner-version matches; treat as "potential".
- `cvss_version`: 3.0 80%, 2.0 18%, 4.0 2%. Scores mix CVSS versions.
- `epss` (exploit probability, next 30 days): float on every hit, 0.0006-0.99999. Distinct CVEs: <0.01 1,038; 0.01-0.1 2,245; 0.1-0.5 550; >=0.5 301.
- `kev` (CISA Known Exploited Vulnerabilities): True on 2,268 hits / 58 distinct CVEs; 42 of the 58 also have EPSS>=0.5. `ransomware_campaign`: Known 372, Unknown 1,889 hits.
- **Everywhere-CVEs**: CVE-2023-44487 (HTTP/2 Rapid Reset) is on 1,133 of 2,909 vuln records with **EPSS ~1.0 and KEV True**, so EPSS and KEV *raise* it; only prevalence can down-weight it. Of 2,345 records with a KEV or EPSS>=0.5 CVE, 686 have no strong CVE other than CVE-2023-44487. The next tier (CVE-2025-23419, a 2009-2013 Apache list on 801 records each) has low EPSS (0.007-0.14), so EPSS does down-weight those.
- Lists are long and repeated: median 11 CVEs per vuln record, p90 125, max 676. The 2,909 records collapse to **291 distinct (product, version)** pairs (nginx 1.24.0 439, nginx 1.18.0 292, OpenSSH 7.4 184, ...). The CVE count is an artifact of version matching; the real finding is "product X at version Y".
- **No publication date** on CVE entries. **CVE-2026-\***: 539 distinct IDs, 39,284 of 126,814 hits (31%), ID numbers up to ~110,000, 456 of 539 with EPSS<0.01 (expected for new CVEs, EPSS lags), 13 KEV. The ID year is the year the ID was reserved, so a CVE-2026 ID cannot have been published before 2026: a valid one-sided "published this year" marker. Whether the high ID numbers are genuine is not verified (no NVD join); settled by the spot-check below.
- **CVE-2026 spot-check: done [M], 2026-10-27**, by the owner via the official CVE API (`cveawg.mitre.org/api/cve/<ID>`). Four of the ten picked IDs were checked, and all four are real, published records, 5-25 days before the scan: CVE-2026-93546 (736 sample records) and CVE-2026-73637 (674), Apache HTTP Server, published 2026-10-01; CVE-2026-106587 (312), OpenSSH, published 2026-10-06; CVE-2026-109618 (108), PHP, published 2026-10-21. Not checked: -109619, -111094, -111095, -111096, -50012, -63072. Conclusion: the high ID numbers are genuine, and the large CVE-2026 share reflects newly published CVEs matched against old versions of common servers. CVE-2026 IDs are scored like any other CVE (D42). The two Apache IDs sit on hundreds of sample records each, so they are candidates for the ubiquitous-CVE list once measured after attribution (D26).
- Edge / security appliances detected by product, title, server or cert `O` (Fortinet 56, SonicWall 102, F5 75, Citrix 29, Ivanti/Pulse 9, Exchange/OWA 11, Palo Alto 8, VMware 5, Cisco ASA 2 records) **almost never carry `vulns`** (2 of ~300): appliances don't expose versions in banners. Their presence is attack surface and a spend signal, not CVE evidence.

Exposed-service counts (full pass, records): 21/FTP 40.5k, 3389/RDP 48.8k (0.33%), 445/SMB 6.0k, 5985/WinRM 33.4k, 3306/MySQL 14.5k, 1433/MSSQL 6.6k, 5432/Postgres 6.6k, 27017/Mongo 5.5k, 6379/Redis 5.1k, 9200/ES 5.1k, 5900/VNC 4.1k, 11211/Memcached 4.1k, 2375/Docker ~0.03%, 102/S7 15.6k, 502/Modbus 4.4k, 161/SNMP 172k, 7547/TR-069 127k, telnet 23 ~4k. Admin-panel titles (of 2.49M titled records): login/sign-in 3.5%, admin/dashboard/console 1.2%, router/gateway 1.3%, camera/NVR 0.3%, VPN/remote access (Fortinet, Citrix, GlobalProtect, ...) 0.35%, DevOps tools 0.24%, db-admin 0.03%.

**Firmographic/size proxies [H]** to combine with risk: number of distinct IPs/domains per company, cert `O` present, cloud provider mix, presence of enterprise gear (Fortinet, SonicWall, Citrix, Exchange, Proofpoint), hostnames count per domain, TLD/country.

## 5c. Extractor measurements [M]
Line sample (91,303 records, 800 MB raw, 94 MB zst), cloud sandbox, 3 worker processes on 4 cores,
extractor v1, blocklist `faf9761a45c4`, 2026-10-27:
- Throughput 14.1k records/s (6.7 s). Not comparable to the owner's 8-core machine; the full-file
  figure comes from Wednesday's run.
- Funnel: dropped 32,607 CDN edge records without a customer name (35.7%), 3,530 noise modules,
  1,543 honeypot; kept 53,601 (58.7%): cloud / hosting 31,150, customer or ISP network 19,833,
  CDN records that name a domain 2,640. Records with at least one candidate name: 8,294 (9.1%).
- Name sources (records, before the measured-leak additions): PTR 7,066, scan hostname 3,541,
  cert CN 1,379, `http.host` 44. Distinct candidate domains: 8,086.
- Feature layer: 6.6 MB Parquet (zstd) for 800 MB raw, ~0.8% of raw / ~7% of the zst input.
- Top candidate domains still included ISPs and hosters (vnpt.vn, wanadoo.fr, pphosted.com,
  wpengine.com, ...); 18 were added to the blocklist. Real companies with many IPs (walmart.com,
  79 IPs in its own org) look similar by counts alone, so the rest is left to eligibility (D34).
- Sample builder on the same file (mechanics test, modulus 20): 388 of 8,086 domains, 475 IPs,
  184 of them shared (2+ candidate domains in the full index); raw pass ~31k records/s, single
  process.

**Full file [M]**, owner's machine (8 cores, 7 workers), extractor at `c61315d`, blocklist
`faf9761a45c4`, input sha256 `71cb1991…b5b7`, 2026-10-27:
- Extract: **9 min 07 s wall (~26.7k records/s), peak RSS ~0.5 GB**; feature layer
  **1,031,306,361 bytes** (0.84% of raw, 5.9% of the 17.6 GB zst).
- Funnel (of 14,608,407 records): dropped CDN edge without a customer name 5,229,445 (35.8%),
  noise modules 573,883 (3.9%), honeypot 250,439 (1.7%), parse error 1; **kept 8,554,639
  (58.6%)**: cloud / hosting 4,990,119, customer or ISP network 3,149,747, CDN records naming a
  domain 414,773. **Records with at least one candidate name: 1,328,323 (9.1%)**, matching the
  line sample (9.1%) and DATA_NOTES 4 (~9%).
- Candidate-name index: **717,056 IPs, 436,171 distinct candidate domains** (before eligibility;
  DATA_NOTES 4c had estimated 100-300k real vanity domains [H], so many of these are expected to
  be ISP / hoster / personal names for the eligibility label).
- Domain-complete sample (modulus 20): 5 min 11 s, peak RSS ~0.5 GB. **21,963 domains (5.0%) on
  45,488 IPs, 15,409 of them shared (33.9%)**; 520,923 records, 121 MB at zstd level 10, 78 MB
  after the owner recompressed it (`zstd --ultra -22 --long=27`). Re-extracting it dropped
  308,034 records (59%) as CDN edge without a name: every record of a sampled CDN edge IP was
  included. Fixed in the builder (D46); the rebuilt sample should hold ~213k records [H].

**Domain-complete sample scored [M]** (sandbox, 2026-10-27; features `bcd01d2d7818` from the
first, unfiltered sample build; the 17,663 blake2b-sampled domains only unless stated):
- Attribution funnel (all 206,817 kept rows): direct 201,473 (CDN-edge naming a domain 95,322,
  cloud / hosting 63,183, customer or ISP 42,968); via-IP 1,532 (311 domains); unresolved 3,812
  (3,384 on cloud / hosting IPs, 428 on IPs with 2+ domains).
- CVE prevalence after attribution (3,961 CVE-bearing accounts): no gap; 42 CVEs on > 30%, 89 on
  > 20%. Version-independent CVEs (>= 90% of a product's observed versions): 54 (D47).
  CVE-2023-44487 is on 61% of nginx accounts with a version; CVE-2024-38475 (KEV) on 58% of
  Apache accounts.
- Shodan's `eol-product` for nginx is consistent: every branch older than 1.30 is tagged (1.30
  stable and 1.31 mainline are current in this snapshot), 0% for 1.30.x / 1.31.x.
- Scores: Tier 1 306 (1.7%), Tier 2 1,710, Tier 3 6,935, not ranked 8,712; ranked median 5,
  p90 32, p99 60, max 95. Tier 1 drivers: exposure only 225, software >= 30 only 41, both 40.
  Exposed services by module: rdp 220, mysql 100, smb 20, telnet 14, dnp3 10, postgresql 9.
- Eligibility: uncertain 72%; likely org: public web property 2,725, cert O 1,071, own network
  459, institutional 116; likely non-prospect: hoster customer servers 162, PTR zone 177,
  dynamic DNS 157, residential 137, parked 2. Default Tier 1 view after the hoster rule: 248,
  8 of them with 50+ IPs.
- Scoring run: 20 s, peak RSS 1.2 GB, artifact 4.7 MB for 37,831 accounts (incl. partial
  accounts of non-sampled domains on shared IPs). Two runs give identical artifacts.

**Rebuilt domain sample [M]** (fixed builder `3a0145f`, owner's machine): 6 min 54 s, peak RSS
~1.3 GB; 206,817 records written (dropped: CDN edge without a name 308,034, noise 6,049, honeypot
23); 57,125,378 bytes; same 21,963 domains on 45,488 IPs (15,409 shared). The manifest's `-dirty`
suffix comes from the tracked sample file being overwritten during the run. Re-extracting it
drops nothing (206,817 rows), and it scores identically to the first build.

**Full-file score [M]** (`e519275`, config `6cf3bc33da1a`, CVE-2023-44487 still on the list,
tiers 45 / 25): 2 min 21 s wall, **peak RSS 13.5 GB** (fixed, D51), artifact 44,838,912 bytes
(under the 100 MB cap). 349,520 accounts, 461,365 findings, 55 ubiquitous CVEs. Tiers: T1 6,070 /
T2 35,083 / T3 136,474 / not ranked 171,893. Eligibility: likely org 85,544 / uncertain 250,997
(72%) / likely non-prospect 12,979. The sample predicted these well (x20).

**Tuning round on the sample [M]** (17,663 sampled domains; "default view" hides likely
non-prospects):
- CVE-2023-44487 off the list (D49), old tiers: T1 306 -> 308, T2 1,710 -> 2,392 (+40%), T3 6,935
  -> 6,251. 684 accounts moved T3 -> T2. 1,191 of the 2,392 Tier-2 accounts rest only on this CVE
  ("nginx older than 1.25.3"), and 2,386 of 2,392 Tier-2 accounts are one software finding with no
  exposure: Tier 2 meant "one web server behind on a patch".
- Default-view tier sizes by threshold (sample, ~x20 for the full file): 45/25 -> T1 250 / T2
  2,274; 55/30 -> 55 / 1,772; 55/40 -> **55 / 299**. Chosen 55/40 (D50): T1 ~1,100 and T2 ~6,000
  on the full file [H]. All 55 Tier-1 accounts have an exposure plus software findings.
- Frozen config `765eef67e0c5`: all accounts T1 91 / T2 360 / T3 8,500 / not ranked 8,712;
  default view T1 55 / T2 299 / T3 8,167.
- Eligibility stays 72% "uncertain": the label mainly hides the obvious non-prospects (hosters, ISP
  zones, dynamic DNS, residential, parked). Stated as a limitation in the write-up.

**Full-file score, frozen config [M]** (`2576298`, config `765eef67e0c5`, 54 ubiquitous CVEs, owner's
machine): 1 min 20 s wall, **peak RSS 2.8 GB** (13.5 GB before D51), artifact 46,411,776 bytes.
349,520 accounts, 486,094 findings. Tiers, all / default view: T1 1,691 / 982, T2 7,535 / 6,201,
T3 168,410 / 162,093, not ranked 171,884 / 167,265. The x20 estimates from the sample held
(~1,100 / ~6,000 in the default view). Published as private release `data-v1`
(`artifact.duckdb`).

**C4 sensitivity [M]** (sample, 17,028 default-view sampled accounts, config `765eef67e0c5`, 34 s):
each of 10 point weights at +/-25%. Top-20 overlap with the frozen ranking >= 0.85 in all 20 runs
(lowest: `cve_kev` +25% and `cve_likely` -25%, 0.85); top-100 overlap >= 0.72 (lowest:
`exposed_service` -25%); Spearman over all accounts >= 0.9993. `version_disclosed` and `no_hsts`
(2 points) round back to 2 at +/-25%, so those four runs were re-run at +/-1 point (D54): top-20
overlap 0.95-1.00, top-100 0.90-1.00, Spearman 0.9971-0.9979 (lowest overall: `no_hsts` +1 pt).
Across all 20 runs: top-20 overlap >= 0.85, Spearman >= 0.9971. The ranking is not knife-edge.

**C1 forward-DNS match rate [M]** (full file, owner's machine, `dd5294e`, 300 links per source,
seed 20261028; a match supports a link, it does not prove ownership, D39):

| Source | Label | Match rate | Of resolved |
|---|---|---|---|
| `http_host` | Medium | 0.937 | |
| `scan_hostname` | High | 0.807 | |
| `ptr` | Medium | 0.587 | 0.657 |
| `cert_cn` | High | 0.417 | 0.439 |
| via-IP | Low | 0.173 | 0.221 |

By label: High 0.612, Medium 0.762, Low 0.173. **Open question:** `cert_cn` is labelled High but
matches less often than both Medium sources. Hypothesis [H]: the certificate names the bare
domain (or a service name) while the web host lives elsewhere, e.g. a cert for `acme.com` on a
mail or VPN server whose IP is not what `acme.com` resolves to. Attribution labels stay unchanged
until the owner's hand-check of the 30 misses (`misses.csv`) is in. Via-IP is the weakest link,
as its Low label says.

**False exposures [M]** (sample artifact, config `765eef67e0c5`, found while checking the UI): the
Shodan module names the probe that ran, not always the service that answered. Of 382
exposed-service findings, ~13 (3.4%) carry a product of a different service: `rdp` answered by
OpenSSH / ProFTPD / RPC over HTTP (3), `telnet` by OpenSSH (5), `ms-sql` by nginx (2), `mysql` by
nginx (1), `dnp3` by nginx / Ncat (2). Proposed fix (not applied; the config is frozen and the C2
pool is being labelled): count an exposure only when the identified product is absent or is not a
generic SSH / FTP / HTTP / proxy server. Open decision for the owner.

C2 pool built from `data-v1`: 60 accounts (20 / 20 / 20), overlap ours vs
highest-CVSS 0, 425 s, peak RSS 0.97 GB.

## 6. Recommended pipeline implications (superseded by `docs/DECISIONS.md`)
1. Pre-filter: drop `tags` in (`honeypot`), modules in noise list, and records whose org class is CDN/ISP *and* whose only names are PTR names.
2. Build a company table keyed by registrable domain (use a public-suffix list), attach all IPs/ports/signals, dedupe CVEs per product, not per record.
3. Score with a transparent rule model (CVSS>=7 + EOL + exposed admin/DB + hygiene gaps), discounted by WAF/CDN presence; add firmographic proxies.
4. Use `sample.jsonl.zst` (91k records) for development; full file only for the final batch.
5. Accept that only ~9% of records link to a candidate domain; the output list will be domains, with company names via external enrichment.
