# UI spec (MVP)

Status: approved 2026-10-28 (incl. Jinja2 and the end-of-life sentence match as a known MVP shortcut);
built on `feature/ui` 2026-10-28; CSS-only polish on `feature/ui-polish` (tier badges, score bars, short reason tags with the full sentence on hover, header summary strip, sticky filter bar; no JavaScript, no data changes). Screenshots in `docs/screenshots/` come from a synthetic demo artifact (`scripts/demo_artifact.py`, `.example` domains, documentation IPs) so no real organisation is named in git (NFR5). `ARTIFACT_PATH` serves a local artifact without the release download (local runs, tests). Plain server-rendered HTML tables (D21: UI
polish is out of scope). Reads only the artifact tables `accounts`, `findings`, `manifest`.

## Rules for every page
- Basic auth and `X-Robots-Tag: noindex` on every response (already in place, NFR4 / NFR5).
- **Escape everything** derived from records (Jinja2 autoescape). No raw banners, no HTML from
  records, no JavaScript needed.
- Header on every page (FR6): snapshot `snapshot_from` to `snapshot_to`, input file, scoring
  config version, "research priority for external attack surface / vulnerability management".
- CVE wording is shown exactly as stored in `findings.sentence` ("potential match ..." or
  "verified match ..."); a one-line note explains "potential = matched from the banner's version,
  not verified".
- Deterministic order everywhere: `accounts.rank` (score, findings, domain).

## Pages
| Path | Purpose | Content |
|---|---|---|
| `/` | Ranked list (UC1, FR1, FR2a) | Filters as GET params (below). Table, 50 rows per page: rank, domain (link), score, tier, top 3 reasons (`reasons`), why-now markers, attribution label, eligibility label, IPs. Footer: total matching accounts. |
| `/account/{domain}` | Why it ranks (UC2, FR3) | Score, tier, eligibility + reason, attribution label. Breakdown: exposure / software / neglect points summing to the score. Findings table ordered by points: points, sentence, ip:port, module, product + version, CVEs (id, CVSS, EPSS, KEV, verified / potential), attribution (direct + source / via-IP), observed at. Then why-now markers and facts (0 points), labelled as such. |
| `/plays` | Plays (UC3, FR4) | The five plays with their buyer role (use-cases.md UC3) and account counts; each links to `/` with the play's filter. |
| `/export.csv` | Hand-off (FR5) | Same filters as `/`, all matching rows (no paging): rank, domain, score, tier, eligibility, attribution label, why-now, reasons joined by " / ". |

## Filters on `/` (GET params, all optional)
| Param | Values | Default | Source |
|---|---|---|---|
| `tier` | 1, 2, 3, ranked, all | ranked (tier > 0) | `accounts.tier` |
| `play` | exposed, exploited, eol, certs, appliances | none | see below |
| `why_now` | any, kev, cve_2026, cert_expiring | none | `accounts.why_now` |
| `gear` | appliance, cdn, none | none | `accounts.appliances`, `accounts.facts` |
| `eligibility` | default (hide likely non-prospects), likely_org, all | default | `accounts.eligibility` |
| `page` | 1.. | 1 | |

Plays as account filters: **exposed** = a `findings.kind = 'exposed_service'` row; **exploited** =
a `software` finding whose `cves` has `"kev": true`; **eol** = a `software` finding whose sentence
contains "end-of-life" (the artifact has no separate EOL flag; acceptable for the MVP, noted);
**certs** = `cert_expired` or `marker_cert_expiring`; **appliances** = non-empty
`accounts.appliances`.

## Implementation notes
- FastAPI + Jinja2 templates (one new dependency), one read-only DuckDB connection opened at
  startup on the downloaded artifact; queries use `LIMIT/OFFSET` and parameters, never string
  formatting of user input. Unknown filter values return 400.
- Tests: every page 200 with auth and 401 without; escaping (a domain / sentence containing
  `<script>` renders escaped); account breakdown sums to the score; CSV rows equal the filtered
  list; play counts equal their filtered list counts.
