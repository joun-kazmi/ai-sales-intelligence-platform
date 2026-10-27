# MVP scope and plan

Status: agreed 2026-10-27, revised the same day after external review. Due **Fri 2026-10-30**.
Decisions D21-D22, D33, D37 in `docs/DECISIONS.md`.

## In scope
- Pipeline: extract, attribution, findings + score, funnel, manifest, eval C1 / C2 / C4
  (FR7-FR10), run locally.
- App: ranked list, minimal filters, plays with buyer roles, account detail, CSV export, snapshot
  info (FR1, FR2a, FR3-FR6), basic auth, noindex, on Render free tier, artifact downloaded from a
  private release.
- Write-up in the README: approach, key decisions, measurement results, scale story, how AI was
  used in the development workflow.

## Cuts

| Cut | Reason |
|---|---|
| FR11 / UC4 coverage-aware merge, C5 | One file; designed in `architecture.md` |
| Queue, workers, object storage, cold raw retention | Design only; the same extract code runs on a local process pool |
| Any LLM (labeller and classifier) | One human-labelled, blind eval is the measurement; the classifier stays design only (D28) |
| C3 (KEV lift) | Cut by review; C1, C2, C4 remain |
| Country filter | Not in the brief; weak proxy (D29) |
| "Recently went end-of-life" | No EOL dates in the file (D2) |
| CRM push, enrichment, contact discovery, outreach drafting | Outside the brief (D5) |
| UI polish; broad test suite | Plain server-rendered tables; unit tests on attribution, scoring rules and app auth |

**Cut order if slipping:** (1) industry / display-name heuristics, (2) extra filters (FR2b),
(3) weaker signals (neglect items first). **Never cut:** attribution quality, evidence on every
finding, the human eval (C2), the hosted list, the write-up.

## Plan

| When | Engineering | Owner |
|---|---|---|
| Tue 10-27 | Bare app (basic auth, noindex), Dockerfile, `render.yaml` (done) | Connect Render, set env vars |
| Wed 10-28 AM | Extract (name candidates, infra classes, projected fields, manifest, atomic writes) and the attribution key; run on the line sample. App: artifact download from a private release (token in env), size cap check | Create the private release and fine-grained read-only token |
| Wed midday | | **Full-file extraction run** (measures extractor throughput) and the domain-complete sample build |
| Wed PM | Attribution, findings, scoring on the sample; ubiquitous-CVE measurement; feature-layer size vs raw. **Deploy through the real artifact-download path** with a sample artifact | Upload the sample artifact to the release |
| Thu 10-29 AM | Tune on the sample, then **freeze weights**. Eval: C1 DNS script, blind label pool export, C4 | Run DNS script; label <= 60 accounts (< 1 h) |
| Thu PM | App: list, detail, plays, CSV | |
| Thu eve | | Score the full feature layer (no re-extraction); upload the full artifact (hard cap enforced) |
| Fri 10-30 AM | Eval results (precision@20, C1 forward-DNS match rate, C4); fix-only changes, no weight changes | |
| Fri PM | README write-up | Final check; submit with the credentials note |

**Throughput claims:** only measured figures are quoted. Full-file extract: 9 min 07 s on 8 cores
/ 7 workers, ~26.7k records/s, peak RSS ~0.5 GB, feature layer 1.03 GB [M] (DATA_NOTES 5c).

**Weights frozen** 2026-10-28 at scoring config `765eef67e0c5` (D50), ahead of the Thursday-morning
slot; labelling can start once the label pool is exported.

**UI spec:** `docs/design/ui.md` (Thursday build).

**Write-up must state:** prospect eligibility leaves 72% of accounts "uncertain"; the label hides
the obvious non-prospects and does not classify the rest.

**Hosted artifact hard cap: 100 MB** (NFR3). Publishing fails above it; the fallback is Tier 1-2
accounts with full evidence plus counts for the rest.
