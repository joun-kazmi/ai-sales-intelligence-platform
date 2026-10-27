# MVP scope and plan

Status: agreed 2026-10-27. Due **Fri 2026-10-30**. Decisions D21-D22 in `docs/DECISIONS.md`.

## In scope
- Pipeline: extract, resolve, findings + score, funnel, eval (FR7-FR10), run locally on one file.
- App: ranked list, minimal filters, plays, account detail, CSV export, snapshot info
  (FR1, FR2a, FR3-FR6), basic auth, noindex, on Render free tier.
- LLM: the C2 labelling assistant only, with kappa and real token cost (D18).
- Write-up in the README: approach, key decisions, measurement results, LLM cost, scale story.

## Cuts
| Cut | Reason |
|---|---|
| FR11 / UC4 coverage-aware merge, C5 temporal validation | One file; designed in `architecture.md` |
| Queue, workers, object storage, cold raw retention | Design only; the same extract code runs on a local process pool |
| LLM account classifier | TLD / keyword rules cover industry and display name; build only with spare time |
| FR2b (confidence, country) and FR2c (industry) filters | Nice to have |
| "Recently went end-of-life" | No EOL dates in the file, low coverage (D2) |
| Points for CVE-2026 IDs | Unverified until the owner's spot-check (D2) |
| CRM push, enrichment, contact discovery, outreach drafting | Outside the brief (D5) |
| UI polish | Plain server-rendered tables; the brief says the UI is not the point |
| Broad test suite | Unit tests on entity-resolution and scoring rules, plus app auth |

## Plan
| When | Engineering | Owner |
|---|---|---|
| Tue 10-27 (eve) | Repo skeleton; bare app (hello world + basic auth + noindex) with Dockerfile and `render.yaml` | Connect the repo to Render and set env vars |
| Wed 10-28 AM | Bare deploy live on Render (hosting risk first). Extract + pass 1 / pass 2 key function; run on the line sample; seed the infra blocklist | |
| Wed midday | | Build the domain-complete sample with that code (~30 min) |
| Wed PM | Resolve, findings, scoring config, funnel; set K and tier thresholds from the sample; measure feature-layer size vs raw | CVE-2026 spot-check, update DATA_NOTES 5b |
| Thu 10-29 AM | Eval command: baselines, label pool, LLM labeller with cost logging, C3, C4; DNS confirmation script | Run the DNS script; label 60 accounts (< 1 h) |
| Thu PM | App: list, detail, plays, CSV; artifact download from the private release; deploy with the sample artifact | Create the fine-grained token |
| Thu eve | | Full-file run (2 x ~13 min + scoring); upload the artifact to the private release |
| Fri 10-30 AM | One round of weight tuning against C2; kappa and precision results | |
| Fri PM | README write-up | Final check; submit with the credentials note |

**Main risk:** the full-file artifact is too large for the free instance. Fallback: publish Tier 1-2
accounts with full evidence, plus counts for the rest.
