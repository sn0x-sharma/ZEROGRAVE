# NTRS + TechPort — Document/Record-Level Access Control Audit

**Date:** 2026-08-01
**Scope:** ntrs.nasa.gov, techport.nasa.gov (both covered by `*.nasa.gov` wildcard scope)
**Headline results:** see `validated-findings/05-techport-file-endpoint-bola-no-parent-check.md`
(CRITICAL — TechPort file-serving BOLA) and
`validated-findings/06-ntrs-redistributions-restricted-distribution-disclosure.md` (LOW-MEDIUM —
NTRS metadata leak). This file documents the full methodology, including everything that was
tested and **ruled out**, per Rule 25 (differential testing) and the engagement's request for a
complete negative-result writeup where applicable.

---

## Part 1 — NTRS (ntrs.nasa.gov)

### API surface map (recovered from Angular bundle `main.<hash>.js`, ServiceStack-style
### typed client, backend is actually Node/NestJS behind `x-powered-by: appdat`)

| Path | Notes |
|---|---|
| `GET/POST /api/citations/search` | Main search, Elasticsearch-backed |
| `GET /api/citations/autocomplete` | Requires `field=` param; didn't find a valid value, low priority |
| `GET /api/citations/{id}` | Citation detail |
| `GET /api/citations/{id}/downloads` | List available downloads for a citation |
| `GET /api/citations/{id}/downloads/{filename}` | Actual file download |
| `GET /api/citations/redistributions` | **Unauthenticated leak — see finding 06** |
| `GET/POST /api/pubspace/search` | Separate, smaller index (author self-submitted content) |
| `POST /api/export`, `/api/export/csv`, `/api/export/xml` | Bulk export of *current search results* — re-runs the same (safely scoped) search, not an independent bypass vector |
| `GET /api/auth/user` | Returns 200 empty when unauthenticated; not pursued further (no auth flow in scope for this audit) |
| `GET /api/announcement`, `GET /api/health` | Non-sensitive |

`legacyMeta.__type: "LegacyMetaIndex, StrivesApi.ServiceModel"` seen in citation JSON is a
**carried-over string from the legacy .NET/ServiceStack STRIVES ingestion pipeline**, not the
live framework — confirmed by testing all standard ServiceStack reflection/metadata endpoints
(`/api/metadata`, `/api/types/typescript`, `/api/swagger.json`, etc.) which all 404 with a
NestJS-style JSON error body. This was a dead end, noted so it isn't re-tried.

### Citation ID scheme (clarifying the task brief)

The citation's own `id` field is a **numeric STI accession-derived integer**
(e.g. `19670009663`), confirmed as the correct ID for `/api/citations/{id}` (HTTP 200). The
UUID-hex string mentioned in the task brief (`b0df108a09c24c1487df17844a917bc2`) is the
**`copyright.id`** sub-object's own row ID (also `exportControl.id`, `authorAffiliations[].id`,
`cui.id` are separate hex IDs) — confirmed by testing it directly against `/api/citations/{id}`,
which returns `400 Validation failed (numeric string is expected)`. Not a vulnerability, just a
schema clarification for anyone continuing this audit.

### Distribution / classification taxonomy (recovered from the Angular submission-form bundle)

Full `distribution` enum (`"tb"` array in the bundle's embedded lookup table):
`PUBLIC`, `US_PERSONS`, `US_GOVERNMENT_AGENCIES_AND_GOVERNMENT_AGENCY_CONTRACTORS`,
`US_GOVERNMENT_AGENCIES`, `US_GOVERNMENT_AGENCIES_AND_NASA_CONTRACTORS`,
`NASA_CIVIL_SERVANTS_AND_NASA_CONTRACTORS`, `NASA_CIVIL_SERVANTS`, `OFFICE_ONLY`
("Distribution via Issuing Office Only"), `DO_NOT_DISTRIBUTE`.

Separately: `copyright.determinationType` includes at least `GOV_PUBLIC_USE_PERMITTED` (seen on
NTRS main index) and `MAY_INCLUDE_COPYRIGHT_MATERIAL` (seen on `pubspace` index) — a copyright
dimension, independent of the export-control (`exportControl.itar`/`.ear`) and CUI
(`cui.isCui`) dimensions also present on every citation object.

### Test 1 — RULED OUT: search-index segregation bypass

- `GET /api/citations/search?page.size=1` (no `q`) → `stats.total = 646398`,
  `aggregations.distribution.buckets = [{"key":"PUBLIC","doc_count":646398}]`. 100% public,
  full corpus.
- `GET /api/pubspace/search?page.size=1` → `stats.total = 51603`, same 100%-PUBLIC result.
- Explicit client-supplied `?distribution=US_GOVERNMENT_AGENCIES`,
  `?distribution=NASA_CIVIL_SERVANTS`, `?distribution=DO_NOT_DISTRIBUTE`,
  `?distribution=OFFICE_ONLY` → all return `total:0` (silently ANDed with an implicit
  PUBLIC-only constraint the client cannot override).
- Lucene-style field-query injection via the free-text `q` parameter
  (`q=distribution:LIMITED`, `q=cui.isCui:true`, `q=exportControl.itar:YES`) → all `total:0`;
  `q` is treated as literal free text, not passed through as a raw query-string/Lucene query.

**Verdict: properly secured.** Non-public documents are excluded from both public search
indices at the index level, not merely filtered at query time, and cannot be coaxed back in.

### Test 2 — RULED OUT: direct file/detail access for non-public documents discovered via `/redistributions`

Sourced 71 legitimately-disclosed non-public-distribution citation IDs from
`/api/citations/redistributions` (see finding 06) — no blind guessing, no brute force. Tested
a spread of 20 of them (3 initial + 17 broader sample across `US_GOVERNMENT_AGENCIES_AND_GOVERNMENT_AGENCY_CONTRACTORS`,
`NASA_CIVIL_SERVANTS`, `NASA_CIVIL_SERVANTS_AND_NASA_CONTRACTORS`, spanning submission years
1962–1964) against all three sibling endpoints:

| Endpoint | Result across all 20 IDs |
|---|---|
| `GET /api/citations/{id}` | 404 `{"statusCode":404,"message":"Not Found"}` — consistent |
| `GET /api/citations/{id}/downloads` | 404 `{"statusCode":404,"message":"Not Found"}` — consistent |
| `GET /api/citations/{id}/downloads/{id}.pdf` | 404 `{"statusCode":404,"message":"Not Found"}` — consistent |

Zero inconsistency, zero 200s. **Verdict: properly secured.** NTRS's citation-detail and
document-download handlers independently re-check distribution status server-side — they do
not merely rely on the search index being scoped. This is the correct, defense-in-depth
pattern and is the main reason the TechPort finding (which lacks this second check) is so much
more severe by contrast.

### Test 3 — field-selection / over-fetch (GraphQL-style pivot, adapted for REST)

Tried `field=exportControl&field=cui&field=sensitiveInformation` and `attachment=true` on
`/api/citations/search` to see if these params changed the response shape (analogous to the
OneUptime `select:{createdByUser:{resetPasswordToken:true}}` field-selection escalation
pattern). Neither had any observable effect — the endpoint returns the full object regardless
(exportControl/cui/sensitiveInformation are already present by default on every result), and
`attachment=true` didn't change the total count. Not exploitable; the gate that matters is at
the record level (whole record 404s for non-public IDs), not the field level.

### Rate limiting observed

`x-ratelimit-limit: 500` per window seen throughout testing; never got close to triggering it
(total NTRS request volume for this audit: roughly 90-100 requests across the whole session).

---

## Part 2 — TechPort (techport.nasa.gov)

See `validated-findings/05-techport-file-endpoint-bola-no-parent-check.md` for the primary,
critical finding (file-serving endpoints ignore `releaseStatus`/`internalOnly`). This section
covers secondary leads and ruled-out avenues.

### API surface map (recovered from Vite bundle `index-<hash>.js`; backend is Java/Spring —
### `Server: NASA/1.0`, `JSESSIONID` cookie)

`/api/projects`, `/api/projects/{id}`, `/api/projects/search` (GET, no nonce — see below),
`/api/projects/search/gridAttributes` / `/allAttributes` (POST, **nonce-protected**),
`/api/enums`, `/api/file/{id}`, `/api/file/presignedUrl/{id}`, `/api/contacts`,
`/api/organizations`, `/api/programs`, `/api/technologyOutcomes`, `/api/tags`, `/api/users`,
`/api/facilities`, `/api/dashboards`, `/api/feedback`, `/api/verify`, `/api/keepAlive`.
Note: `/api`, `/api-docs`, `/swagger`, `/publicApi/*` are all just the React SPA's `index.html`
catch-all (identical 1650-byte body) — not real API endpoints, despite returning HTTP 200. Only
paths explicitly referenced in the JS bundle's request-builder code are real.

### Secondary lead — NOT independently confirmed as an additional data exposure

`POST /api/projects/search/gridAttributes` (and `/allAttributes`) require a nonce:
```
{"code":401,"message":"No nonce was passed by the client... there may be hijacking going on!\nnull","redirect":true}
```
but the **plain `GET /api/projects/search`** (no query parameters at all) returns a large
(17MB+, response was still growing when I stopped the download after ~3,451 project records —
did not let it complete) unauthenticated JSON dump of full project records, with no nonce
requirement. This is a genuine method-based inconsistency (the skill's "HTTP method swap"
bypass pattern) worth NASA reviewing on principle, but:

- The `projectId` set observed in the partial GET dump (3,451 IDs) was a **strict subset** of
  the already-public `/api/projects` master listing (0 IDs exclusive to the GET dump) —
  i.e., within the portion I safely inspected, I did **not** find evidence this endpoint
  returns anything beyond what's already unauthenticated elsewhere.
- I deliberately did not let the 17MB+ download complete or push further into this endpoint
  (e.g., trying to add filter parameters to the GET variant to see if it accepts a
  `releaseStatus` override) — this felt like it was trending toward broad enumeration rather
  than targeted testing, and the primary file-endpoint finding already provides a decisive,
  well-evidenced result.
- **Recommendation for follow-up (not done here):** NASA should check server-side whether
  `GET /api/projects/search` without params applies the same `releaseStatus=Released` filter
  the frontend explicitly adds to its POST requests, or whether it's unscoped like the file
  endpoints.

### RULED OUT / inconclusive — could not confirm a Draft/Under_Review project ID directly

- Compared the master `/api/projects` listing (unauthenticated, 20,218 total, no visible
  `releaseStatus` field on list entries) against `/api/projects/{id}` detail lookups for the
  highest-numbered (newest) IDs in the list — all sampled were already `Released`.
- Computed **gaps** in the sequential ID space near the top of the range (270 missing IDs in
  the last 500 of the ID space — i.e., integers with no corresponding master-list entry) and
  tested a spread of 8 of them directly against `/api/projects/{id}` — all returned the
  generic `{"code":404,"message":"Object not found..."}`, indistinguishable from genuinely
  never-allocated IDs (`/api/projects/999999999`, `/api/projects/0` return the identical body).
  **Could not prove or disprove** whether these gaps are Draft projects correctly gated, or
  simply unused auto-increment values — the error message doesn't leak existence either way,
  which is itself good practice.
- Searched ~150 sampled library items (across ~90 project detail fetches: 75 random + 15
  "most recently updated") for any `internalOnly:true` entry — found **zero**. Either these
  are rare in the corpus, or (more likely, given the UI explicitly supports toggling this
  flag) the project-detail JSON response filters them out for anonymous callers — but I could
  not find a positive example to confirm the filtering claim directly.
- This is exactly *why* the file-endpoint finding (05) is reported the way it is: I could not
  cleanly produce "here is fileId X, which definitely belongs to a Draft project" as a single
  clean PoC. Instead, the finding is proven **structurally** — by the complete absence of any
  authorization signal (401/403) across 57 file-endpoint probes spanning the platform's entire
  upload history, contrasted against the project-detail endpoint's consistent, correct 404
  gating on the same class of ID. That contrast is sufficient proof of the missing check
  without needing to catch one specific restricted file in the act.

### Rate limiting / volume discipline

No rate limiting encountered on techport.nasa.gov during this audit. Total request volume:
roughly 90 project-detail fetches, 57 file-endpoint probes (each capped at a 24-byte body read
via streaming abort, except one deliberate full-body baseline fetch of a known-public file),
~5 schema/enum/JS-bundle fetches, 2 search-endpoint probes. No destructive actions, no write
operations, no login attempted, no brute-forcing of the full ID space.

---

## Summary table

| Target | Vector tested | Result |
|---|---|---|
| NTRS | Search-index segregation (main + pubspace) | **Ruled out** — properly secured, verified against full corpus |
| NTRS | Detail/download access for non-public docs (`/redistributions`-sourced IDs) | **Ruled out** — properly secured, 20/20 consistent 404 |
| NTRS | `field=`/`attachment=` over-fetch on search | **Ruled out** — no effect |
| NTRS | `/api/citations/redistributions` unauthenticated listing | **CONFIRMED** — finding 06 (Low-Medium) |
| TechPort | `/api/file/{id}` + `/api/file/presignedUrl/{id}` parent-object check | **CONFIRMED** — finding 05 (Critical) |
| TechPort | `GET /api/projects/search` nonce bypass vs POST | **Lead, not independently confirmed** — documented above for follow-up |
| TechPort | Draft/Deleted project direct-ID access (`/api/projects/{id}`) | **Ruled out / inconclusive** — consistently gated in every sample tested |
