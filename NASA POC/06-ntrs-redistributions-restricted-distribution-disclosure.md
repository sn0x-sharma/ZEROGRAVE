# Unauthenticated Disclosure of Restricted-Distribution Document Existence + Classification — ntrs.nasa.gov

**Status:** Validated (confirmed live, low/medium impact — metadata-only, NOT a content leak;
see companion ruled-out testing in `recon/analysis/ntrs-techport-notes.md` for the more severe
hypothesis that was tested and disproven). Same bug class as
`01-nasa-gov-unpublished-content-index-disclosure.md` (missing authorization on an internal
listing route), higher sensitivity of the data disclosed.

**Target:** https://ntrs.nasa.gov
**Endpoint:** `GET /api/citations/redistributions`
**Class:** Broken Access Control / Information Disclosure (CWE-862 Missing Authorization)

## Summary

NTRS's public search API (`/api/citations/search`) and its "pubspace" variant
(`/api/pubspace/search`) are both correctly index-segregated: verified across their **full**
corpora (646,398 and 51,603 records respectively, via blank-query aggregation) that
`distribution` is **100% `PUBLIC`** — non-public STI distribution categories are not present
in the searchable index at all, and a client-supplied `distribution=` filter for a non-public
value is silently ignored (0 results), confirming the server does not trust client-supplied
distribution filters. This is good design.

However, a separate, undocumented (not linked from the search UI) endpoint —
`GET /api/citations/redistributions` — is fully unauthenticated and returns a paginated feed
of documents whose distribution/dissemination status has been formally reconsidered, **including
current non-public distribution categories**:

```
GET https://ntrs.nasa.gov/api/citations/redistributions?page.size=100
```
```json
{"stats":{"total":2802},"results":[
  {"disseminated":"DOCUMENT_AND_METADATA","id":19620004432,
   "distribution":"US_GOVERNMENT_AGENCIES_AND_GOVERNMENT_AGENCY_CONTRACTORS",
   "redistributedDate":"2024-01-24T12:34:58.8808480"},
  {"disseminated":"DOCUMENT_AND_METADATA","id":19630000658,
   "distribution":"NASA_CIVIL_SERVANTS","redistributedDate":"2025-10-09T21:00:37.9851490"},
  ...
]}
```

Fields disclosed per record: internal numeric citation ID, current `distribution`
classification tier (full taxonomy recovered from the Angular submission-form bundle:
`PUBLIC`, `US_PERSONS`, `US_GOVERNMENT_AGENCIES_AND_GOVERNMENT_AGENCY_CONTRACTORS`,
`US_GOVERNMENT_AGENCIES`, `US_GOVERNMENT_AGENCIES_AND_NASA_CONTRACTORS`,
`NASA_CIVIL_SERVANTS_AND_NASA_CONTRACTORS`, `NASA_CIVIL_SERVANTS`, `OFFICE_ONLY`,
`DO_NOT_DISTRIBUTE`), `disseminated` flag (whether an actual document file is attached —
`DOCUMENT_AND_METADATA` vs `METADATA_ONLY`), and a `redistributedDate` timestamp.

In a single 100-record page: **78 of 100 (78%)** were non-`PUBLIC` distribution, of which
**54 had `disseminated:DOCUMENT_AND_METADATA`** (a file exists on the backend for that
record). Total feed size: 2,802 records.

**No title, abstract, author, or document content is exposed by this endpoint** — only
existence + classification tier + file-presence boolean + date. See the companion note for
why this does *not* extend to actual content access (tested and ruled out — NTRS's
detail/download endpoints independently re-check distribution status and consistently 404
for every one of the 20 non-public IDs I cross-tested from this feed).

## PoC

```bash
curl -s "https://ntrs.nasa.gov/api/citations/redistributions?page.size=100"
```
No auth header, cookie, or nonce required. Confirmed reproducible across multiple requests
(page.size caps at 100 server-side; `total:2802` is stable across repeated calls).

## Impact

An unauthenticated attacker can learn, at scale (2,802 records) and with zero
preconditions: which specific NASA STI accession numbers are currently restricted from public
release, their exact restriction tier (e.g. "NASA civil servants only" vs "US Government
agencies and their contractors"), whether a document file exists for that restricted record,
and when the restriction determination was made. This is an embargo/classification-tier
oracle — while it doesn't leak the document itself, it discloses which historical NASA
technical work products NASA has deliberately chosen to keep non-public, which is itself
sensitive metadata in an export-control-conscious federal context. Combined with adjacent
public-record metadata from the same era/center (title/subject-category patterns from
neighboring accession numbers), this could assist an adversary in prioritizing FOIA requests,
social-engineering targets, or areas of NASA technical work to focus further reconnaissance on.

## Root cause

Same pattern as the already-logged `www.nasa.gov` finding: an internal/admin-facing listing
route (likely built for the STI curation team to audit recent redistribution decisions) shipped
without a `permission_callback`/auth guard, reachable by anyone who finds the route (recovered
here from the Angular frontend's typed API client constants —
`SearchControllerGetRedistributedPath="/citations/redistributions"` — not linked from any
public-facing search UI).

## Recommendation for NASA

1. Require authentication (STI curator role) on `GET /api/citations/redistributions`, consistent
   with how the detail/download endpoints already correctly gate non-public records.
2. Audit other `SearchController*`/`ExportController*` routes recovered from the same JS bundle
   for the same missing-auth pattern (full route list documented in
   `recon/analysis/ntrs-techport-notes.md`).

## Severity justification

P3 (Low-Medium). Real, reproducible, unauthenticated, at meaningful scale (2,802 records), and
discloses genuinely sensitive classification metadata about federal technical documents — more
sensitive than the already-logged WordPress draft-index finding, but capped in severity because
it is existence/classification-only, not content. Not on NASA's never-submit list. The more
severe hypothesis (does this let you actually read a restricted document) was tested rigorously
and ruled out — see `recon/analysis/ntrs-techport-notes.md`.
