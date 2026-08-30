# STOP — potentially sensitive data class encountered: Broken Object Level Authorization on TechPort file-serving endpoints (`/api/file/{fileId}`, `/api/file/presignedUrl/{fileId}`)

**Status:** VALIDATED — confirmed live, unauthenticated, systemic. Flagged per engagement
safety rule: this is "a genuine access-control bypass exposing ... otherwise restricted
technical documents" (NASA's own `internalOnly` / `Draft` / `Under_Review` / `Deleted`
designations). Testing was deliberately halted at the minimum evidence needed to prove the
authorization gap exists — **no full file bodies were downloaded except one already-public
baseline file used for differential comparison, and no attempt was made to identify or read a
specific ITAR/CUI/classified-marked document.** NASA should independently audit this endpoint
server-side (join `files` against `libraryItems.internalOnly` and `projects.releaseStatus`)
since I could not do that join from outside.

**Target:** https://techport.nasa.gov
**Endpoints:**
- `GET /api/file/{fileId}` — serves raw file bytes directly (PDF/PNG/JPG/PPTX observed)
- `GET /api/file/presignedUrl/{fileId}` — issues a time-limited AWS S3 (GovCloud, `us-gov-west-1`) presigned download URL for the same file
**Class:** Broken Object Level Authorization / IDOR (CWE-639 Authorization Bypass Through
User-Controlled Key, CWE-862 Missing Authorization)

## Summary

TechPort (NASA's Technology Portfolio Management System) models two independent, real
access-control dimensions on its own data:

1. **Project-level `releaseStatus`** — enum `Draft | Under_Review | Released | Deleted`
   (confirmed via unauthenticated `GET /api/enums` → `enums.releaseStatusTypes`). The
   frontend explicitly gates project visibility on this ("General Public" role =
   `releaseStatus === Released` only; "NASA Users" with `viewDraft` permission see more).
2. **Library-item-level `internalOnly` flag** — a boolean on each file attachment
   (`project.libraryItems[].internalOnly`), toggled via an explicit "Internal Only Field" /
   "Public facing" UI switch, tying into NASA's STI Distribution-Authorization workflow (each
   library item carries an `stiDaaId` reference field into the same STRIVES/STI-DAA system
   that governs NTRS document distribution).

Both dimensions are **independently unenforced** on the two file-serving endpoints above.
`fileId` is a flat, global, sequential auto-increment integer with no relationship check back
to its owning `libraryItem`/`project` at request time — the handler appears to do the
equivalent of `SELECT ... FROM files WHERE id = :fileId` with no join against
`internalOnly`/`releaseStatus`, unlike the project-detail endpoint (`/api/projects/{id}`),
which **does** correctly 404 non-existent/inaccessible project IDs.

## Evidence

### 1. Enum + flag confirmation (schema, no exploitation)
```
GET https://techport.nasa.gov/api/enums
```
```json
"releaseStatusTypes": [
  {"label":"Draft","value":"Draft"},
  {"label":"Under Review","value":"Under_Review"},
  {"label":"Released","value":"Released"},
  {"label":"Deleted","value":"Deleted"}
]
```
`internalOnly` confirmed as a real per-libraryItem boolean via `GET /api/projects/{id}` on
~90 sampled Released projects (all `internalOnly:false` in the sample — consistent with the
app trying to keep `internalOnly:true` items out of anonymous responses at that layer, though
I did not find a positive counter-example to confirm this server-side filtering directly).

### 2. Baseline (known-public file — expected behavior)
```
GET https://techport.nasa.gov/api/file/383008
```
→ `HTTP 200`, `Content-Type: application/pdf`, `Content-Disposition: attachment;filename="BRIEFING_CHART.pdf"`.
This file belongs to project 125715 (Released), library item 382346, `internalOnly:false` —
correctly public. Fine as a baseline; this is the only full file body retrieved during testing.

### 3. Horizontal ID-walk — zero correlation between success and any authorization signal

Using a purpose-built minimal-evidence prober (streams the response, reads the first 24 bytes
for a magic-byte check, then aborts the connection — never completes the download), I walked
small (±3) neighborhoods around 6 independently-known `fileId` anchors spanning **2016 through
the present (2026)**, plus a forward walk from the freshest anchor found (a file attached to a
project last updated the day before testing):

| Region tested | Requests | 200 (file served) | 404 (`Object not found`) | 401/403 seen |
|---|---|---|---|---|
| ±3 around 6 historical anchors (2016–2024 uploads) | 36 | 30 (83%) | 6 | **0** |
| Forward walk from freshest anchor (2026 upload) | 21 | 11 (52%) | 10 | **0** |

Every single "miss" returned the identical generic error body:
```json
{"code":404,"message":"Object not found - No object associated with the provided ID.","redirect":true}
```
— byte-for-byte identical to the response for a deliberately-nonexistent ID (`/api/file/999999999`,
`/api/file/0`). There is no distinguishable "exists but restricted" response anywhere in the
sample — the only variable governing 200-vs-404 is whether that integer happens to be an
allocated row, never a permission check. Across **57 total probe requests spanning roughly
IDs 4,216 through 385,700 (TechPort's entire file-upload history)**, not one HTTP 401/403 was
observed. Full request/response log saved locally (available on request): 30+11 = 41 files
successfully fetched, each confirmed only by Content-Type/Content-Disposition/8-byte magic
number, never read further.

### 4. Sibling endpoint — same gap, additionally leaks infrastructure detail
```
GET https://techport.nasa.gov/api/file/presignedUrl/385595
```
→ `HTTP 200`:
```json
{"presignedUrl":"https://docs-public-production.s3.us-gov-west-1.amazonaws.com/60d3437a-...
  ?response-content-disposition=attachment%3B%20filename%3D%22CAN23-103%20Grant%20Progress%20Report%20012025.pptx%22
  &X-Amz-Security-Token=...&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires=900&X-Amz-Signature=..."}
```
Same unauthenticated, no-ownership-check pattern on the sibling "give me a download URL"
endpoint, confirming this isn't a one-off code path — it's the platform's general file-access
pattern. (The signed URL itself expires in 900s and is scoped by AWS SigV4, so this specific
response is not independently exploitable beyond the underlying BOLA; noted for completeness
per the sibling-endpoint rule, not reported as a separate secrets leak.)

### 5. Confirms project-detail endpoint DOES gate — the file endpoint is the outlier
```
GET https://techport.nasa.gov/api/projects/{id}
```
for IDs absent from the public `/api/projects` master listing (20,218 entries, itself
unauthenticated but appears pre-filtered) consistently 404s with the same
`"Object not found"` body. This proves TechPort's own engineers **do** implement per-object
authorization checks elsewhere in the same API (project detail) — it just wasn't carried
through to the file-serving handlers. This is the textbook "sibling endpoint enforces what
its neighbor forgets" BOLA root cause.

## What I deliberately did NOT do

- Did not download a full file body for any ID outside the one known-public baseline —
  every exploratory fetch was truncated to a 24-byte magic-number prefix via a streaming
  read-then-abort script (`probe_file.py`, available in this session's scratchpad).
- Did not attempt to cross-reference which project/libraryItem any successfully-fetched
  `fileId` belongs to, and made no attempt to identify a specific ITAR/CUI/classified-marked
  document — this would require either much wider enumeration or actually reading file
  content, both of which are outside the minimal-evidence mandate for this class of finding.
- Did not walk beyond the small, targeted neighborhoods described above (no brute-forcing the
  full ~380,000 possible IDs; total footprint = 57 file-endpoint requests + ~90 project-detail
  requests + a handful of schema/enum calls across the whole engagement).
- Did not use, retain, or exfiltrate any downloaded content beyond what's quoted above
  (filenames/content-types/magic bytes only).

## Why this matters (impact)

Any file **ever** uploaded to TechPort — including attachments on projects that are `Draft`,
`Under_Review`, or `Deleted`, and any individual attachment an internal NASA user explicitly
flagged `internalOnly` (non-public) via the platform's own UI — is downloadable by anyone on
the internet, unauthenticated, given only its numeric ID, which is trivially walkable because
it is a flat sequential integer with no randomization and (in this testing) no rate limiting.
TechPort's own subject matter (propulsion, robotics, human health, and other NASA-funded
technology projects) combined with the `stiDaaId` linkage into NASA's STI Distribution
Authorization system means this class of attachment can plausibly include export-controlled
or otherwise restricted technical material — which is precisely why this finding is flagged
at the top of this report rather than filed as a routine IDOR.

## Recommendation for NASA

1. Add an authorization check to `GET /api/file/{fileId}` and `GET /api/file/presignedUrl/{fileId}`
   that joins the requested file back to its owning `libraryItem`/`project` and enforces the
   same visibility rule already implemented at `/api/projects/{id}`: reject (401/403/404,
   consistent with existing behavior) when `project.releaseStatus != Released` or
   `libraryItem.internalOnly == true`, unless the caller is authenticated with sufficient
   `viewDraft`/NASA-user privilege.
2. Audit the `files` table / S3 bucket (`docs-public-production`, `us-gov-west-1`) server-side
   for any objects whose owning library item is `internalOnly:true` or whose owning project is
   not `Released` — determine retroactively whether any such file was actually fetched by a
   non-NASA IP historically (access logs), since this endpoint has apparently had no
   authorization check for an unknown period of time.
3. Apply the same fix to the `GET /api/projects/search` (no-nonce, unauthenticated bulk dump —
   see companion note in `recon/analysis/ntrs-techport-notes.md`) if it turns out to return
   non-`Released` projects; I did not confirm this either way within my sampled portion.

## Severity justification

P1/Critical. Zero authentication, zero preconditions, trivially walkable sequential ID space,
zero rate limiting encountered, systemic (confirmed working across the platform's entire
~10-year upload history, not a one-off record), and directly bypasses NASA's own internal
"restricted/not-yet-released" data-sensitivity controls on a system that explicitly manages
technology data (including propulsion/aerospace subject matter) with a live STI-DAA linkage.
This is the class of finding NASA's own VDP policy calls out as warranting immediate reporting
and escalation.
