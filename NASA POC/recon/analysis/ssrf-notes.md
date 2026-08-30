# SSRF Hunt — Ruled-Out Surfaces & Session Summary

**Date:** 2026-08-01
**Scope tested:** CMR, MMT, GIBS, data.nasa.gov (CKAN), images-api/images-admin.nasa.gov,
NTRS, TechPort, Harmony, AppEEARS, Giovanni (partial)
**Methodology:** SSRF-GODMODE skill (full bypass ladder + "real-world learnings" — hunted
specifically for the "validate/preview/attach a resource by URL" JSON-field shape, not classic
`?url=` GET params). OOB listener: `interactsh-client` →
`d9mthshg9qge45ph8cdg85s9fazwfe8pm.oast.fun` (stopped at end of session; 0 real callbacks — every
candidate SSRF-shaped parameter found was blocked by a pre-processing auth/schema wall before
reaching any actual fetch logic, so the listener never had a live target to confirm against).

## Already ruled out before this session (per task brief, not re-tested)
- `GET /wp-json/oembed/1.0/proxy?url=` (www.nasa.gov) — stock WP route, 401s correctly.
- `GET /wp-json/nasa-plus-video-url/v1/get?url=` (www.nasa.gov) — custom plugin, 401s correctly.

## Ruled out this session (with evidence)

### 1. data.nasa.gov (CKAN 2.11.5) — harvest extension + resource_create/package_create
Confirmed extensions installed: `harvest`, `ckan_harvester`, `datajson_harvest`, `datapusher`,
`launchpadlogin`, `s3filestore`. This is CKAN's textbook SSRF class (harvest source URL fetched
server-side by the harvester cron; `resource_create` + `datapusher` fetches a resource URL to
push into the datastore).
- `POST /api/3/action/harvest_source_create` (unauth) → schema help text confirms it proxies to
  `package_create`'s auth check. `GET /harvest/new` (UI create form, unauth) → `303 → /oauth/authorize`
  (Launchpad OAuth). **Properly gated — cannot create a malicious harvest source unauthenticated.**
- `POST /api/3/action/resource_create` (unauth, fake package_id) → `404 Not Found Error`.
- `POST /api/3/action/package_create` (unauth) → `403 Authorization Error: "Access denied: User
  not authorized to create packages"`. **Properly gated.**
- `GET /api/3/action/harvest_source_list` (unauth) → **200, publicly lists existing harvest
  sources** (read-only, this is normal/expected CKAN behavior) — BUT this incidentally leaked a
  live API token in one source's `config` field. **Not an SSRF finding** — see
  `validated-findings/03-data-nasa-gov-ckan-harvest-token-disclosure.md` (flagged per hard
  stop-and-flag-on-credentials rule, token was NOT used/tested).
- **Verdict: no reachable unauthenticated SSRF vector on data.nasa.gov's CKAN.** All write paths
  (the only paths that could plant/trigger a malicious URL fetch) are properly OAuth-gated.

### 2. CMR ingest + search — subscriptions (webhook-URL-on-new-data pattern)
This was the most promising a priori candidate (subscriptions = "notify a URL when new data
matches a query" is the canonical webhook-SSRF shape). **Ruled out structurally, not just by
auth** — confirmed via 3 independent probes that the schema has no URL/webhook field at all:
- `PUT /ingest/providers/{id}/subscriptions/{native-id}` with a body containing `EndpointURL` →
  `400 {"errors":["... extraneous key [EndpointURL] is not permitted"]}`.
- Same request with `EndpointURL` removed + minimal valid `MetadataSpecification` object added →
  `401 "You do not have permission to perform that action."` (schema now valid, auth now enforced
  — confirms the *only* thing missing before was the schema shape, not that EndpointURL is
  gated-but-real).
- `graphql.earthdata.nasa.gov/api` introspection of `CreateSubscriptionInput`/
  `UpdateSubscriptionInput` → fields are exactly `collectionConceptId, name, nativeId,
  subscriberId, query, type`. No URL field at either the REST ingest layer or the GraphQL layer.
- **Verdict: CMR subscriptions deliver via email only (`subscriberId`+account email on file) —
  there is no attacker-controllable webhook URL to inject, with or without auth.** This corrects
  a killed-agent's unverified note (see `harmony-destinationurl-shape-LEAD-needs-creds.md` for
  the full correction) — don't spend a future EDL credential re-testing this.

### 3. MMT (mmt.earthdata.nasa.gov) — Tool/Service record URL fields via `ingestDraft`
MMT is a static React SPA (S3+CloudFront) with zero server-side logic of its own; all writes go
through `graphql.earthdata.nasa.gov/api` → CMR ingest (Lambda/Node backend, confirmed via stack
trace — see below). Tool/Service UMM records do have real `URL.URLValue` fields.
- `mutation { ingestDraft(conceptType: Tool, ..., metadata: {..., URL:{URLValue:
  "http://169.254.169.254/latest/meta-data/", ...}}) }` (unauth) →
  `{"errors":[{"message":"You do not have permission to perform that action.", "extensions":
  {"stacktrace":["...at $l.parseIngest","...at draftSourceIngest","...at ingestDraft"]}}]}`.
  **Properly gated** (permission check present). Stack trace shows the call path is pure
  parse→store (`parseIngest`/`draftSourceIngest`) with no evidence of any outbound-fetch step —
  consistent with MMT/CMR's architecture as a metadata catalog that stores but does not resolve
  provider URLs (makes sense: CMR catalogs ~50 independent DAAC providers' service endpoints; it
  would be architecturally reckless for the catalog itself to blindly fetch every curator-entered
  URL). Verbose stack trace itself is not reportable (NASA policy explicitly excludes "issues
  related to descriptive or verbose error messages").
- Grepped the full MMT JS bundle (`index-D1G4yEOq.js`, 3.4MB) for any client-side "test
  URL"/"verify connection"/"GetCapabilities-on-save" UX — none found. The `GetCapabilities` string
  hits are just static JSON-schema `enum` values for the UMM-S form (documentation strings, not
  fetch logic).
- **Verdict: no evidence of server-side URL fetch behind the Tool/Service URL fields, gated or
  not.** Auth wall is real; underlying feature doesn't appear to fetch URLs at all even for
  authenticated users.
- `draftmmt.earthdata.nasa.gov` — connection failure (`000`) from external vantage point, does
  not resolve/respond publicly. Not pursued further (likely genuinely internal/VPN-gated, which
  is explicitly out of scope per program policy).

### 4. GIBS (gibs.earthdata.nasa.gov + gibs-a/b/c) — WMS/WMTS tile server
Confirmed running MapServer (`wms.cgi`). Explicitly tested the classic MapServer `map=` CGI
variable SSRF/path-traversal class (historically CVE-2020-27837/CVE-2020-27838-adjacent
misconfig pattern — unrestricted `map=` lets a caller point MapServer at an arbitrary
external/internal mapfile URL):
```
GET /wms/epsg4326/best/wms.cgi?map=http://169.254.169.254/latest/meta-data/&SERVICE=WMS&REQUEST=GetCapabilities
→ 200, body: "msCGILoadMap(): Web application error. CGI variable "map" fails to validate."
```
**Confirmed hardened** — MapServer's `MS_MAP_NO_PATH`/`MS_MAP_PATTERN`-style restriction is
active and explicitly rejects the parameter. No other proxy-shaped params found on GIBS.

### 5. images-api.nasa.gov / images-admin.nasa.gov
`images-api.nasa.gov` is the documented public read-only NASA Image & Video Library search/asset
API (`/search`, `/asset/{id}`) — no thumbnail-from-URL, avatar-from-URL, or import-by-URL feature
found in any response schema. `images-admin.nasa.gov` cleanly `301`s to `https://images.nasa.gov/login`
for every path tested — no pre-auth surface reachable (proper auth gate, admin backend
inaccessible without NASA staff credentials).

### 6. AppEEARS (appeears.earthdatacloud.nasa.gov)
Area/point sample-request schema (`/api/examples/sample_area_request.json`) takes an **inline**
GeoJSON `geo` polygon object directly in the request body — not a URL reference to an
externally-hosted shapefile. No URL-fetch field found. Task submission additionally requires EDL
auth regardless. **Ruled out** — no SSRF-shaped field exists here (different from Harmony's
`shape` param, which explicitly documents accepting file references).

### 7. NTRS (ntrs.nasa.gov)
Citation search API (`POST /api/citations/search`) is read-only; result object fields
(`downloads`, `related`, `publications`, etc.) reflect already-stored data, not
submission/import-by-URL inputs. `/api/submissions` → 404. No unauthenticated URL-accepting write
endpoint found within time budget. (IDOR/enumeration on NTRS is explicitly another agent's lane
per task brief — not duplicated here.)

### 8. TechPort (techport.nasa.gov)
Read-only public project-portfolio API (`/api/projects`, standard per api.nasa.gov docs).
`/api/swagger.json` → 404; `/api-docs` is a JS-rendered SPA I could not inspect further via curl
(would need a browser-render pass). No write/URL-import endpoint found within time budget —
consistent with TechPort's documented read-only design, but flagging as "not found" rather than
"structurally absent" since the api-docs SPA content wasn't fully enumerable.

### 9. `*.intsvc.cloud.earthdata.nasa.gov` (internal-service naming pattern)
Confirmed genuinely unreachable from external vantage point (`curl` → connection failure/`000`,
`dig` → no answer) — good baseline for this hostname pattern as a future internal-reachability
oracle. **Never used as an active SSRF payload target this session** because no candidate
endpoint (Harmony, MMT, CMR, CKAN) got past its pre-processing auth/schema wall to reach actual
fetch logic — there was no live vulnerable fetch to point at it. If a future session finds an
endpoint that DOES reach fetch logic (e.g., Harmony with valid EDL creds), this hostname pattern
is the right internal-reachability probe to try first.

## Inconclusive / not reachable
- **Giovanni** (`service.giovanni.earthdata.nasa.gov`) — connection failure (`000`) from this
  vantage point at time of testing. Not ruled out, just not reachable to test; worth a retry in a
  future session (could be transient).
- **data.nasa.gov root path flakiness** — intermittently returned `000` on fresh connections (2
  of 3 attempts), then `200` on retry, while CKAN API sub-paths on the same host responded
  reliably. Not itself a finding (no exploitable behavior, just connection-level flakiness/possible
  rate limiting) — noted in case a future session sees the same pattern and wonders if it's
  environmental or a target-side quirk.

## Live lead requiring credentials (not ruled out, not confirmed)
See `harmony-destinationurl-shape-LEAD-needs-creds.md` — Harmony's `destinationUrl` (explicitly
`s3://`-scheme-restricted per public docs) and `shape` (file/URL for spatial subsetting) params
on the OGC Coverages API are architecturally the best-shaped SSRF candidate found this session
(Harmony's whole purpose is server-side data fetching, unlike CMR/MMT which are pure metadata
catalogs). Blocked end-to-end by a clean, payload-independent Earthdata Login OAuth 303 redirect
— confirmed via differential testing (4 payload variants, identical redirect every time). Needs
an EDL test account to proceed.

## Summary for Brain / next SSRF pass
- **CONFIRMED (this session):** 0 SSRF findings meeting the HTTP-layer-signal bar.
- **POTENTIAL:** Harmony `destinationUrl`/`shape` — needs EDL credentials to test past the auth
  wall. Highest-value remaining SSRF lead on this program.
- **EXHAUSTED (real evidence, not just "didn't look"):** CKAN harvest/resource_create/package_create
  (data.nasa.gov), CMR subscriptions (REST + GraphQL, structurally no URL field), MMT ingestDraft
  (permission-gated + no fetch-behavior evidence), GIBS MapServer `map=` (explicitly hardened),
  images-api/images-admin (read-only / auth-gated), AppEEARS (inline geo, no URL field).
- **WAF/filtering behavior observed:** none of the tested surfaces returned WAF-style blocks —
  every negative result was a clean application-level auth (303/401/403) or schema (400) response,
  not a filter/WAF signature. No bypass-ladder iteration was needed because nothing got far enough
  to have a filter to bypass — the blockers were all pre-processing auth walls, not input filters.
- **Follow-up needed:** (1) obtain an Earthdata Login test account to re-test Harmony; (2) retry
  Giovanni connectivity; (3) browser-render pass on TechPort's `/api-docs` SPA to see the full
  endpoint list; (4) NASA should rotate the credential in
  `validated-findings/03-data-nasa-gov-ckan-harvest-token-disclosure.md` regardless of SSRF outcome.
