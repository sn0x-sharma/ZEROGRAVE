# LEAD (unconfirmed, needs real Earthdata Login/EDL account) — `destinationUrl`/`shape` params on Harmony OGC Coverages API

**Status:** Investigated, NOT exploitable pre-auth — needs an authenticated pass. Do not report as-is.
**Host:** `harmony.earthdata.nasa.gov` (EOSDIS data transformation/subsetting service, CloudFront-fronted, live)

## What's real
Harmony's public API docs (`https://harmony.earthdata.nasa.gov/docs`) document two URL-shaped
parameters on the OGC Coverages rangeset endpoint
(`/{collectionId}/ogc-api-coverages/1.0.0/collections/{variable}/coverage/rangeset`):

1. **`destinationUrl`** — "destination url specified by the client; **currently only s3 link
   urls are supported** (e.g. `s3://my-bucket-name/mypath`) and will result in the job being run
   asynchronously." The phrase "currently only ... supported" is exactly the shape of a
   scheme-allowlist that's worth testing for bypass (does the validator do a strict URL-scheme
   parse, or a naive `.startswith('s3://')` / regex check that something like
   `s3://legit-bucket@169.254.169.254/x` or a parser-differential payload could slip past?).
2. **`shape`** — POST `multipart/form-data` field: "perform a shapefile subsetting request on a
   supported collection by passing the path to a GeoJSON file (*.json/.geojson), an ESRI
   Shapefile (.zip/.shz), or a kml file (.kml)". Worth testing whether this field also accepts a
   remote URL string (not just a multipart file upload) — many "shape upload" implementations
   backing spatial subsetting tools fetch the referenced file server-side.

Both match the task brief's highest-yield SSRF shape ("validate/preview/attach a resource by URL
before using it") and Harmony's own architecture is uniquely suited to it — its entire job is
fetching and transforming real granule data server-side, unlike CMR/MMT which are pure metadata
catalogs (see ssrf-notes.md — CMR/MMT do NOT fetch the URLs they catalog).

## What I disproved
Every request to the rangeset endpoint — regardless of query params — returns an **identical**
`303 See Other → https://urs.earthdata.nasa.gov/oauth/authorize?...` (Earthdata Login OAuth). This
was confirmed as **payload-independent** (Rule 25 differential testing) across 4 variants:
```bash
# baseline, no special params
curl -s -w "%{http_code}" "https://harmony.earthdata.nasa.gov/C1234208438-POCLOUD/ogc-api-coverages/1.0.0/collections/bathymetry/coverage/rangeset"
# → 303, same redirect

# SSRF payload
curl -s -w "%{http_code}" ".../rangeset?destinationUrl=http://169.254.169.254/latest/meta-data/"
# → 303, IDENTICAL redirect (same state param structure, same target)

# valid-shaped s3:// (should be the "happy path")
curl -s -w "%{http_code}" ".../rangeset?destinationUrl=s3://legit-test-bucket/path"
# → 303, IDENTICAL redirect

# garbage value
curl -s -w "%{http_code}" ".../rangeset?destinationUrl=not-a-url-at-all"
# → 303, IDENTICAL redirect

# shape param with SSRF payload
curl -s -w "%{http_code}" ".../rangeset?shape=http://169.254.169.254/latest/meta-data/"
# → 303, IDENTICAL redirect
```
This means Earthdata Login (EDL) OAuth middleware runs **before** any query-param/business-logic
processing — there is zero differential signal pre-auth (no timing difference, no distinct error
class), unlike the CMR ingest schema-validates-before-auth pattern (see ssrf-notes.md). Confirmed
this isn't a blanket "every Harmony path needs auth" — `/docs`, `/versions` are public 200s with
real content (backend service-image version list) — the auth wall is specifically scoped to the
data-processing/job-submission paths, which is the expected, correctly-designed behavior.

## Why it's unconfirmed, not ruled out
Without a valid Earthdata Login (EDL) bearer token I cannot get past the OAuth wall to see how
`destinationUrl`/`shape` are actually validated once request processing begins. This is the exact
same blocker as `launchpad-target-param-LEAD-needs-creds.md` — a real, well-scoped lead that
needs credentials this session doesn't have (`credentials.md` is not present in
`/home/sn0x/bb/targets/NASA/`).

## Next step (if/when EDL test creds become available)
1. Get a valid EDL bearer token (`.netrc` or `Authorization: Bearer` per Harmony's own docs).
2. Re-run the exact 5 requests above WITH auth — compare `destinationUrl=s3://...` (valid) vs
   `destinationUrl=http://169.254.169.254/...` (invalid scheme) vs bypass variants:
   - `s3://legit-bucket.169.254.169.254/x` (dot-in-hostname parser confusion)
   - `s3:169.254.169.254/x` (scheme-only, missing `//`)
   - `s3://[::ffff:169.254.169.254]/x`
   - Full SSRF-GODMODE Level 4 URL-parser-confusion ladder if the naive check turns out to just
     be `.includes('s3://')` rather than a real scheme parse.
3. For `shape=`, test both as a URL string AND check whether the multipart file upload path
   itself parses SVG/XML/zip contents that could reference external entities (XXE-via-shapefile
   chain, separate from raw SSRF but same entry point).
4. If any variant reaches an actual outbound fetch, confirm via the OOB listener
   (`interactsh-client`, domain used this session:
   `d9mthshg9qge45ph8cdg85s9fazwfe8pm.oast.fun` — now stopped, generate a fresh one for the
   follow-up session) AND via HTTP-layer error-class signal (per the hard rule: DNS-only is not
   enough, need a connection-attempt-class error or real response body).

## Correction to a prior (killed-agent) note
`IN-PROGRESS-leads-from-quota-killed-agents.md` LEAD 3 states CMR subscriptions "historically
used an `EndPoint` field" and suggests testing `POST https://cmr.earthdata.nasa.gov/search/subscriptions`
with an SSRF payload once a bearer token is obtained. **This is now ruled out, not just
auth-blocked** — live schema introspection (both the raw CMR ingest UMM-Sub validator and the
`graphql.earthdata.nasa.gov` `CreateSubscriptionInput`/`UpdateSubscriptionInput` types) confirms
the *only* fields are `collectionConceptId`, `name`, `nativeId`, `subscriberId`, `query`, `type` —
no `EndPoint`/`EndpointURL`/URL field exists in the schema at all, at either the REST or GraphQL
layer. CMR subscriptions deliver via email (`SubscriberId`/`EmailAddress` in the older REST
shape) — there's no attacker-controllable webhook URL to inject even with a valid EDL token. See
`ssrf-notes.md` for full detail. Getting an EDL token specifically to re-test CMR subscriptions
for SSRF would be wasted effort — redirect that credential toward Harmony instead (this file).
