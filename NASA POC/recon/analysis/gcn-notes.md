# GCN (test.gcn.nasa.gov) — deep-dive notes, mostly RULED OUT

NASA's own VDP policy explicitly names `test.gcn.nasa.gov` as the designated non-prod test
target ("Example: Test in test.gcn.nasa.gov NOT in gcn.nasa.gov"), so this got focused
attention. Remix/AWS app, Cognito auth, Kafka M2M client-credentials architecture (see
`/docs/internal/auth` — publicly documented by design, open-source project on GitHub).

## RULED OUT

**Cognito OAuth redirect_uri validation** — airtight. 7/7 bypass variants rejected
(external host, subdomain, suffix-confusion, path-append, userinfo@, localhost, even a
*different path on the same legitimate host*) — all `302 -> /error?error=redirect_mismatch`,
exact-match enforced. Client: `32lajke7n176ohl1siv8m8lurd` @ `auth.test.gcn.nasa.gov`.

**Admin surface** — `/admin`, `/admin/users`, `/circulars/moderation` all correctly `403`
unauthenticated. `/api/users` and `/api/circulars` (no query) both `400
{"message":"Unexpected Server Error"}` — generic, no stack trace/detail leaked (unlike the
CKAN Solr case), not reportable per NASA's verbose-error exclusion, and not a real signal of
anything beyond a bare parameter-validation error.

**Circulars search (`?query=`) — Elasticsearch-backed** (GCN's own docs at
`/docs/circulars/archive` document Lucene special-char escaping). Malformed syntax
(`GRB AND AND (`, unescaped `"`) triggers a **generic** `500 Unexpected error` page — no
stack trace, no query object, no ES/OpenSearch detail of any kind (contrast with the CKAN
Solr finding, which leaks the full internal query + ACL filter chain — that's what makes
that one reportable and this one not). Ruled out.

**`/circulars/new/{circularId}` edit-route pre-auth data leak — real anti-pattern, NOT
reportable.** The Remix loader for this route runs and embeds its result in
`window.__remixContext` in the server-rendered HTML **before** the client-side auth check
redirects to sign-in — i.e. `curl` (no auth, no cookies) against
`/circulars/new/33706` returns the full loader payload:
```json
{"circularId":33706,"defaultSubject":"GRB foo","defaultBody":"testing",
 "defaultFormat":"text/plain",
 "defaultSubmitter":"Leo Singer at NASA/GSFC <leo.p.singer@nasa.gov>"}
```
Checked whether this is a genuine new PII/content exposure — **it is not**. The submitter
name+email is displayed in plain visible text on the normal public circular page
(`/circulars/33706`) by design — GCN circulars are astronomical transient-event
notifications where showing "who to contact" is the entire point of the feature. Confirmed
`leo.p.singer@nasa.gov` appears in a visible `<div>` on the public page, not just buried in
a script tag. Also tried IDs past the current max (33707 through 999999) looking for a
pending-moderation circular whose content might not yet be public — all cleanly `404`, no
draft content reachable this way (draft/pending circulars apparently don't get an ID
allocated in this guessable range until approved). Net: the loader-before-auth-check pattern
is real but the data it leaks is not sensitive. Matches the "accessible but not
demonstrably sensitive" / "already public" kill pattern — not submitted.

**Self-registration** — open on test (Cognito hosted UI `/signup` reachable), but requires
email verification, so it doesn't unlock further authenticated testing without a real
inbox. Not pursued further without a mailbox to verify against.

## Not yet tried / could revisit with more time
- `routes/api.synonym.circulars`, `routes/api.tooltip.*` (arxiv/doi/tns lookups) — found in
  the JS manifest, not individually probed.
- Actual circular *submission* flow (stored-XSS-shaped: user-authored body rendered back to
  all readers) — needs a verified account, same blocker as self-registration above.
- Kafka OIDC client-credentials flow itself (`/docs/internal/auth` describes users can
  mint Kafka client_id/client_secret pairs) — needs an authenticated account to reach the
  "client credentials" management page at all.
