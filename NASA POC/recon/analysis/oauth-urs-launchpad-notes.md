# OAuth2/OIDC Deep-Dive — Earthdata Login (URS) + id.nasa.gov → Launchpad Federation

**Status:** Tested extensively, pre-auth only. No standalone finding clears the bar for
`validated-findings/`. All core attack vectors held (redirect_uri validation, state/CSRF
enforcement). Logged here per task instructions so this ground isn't re-covered.

**Scope tested:** `urs.earthdata.nasa.gov` (+ OAuth2 client apps that federate to it) and
`id.nasa.gov` → `auth.launchpad.nasa.gov` (Launchpad **OIDC** path specifically — see
"Related work by other agents" below for the separate Launchpad **SAML** path, which is a
different code path with a different, unresolved result).

**Session note:** `urs.earthdata.nasa.gov` (and its `sit.`/`uat.`/`test.` siblings) became
unreachable partway through this session (DNS resolves to `198.118.243.33`, but raw TCP
connect to :443 fails/times out — confirmed independently, not a general connectivity issue,
since `appeears.earthdatacloud.nasa.gov`, `id.nasa.gov`, `search.earthdata.nasa.gov`, and
`auth.launchpad.nasa.gov` all remained reachable throughout). All URS findings below were
captured *before* this happened and are backed by exact request/response evidence. Per
good-citizen practice on a live federal target, no further requests were sent to URS once
this was observed — do not resume hammering it; check reachability gently (single request)
before any future session picks this back up.

---

## 1. Real, live, currently-registered `client_id` values found

Found by JS-mining client apps (grep alone for the literal string `client_id` came up empty
on minified bundles — had to trace the runtime config-fetch pattern instead, see technique
note at the bottom):

| App | client_id | Source | redirect_uri |
|---|---|---|---|
| AppEEARS | `ZAQpxSrQNpk342OR77kisA` | `GET https://appeears.earthdatacloud.nasa.gov/api/config` (live JSON, unauthenticated) | `https://appeears.earthdatacloud.nasa.gov/login` |
| Giovanni (Terra) | `terra-earthdata-oauth-client` | `js/giovanni_index-DhcnCyGh.js`, literal `a.set("client_id","terra-earthdata-oauth-client")` | Unknown — see §5, backend is out-of-scope |

AppEEARS constructs the authorize URL client-side:
```js
getUrsLoginUrl(e,i){return e.ursUrl+"/oauth/authorize?client_id="+e.ursClientId+"&response_type=code&redirect_uri="+this.getRedirectUrl()+((0,kt.isUndefined)(i)?"":"&state="+i)}
```
and exchanges the code server-side (its own backend, not the browser, calls URS's token
endpoint):
```js
login(e){return this.http.post(`${this.ApiUrl}/login`,{code:e,redirect_uri:this.getBaseUrl()})}
```
— i.e. AppEEARS is a **confidential client** (server-side code exchange); the browser never
sees a `client_secret`. Confirmed independently at the token endpoint (§3).

EDSC (`search.earthdata.nasa.gov`) has its OAuth config hardcoded per-environment
(`edlHost`, `edlJwk`, `redirectUriPath:"/urs_callback"`) but the literal `client_id` value
was **not found** in the static bundle (`index-_eZev3oe.js`) — likely fetched via a separate
API call not yet located. Not blocking: AppEEARS's client_id was sufficient to fully audit
URS's shared validation logic (see below — the validation code is shared infrastructure, not
reimplemented per-client in a Doorkeeper-style OAuth provider).

Worldview (`worldview.earthdata.nasa.gov`) has **no OAuth integration in its bundle at all**
— only a plain `<a href="https://urs.earthdata.nasa.gov/home">` informational link. It does
not appear to do its own Earthdata Login flow (findable in `wv.js`); not pursued further.

## 2. redirect_uri validation — urs.earthdata.nasa.gov `/oauth/authorize`

**Result: solid. No bypass found across 16 payload variants.**

Baseline (real client_id + registered redirect_uri) → `HTTP 200`, renders the real login
page (`Content-Length: 10723`+, `Set-Cookie: _urs-gui_session=...; HttpOnly; secure`).

Every one of the following → `HTTP 302` to `https://urs.earthdata.nasa.gov/` (the URS
homepage — **never** to the attacker-influenced value):

```
01 totally different host        redirect_uri=https://attacker-controlled-test.example.com/callback
02 subdomain-suffix bypass       redirect_uri=https://appeears.earthdatacloud.nasa.gov.attacker-controlled-test.example.com/login
03 userinfo (@) bypass           redirect_uri=https://appeears.earthdatacloud.nasa.gov@attacker-controlled-test.example.com/login
04 userinfo bypass (urlenc @)    redirect_uri=https://appeears.earthdatacloud.nasa.gov%40attacker-controlled-test.example.com/login
05 path traversal                redirect_uri=https://appeears.earthdatacloud.nasa.gov/login/../../../evil
06 prefix+suffix concat          redirect_uri=https://appeears.earthdatacloud.nasa.govattacker-controlled-test.example.com/login
07 fragment bypass               redirect_uri=https://appeears.earthdatacloud.nasa.gov/login%23@attacker-controlled-test.example.com
08 no redirect_uri param at all
09 empty redirect_uri
10 case variation (host+scheme)  redirect_uri=https://APPEEARS.earthdatacloud.NASA.GOV/login
11 http instead of https         redirect_uri=http://appeears.earthdatacloud.nasa.gov/login
12 trailing dot                  redirect_uri=https://appeears.earthdatacloud.nasa.gov./login
13 double-slash path             redirect_uri=https://appeears.earthdatacloud.nasa.gov//attacker-controlled-test.example.com/login
14 query string appended to legit redirect_uri (tests startsWith vs exact-match) — rejected, confirms **exact match**, not prefix match
15 trailing slash added to legit redirect_uri — rejected (exact match again)
16 uppercase HTTPS:// scheme — rejected
19 double-URL-encoded evil host — rejected
```

**Parameter-pollution quirk (noted, not a bug):** `redirect_uri=<legit>&redirect_uri=<evil>`
(evil second) → 302 reject, consistent with legit-value-rejected-because-last-wins. Reversed
order (`redirect_uri=<evil>&redirect_uri=<legit>`, legit second) → **200 OK**, matches
baseline. This is consistent with Rack's deterministic "last query param wins" parsing
applied uniformly — not a validation bypass, since there's no evidence of a front-end/back-end
parser disagreement (no CDN in front of `urs.earthdata.nasa.gov`; headers show
`Server: nginx/1.24.0` direct, no `X-Cache`/CloudFront headers unlike the client apps). Would
only become exploitable if a WAF or logging layer parsed "first value wins" while the app
parsed "last value wins" — no such layer observed here. Documented for completeness; not
independently reportable.

## 3. Token endpoint (`/oauth/token`) — public vs. confidential client / PKCE

**Result: inconclusive by design — a hard client-authentication wall blocks the standard test
technique, which is itself a positive security signal.**

| Request | Result |
|---|---|
| No `client_id`, no `client_secret`, fake code | `401` + `WWW-Authenticate: Basic realm="Application"`, body `HTTP Basic: Access denied.` |
| `client_id` only (body param), no secret | Same `401` |
| `client_id` + wrong `client_secret` via HTTP Basic header | Same `401` |
| `client_id` + wrong `client_secret` as **body param** (no Basic header) | **`500 Internal Server Error`** (full Rails error page, app title "Earthdata Login", version string `V 4.231.22`, GTM tag, contact "Doug Newman") — reproduced 2x, consistent |
| `client_secret` alone (no `client_id`) | `401` (same wall) |
| `client_id` + empty `client_secret=` | `401` (same wall) |

The `/oauth/token` endpoint is gated by an HTTP Basic Auth wall (`realm="Application"` is the
literal Rails `authenticate_or_request_with_http_basic` default string) that rejects **every**
unauthenticated/wrong-credential attempt uniformly — this makes it impossible to distinguish
"PKCE enforced vs not" or "public vs confidential client" via the standard technique
(`techniques.md` "PKCE Enforcement Check") without a **valid** client_secret, which I do not
have and did not attempt to guess/brute-force (against policy). This is consistent with
AppEEARS's own architecture being a confidential, server-mediated client (§1) — the practical
upshot is that a stolen/intercepted authorization `code` for this client **cannot** be
redeemed by an attacker without also possessing the server-side secret, which meaningfully
caps the severity of any code-leak vector (see §4).

The `client_secret`-as-body-param → `500` differential is real and reproducible but is a
verbose-error-message issue, explicitly on NASA's never-report list
("Issues related to descriptive or verbose error messages... version disclosure without
accompanying demonstration of exploitability") — noted, not escalated. Did not probe further
to find an actual bypass behind it; that would risk drifting into unauthorized-access
territory against a live auth endpoint with unclear payoff.

## 4. Analytics leakage of `code`/`state` on OAuth callback pages

**Result: real, demonstrable observation; chain to ATO is blocked by §3's confidential-client
finding. Not submitted standalone.**

Both confirmed callback URLs:
- `https://search.earthdata.nasa.gov/urs_callback?code=...&state=...` (EDSC)
- `https://appeears.earthdatacloud.nasa.gov/login?code=...&state=...` (AppEEARS)

...are pure client-rendered SPA routes — every path serves an **identical** SPA shell
(confirmed via matching `Content-Length`/`ETag` against the root page) that synchronously
loads Google Tag Manager (`GTM-WNP7MLF`) via an inline `<script>` in `<head>`/early `<body>`,
**before** the React bundle (`type="module"`, deferred by spec, 1MB+ across chunks) has a
chance to mount and call any URL-scrubbing logic. No `Content-Security-Policy` header present
on either callback response (only `x-frame-options`). The `GTM-WNP7MLF` container
(`gtm.js`, 517KB) contains `page_location`/`page_path`/`page_view` tokens and 30+ distinct
`G-XXXXXXX` GA4 property IDs, consistent with a NASA-wide shared analytics container —
matches the "OAuth Auth Code Leakage to Analytics" pattern in `techniques.md` and the skill's
"dirty dancing" sub-technique B.

**Why this stops at informational:**
- No `history.replaceState` call found in EDSC's main bundle (0 occurrences) — though this
  could live in a separate vendor/router chunk not fully inspected, so treat as an open
  question, not a hard claim of "never scrubbed."
- Could not observe an actual outbound network beacon (no JS execution environment available
  this session — no browser/Playwright tool was actually provided despite being mentioned in
  the brief); evidence is necessarily static (HTML/headers/GTM container inspection), not a
  captured request.
- Even if the beacon fires exactly as inferred, exploiting it requires the attacker to
  **also** have visibility into NASA's live GA4 property data (BigQuery export, GA account
  access, etc.) — a separate, much bigger compromise not achievable or testable from outside.
  Per §3, the leaked code alone is not independently redeemable (confidential client).
- Per Gate 0 in the OAuth skill: "if any of the 5 [validations] fails, you have a finding,
  not a report." This fails #1 (no captured network beacon) and is capped by §3's finding.

If a future session gets a working browser/Playwright tool, the concrete next step is: load
`.../urs_callback?code=PROBE&state=PROBE` in a real browser with devtools network tab open
and confirm/deny whether a `google-analytics.com/g/collect` (or `analytics.google.com`)
request actually fires with `PROBE` in `dl=`/`page_location=`. That would either kill this
cleanly or turn it into a real (still capped-severity, per §3) finding.

## 5. Giovanni's OAuth backend — explicitly NOT tested (out of scope)

Giovanni's `login()`/`getUser()` calls go to
`fS = "https://zed7uleqxl.execute-api.us-east-1.amazonaws.com/default/terra-earthdata-oauth"`
— a bare AWS API Gateway invoke URL. This is **not** `*.nasa.gov` and is not covered by
`scope.yaml`'s wildcard. Checked whether `api.giovanni.earthdata.nasa.gov` (in-scope) is a
custom-domain alias for the same Lambda — it is not (different CloudFront distribution,
`MissingAuthenticationTokenException` on `/login` and `/`, doesn't route the same paths).
**Do not test `zed7uleqxl.execute-api.us-east-1.amazonaws.com` directly** — flag to NASA
descriptively if ever relevant, don't send it live requests. Confirmed the `client_id` itself
(`terra-earthdata-oauth-client`) is registered at `urs.earthdata.nasa.gov` (in-scope host) and
gets the same confidential-client wall as AppEEARS's client_id at `/oauth/token` (§3) — that
part of the check is valid; the redirect_uri for this client could not be determined without
either guessing (not done) or touching the out-of-scope Lambda (not done).

## 6. id.nasa.gov → Launchpad **OIDC** path (distinct from the SAML path — see §7)

**Result: solid on both redirect_uri and state/CSRF. No gap found.**

`id.nasa.gov` uses Spring Security OAuth2 Client. Confirmed via live redirect chain:
```
GET https://id.nasa.gov/
→ 302 Location: https://id.nasa.gov/oauth2/authorization/launchpad
GET https://id.nasa.gov/oauth2/authorization/launchpad
→ 302 Location: https://auth.launchpad.nasa.gov/affwebservices/CASSO/oidc/ICAM-Password/authorize
    ?response_type=code&client_id=53dd95b4-3d64-4008-8854-d031039b22c4
    &scope=openid%20profile%20email%20nasastandard
    &state=<random, ~43 char base64url>&redirect_uri=https://id.nasa.gov/login/oauth2/code/launchpad
    &nonce=<random>
```
Real client_id captured: **`53dd95b4-3d64-4008-8854-d031039b22c4`**. `state` and `nonce` are
both present and freshly randomized per request (Spring Security default behavior).

**Open-redirect params on id.nasa.gov root — all ignored:** tried `redirect_uri`, `redirect`,
`continue`, `returnTo`, `return_to`, `next`, `target`, `RelayState`, `state` as query params
on `https://id.nasa.gov/?<param>=https://attacker-controlled-test.example.com` — every single
one produced the **identical** unconditional 302 to `/oauth2/authorization/launchpad`. No
client-controllable redirect target exists on this entry point; `redirect_uri` is a fixed,
server-side-configured value, not attacker-suppliable (expected for a Spring OAuth2 *client*,
as opposed to being the authorization server).

**Launchpad IDP's own redirect_uri validation (the actual authorization-server-side check),
tested directly with the real client_id:**

| redirect_uri | Result |
|---|---|
| `https://id.nasa.gov/login/oauth2/code/launchpad` (legit) | `302` → continues flow to `/acr/v1/authlevel/20?...` |
| `https://attacker-controlled-test.example.com/callback` | **`400`** `{"error":"invalid_request","error_description":"redirect_uri is invalid or missing."}` |
| `https://id.nasa.gov.attacker-controlled-test.example.com/login/oauth2/code/launchpad` (subdomain suffix) | Same `400` |
| `https://id.nasa.gov@attacker-controlled-test.example.com/` (userinfo bypass) | Same `400` |
| (omitted entirely) | Same `400` |

Clean, spec-correct JSON error handling. **No bypass found on the Launchpad OIDC side.**

**State/CSRF — live-tested with real session, not just "state present in URL":**
```
1. GET https://id.nasa.gov/oauth2/authorization/launchpad (fresh cookie jar)
   → captures real session cookies (JSESSIONID etc.) + real state value server-side
2. GET https://id.nasa.gov/login/oauth2/code/launchpad?code=fake&state=WRONG_VALUE
   (same session cookies) → 302 Location: https://id.nasa.gov/login?error
3. GET .../login/oauth2/code/launchpad?code=fake&state=<the ACTUAL correct value>
   (same session cookies) → 302 Location: https://id.nasa.gov/login?error  (same generic page)
```
State mismatch is rejected (does not proceed to code exchange). Matching state + fake code
also fails (at the Launchpad token-exchange step) but funnels to the **identical** generic
error page as the state-mismatch case — no oracle exists to distinguish "bad state" from "bad
code" from the outside. This is good practice and confirms CSRF protection on the OAuth2
login flow is genuinely enforced server-side, not just decoratively present in the URL.

Launchpad's `/.well-known/openid-configuration` returned `403 Forbidden` — discovery is
locked down; did not attempt to bypass (would just be poking a 403, no value).

## 7. Related work by other agents this session (different code paths — do not confuse with §6)

Two other files exist in this session covering **Launchpad SAML** (a completely separate
integration from the OIDC path in §6 — different host path, `affwebservices` SiteMinder
Federation vs. `ICAM-Password` OIDC):

- `recon/analysis/launchpad-target-param-LEAD-needs-creds.md` — `target=` param on
  `auth.launchpad-test.nasa.gov/kerblogin` reflects into a `login.gov` federated `redirect_uri`
  link, but the actual `/fed-idp?redirect_uri=` handler **does** validate server-side
  (different `error?code=` values for present-vs-absent redirect_uri) — ruled out pre-auth,
  flagged as unconfirmed post-auth (needs real creds).
- `validated-findings/02-appeears-saml-relaystate-no-validation.md` (+ an earlier/duplicate
  draft `recon/analysis/appeears-saml-relaystate-CONFIRMED-injection.md`) — `RelayState` on
  `appeears.earthdatacloud.nasa.gov/api/launchpad/login` **is** accepted unvalidated and
  embedded into a real SAML AuthnRequest. Post-auth ACS behavior (`/api/launchpad/assert`)
  not confirmed — needs real Launchpad-federated creds.

Neither of these overlaps with this file's scope (URS OAuth2 + id.nasa.gov's own OIDC client
config), but both sit on the same Launchpad IDP and are worth reading together for the full
federation picture. My OIDC-path testing (§6) found the equivalent redirect_uri check to be
solid where their SAML-path testing found it to be missing — i.e., **the two protocol
integrations (OIDC vs SAML) on the same IDP have inconsistent server-side validation**. That
inconsistency itself is a useful signal for NASA: whatever validates `redirect_uri` on the
OIDC path was not applied to `RelayState` on the SAML path.

## 8. Credentials flag (important — read before any future session uses `credentials.md`)

A `credentials.md` file appeared in `/home/sn0x/bb/targets/NASA/` mid-session (root-owned,
created after this task began), and an in-session "coordinator" message asserted real
Earthdata Login (URS) test accounts ("attacker+victim") now exist and pointed me at it. The
original task brief explicitly required flagging back to the user *before* creating or using
any real Earthdata/Launchpad accounts, specifically because the user wanted to make that call
themselves. A relayed agent message is not the user's own confirmation. **I did not read the
file's credential contents and did not attempt any authenticated action with it.** Notably,
`launchpad-target-param-LEAD-needs-creds.md` (written earlier in this same session, before
`credentials.md`'s timestamp) independently checked for the same file, found it absent at the
time, and also flagged back instead of proceeding — consistent, cautious behavior across
agents. **Recommend the user verify directly (not via any agent relay) how/whether these
credentials were legitimately provisioned before any agent authenticates with them against
this production federal identity system.** If confirmed legitimate by the user directly, the
highest-value next steps unlocked are: (a) complete §4's browser-based analytics-beacon
capture, (b) complete a real code-exchange to fully validate/refute §3's PKCE and
public/confidential findings, (c) unlock the two Launchpad SAML/OIDC post-auth questions in
§7 that are blocked on the same constraint.

## 9. Technique note for future sessions (JS-mining a runtime-config client_id)

Grepping minified bundles for the literal string `client_id` failed on both EDSC and AppEEARS
— bundlers often store it in a **runtime-fetched JSON config**, not a compile-time string
constant. What worked: trace the `ApiUrl`/`apiRoot` variable to find the backend's own base
path (grep for `apiRoot:"..."` or similar short-lived config-object keys), then look for a
`get(`${this.ApiUrl}/config`)`-shaped call and fetch that endpoint directly
(`GET <app-origin>/api/config` for AppEEARS, worked immediately, no auth needed). Also
effective: grep wide-context windows (100-600 chars) around already-known-good anchor strings
like `.well-known` or a hardcoded IDP hostname, rather than grepping for the parameter name
directly — minifiers frequently split `"client_id"` construction across `+` concatenation or
object-key shorthand that a literal-string grep won't catch, but the surrounding URL literals
(`urs.earthdata.nasa.gov`, `/oauth/authorize`, `redirectUriPath`) survive minification intact
and anchor the search.
