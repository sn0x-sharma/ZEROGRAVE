# Exposed Dev/Ops Tools — luna / smce / jsc appdat cloud infra — Ruled Out

**Date:** 2026-08-01
**Tester:** sn0x (web-hunter agent)
**Scope check:** all hosts below are `*.nasa.gov` subdomains (in-scope wildcard per scope.yaml).
Testing was confirm-only: version/config fingerprinting, narrow realm enumeration via unauth
OIDC discovery, ONE default-credential attempt per login surface that was actually reachable,
and one safe non-sensitive-file CVE-2021-43798 traversal probe. No brute-forcing, no destructive
actions, no persistent resources created. Raw evidence: `/home/sn0x/bb/targets/NASA/evidence/devtools-check/`.

**Result: no auth bypass, no default creds, no working unauthenticated CVE on any of the 5 targets.**
Nothing here clears the bar for a report (would be version/banner disclosure without an exploit,
which is explicitly non-reportable on this program). Logging so this surface isn't re-walked later.

---

## 1. Keycloak — keycloak.luna.nasa.gov + keycloak.staging.luna.nasa.gov

**Status:** Ruled out — hardened, up-to-date, no unauth CVE applies, no login attempted.

- Both hosts: `/` → 302 → `/admin/` → 302 → `/admin/master/console/` → 200. Real Keycloak admin
  login console on both (identical behavior on prod and staging).
- **Version fingerprint** (exact version not directly disclosed — modern KC no longer embeds a
  literal version in the resource path, it uses a cache-busting hash: `resources/zqw7t/admin/keycloak.v2/`):
  - `GET /admin/realms/master/organizations` (unauth) → **401** (endpoint exists, needs auth) —
    the Organizations feature only exists from **Keycloak 25.0+**, so 401 (not 404) puts this
    build at **≥ 25.x**.
  - `/realms/master/.well-known/openid-configuration` includes `pushed_authorization_request_endpoint`,
    `dpop_signing_alg_values_supported` (DPoP), and JARM response modes (`query.jwt`, `fragment.jwt`,
    `form_post.jwt`) — all consistent with a recent (25.x/26.x-line) build.
  - `resources/zqw7t/admin/keycloak.v2/environment.json` → 404 (not exposed, so no direct
    precise-version leak from that route).
  - Evidence: `evidence/devtools-check/keycloak_luna_admin.html`, `kc_master_discovery.json`,
    `headers_20260801_165102.txt`.
- **Realm enumeration** (unauth `GET /realms/<name>/.well-known/openid-configuration`, single GET
  per name, 16 names tried on each host — recon via discovery endpoint, not a credential attack):
  `master`(200), `nasa`, `luna`, `staging`, `sit`, `uat`, `earthdata`, `urs`, `prod`, `jsc`, `smce`,
  `appdat`, `internal`, `sso`, `employees`, `nasa-sso` (all 404) — **identical result on both hosts**.
  Only `master` is exposed. No app-specific realm found with this wordlist.
- **CVE check** (web search, Keycloak 25/26 line): CVE-2025-7784 (admin-console FGAPv2 privilege
  escalation) and CVE-2025-14083 (Admin REST API info disclosure via `/admin/realms/master/users/profile`)
  both **require an already-authenticated admin with partial permissions** (`manage-users` /
  `create-client` respectively) — neither is a pre-auth/unauthenticated vector, so neither applies
  to us with zero credentials. No unauthenticated RCE/auth-bypass CVE found for this version range.
- Per task instructions, no login was attempted (no known-real credential available; default-cred
  guessing against a federal IAM/SSO admin console was explicitly out of scope for this target).
- **Verdict:** properly configured, single-realm, current Keycloak. Nothing actionable. Do not
  re-test version/realm enum here again unless a new realm name surfaces elsewhere (e.g. leaked in
  a JS bundle or OAuth client config) — then test that specific realm's discovery endpoint only.

## 2. MinIO — minio.luna.nasa.gov + console.er7.minio.luna.nasa.gov

**Status:** Ruled out — no live backend behind either hostname (DNS exists, application does not).

- DNS: both hostnames (`minio.luna.nasa.gov`, `console.er7.minio.luna.nasa.gov`, and
  `er7.minio.luna.nasa.gov`) CNAME to `luna.nasa.gov` → shared ingress IP `34.171.202.108`
  (same IP as the Keycloak hosts — one shared ingress fronting multiple `luna.nasa.gov` services).
- `console.er7.minio.luna.nasa.gov`: TLS handshake succeeds but the presented certificate is
  `CN=*.luna.nasa.gov` (Let's Encrypt), which does **not** cover a 3-label subdomain like
  `console.er7.minio.luna.nasa.gov` — hostname/cert mismatch (`curl: (60) SSL: no alternative
  certificate subject name matches`). Retried with `-k` (skip verify): still **404**, empty body,
  no `Server` header — same "no route matched" shape as below, not an actual MinIO response.
- `minio.luna.nasa.gov`: tested `GET /`, `GET /minio/health/live` (MinIO's always-unauth liveness
  probe by design), and `GET /?list-type=2` (unauth S3 bucket-listing style request) — **all 404**,
  empty body, minimal headers (`date` only), reproduced identically on HTTP/1.1 and HTTP/2. Real
  MinIO always sends a `Server: MinIO` header and XML/JSON error bodies even on 404s — the complete
  absence of both, plus the identical shape across every path tested, matches a generic ingress
  "no route configured for this Host" default response, not an application-level 404 from MinIO
  itself.
- **Conclusion:** these are stale/reserved DNS records (or an ingress route that was never
  provisioned / has since been torn down) pointing at a shared ingress with no live MinIO service
  bound to either hostname right now. There is no login page or S3 API surface to actually test —
  the `minioadmin`/`minioadmin` attempt was not applicable because nothing reachable presents an
  auth prompt. Not a vulnerability; nothing to exploit against an absent backend.
- Evidence: inline in session transcript (curl -v TLS handshake output, 404 responses); no
  separate saved file needed since responses had no body content.
- **Re-test trigger:** if a future recon pass shows this ingress IP responding differently (e.g.
  a real MinIO `Server` header appears), re-check for default creds then — not before.

## 3. Grafana — grafana.staging.iot-general.appdat.jsc.nasa.gov/grafana/

**Status:** Ruled out — patched version, no anonymous access, default creds fail, traversal blocked.

- Redirect chain: `/` → 301 → `/grafana/` → 302 → `/grafana/login` → 200. (The `/` → `http://`
  downgrade in the Location header was noted but is out of scope per task instructions — not
  reported.) Behind an nginx ingress (`x-using-nginx-controller: true`, `x-powered-by: appdat`).
- **Version:** `GET /grafana/api/health` (Grafana's by-design unauthenticated healthcheck) →
  `{"commit":"9708acf893...","database":"ok","version":"10.4.18+security-01"}`. The
  `+security-01` suffix indicates this is a Grafana Labs security-backport build on the 10.4.x
  branch (patched, not a stale unpatched minor).
- **Anonymous access check:** `/grafana/api/frontend/settings`, `/grafana/api/search`,
  `/grafana/api/datasources` all → **401** `{"message":"Unauthorized",...}`. Only `/api/health` is
  unauth, which is expected/by-design for every Grafana install — not a misconfiguration.
- **ONE clean `admin`/`admin` login attempt** (`POST /grafana/login` with JSON body) → **401**
  `{"message":"Invalid username or password","messageId":"password-auth.failed",...}`. Default
  creds do not work.
- **CVE-2021-43798 (plugin path traversal) check:** version 10.4.18 is far outside the vulnerable
  range (8.0.0-beta1 – 8.3.0, patched in 7.5.13/8.0.7/8.3.1), so this was expected to be a clean
  negative. First attempt via plain `curl` gave a false read (curl itself normalizes `../` client
  side before sending, collapsing the path) — redone correctly with `--path-as-is` so the raw
  traversal sequence actually reached the server:
  `GET /grafana/public/plugins/alertlist/../../../../../../../etc/hostname` (and again without the
  `/grafana` prefix) → **400 Bad Request** from `nginx` both times, i.e. the ingress layer itself
  rejects the raw `../` sequence before it ever reaches the Grafana application. Double-confirmed
  not vulnerable (version + ingress-level rejection). No sensitive or non-sensitive file content
  was ever returned.
- Evidence: `evidence/devtools-check/grafana_login_attempt.txt`, `grafana_frontend_settings.json`,
  transcript output for the health/search/datasources/traversal checks.
- **Verdict:** correctly configured and patched. Nothing actionable.

## 4. Jupyter — jupyter.aps.smce.nasa.gov

**Status:** Ruled out — hostname does not exist (NXDOMAIN), not a transient connectivity issue.

- `dig jupyter.aps.smce.nasa.gov` → **NXDOMAIN** (SOA-only answer, no A/CNAME record at all).
  This confirms the earlier "connection failed (000)" reports were not transient/firewall
  artifacts — the DNS record simply does not exist under this name.
- The parent zone `aps.smce.nasa.gov` *does* resolve (AWS Route53-hosted, A records
  `13.225.5.{3,10,34,79}`), so the zone is alive; there is just no `jupyter` host in it.
  `https://aps.smce.nasa.gov/` itself → 403, `Server: AmazonS3`, `X-Cache: Error from cloudfront`
  — an S3-backed CloudFront static site, unrelated to Jupyter/JupyterHub. This explains the naming:
  `aps.smce.nasa.gov` hosts something else entirely (likely a docs/portal site), not a notebook
  service.
- Checked a small number of close naming variants (not a wordlist scan — 4 targeted guesses only,
  consistent with "retry the target," not authorized for broader enumeration): `jupyterhub.aps.smce.nasa.gov`,
  `notebook.aps.smce.nasa.gov`, `jupyter.smce.nasa.gov` — all non-resolving.
- **Conclusion:** no unauthenticated Jupyter (or any) service reachable at this hostname today.
  Cannot confirm a TIER-1 finding for something that doesn't exist. Did not pursue further
  subdomain guessing against `smce.nasa.gov` — that would be a wordlist-scan action beyond what
  was authorized for this specific "retry" check, and NASA SMCE JupyterHub deployments are
  typically hosted under an entirely different domain (`*.mysmce.com`, not `*.smce.nasa.gov`),
  which is out of the declared `*.nasa.gov` scope anyway and was not tested.
- Evidence: `evidence/devtools-check/dns_check_20260801_165102.txt` (dig output).
- **Re-test trigger:** only if a future recon pass finds this hostname (or a genuine
  `*.smce.nasa.gov` Jupyter host) actually resolving.

## 5. images-admin.nasa.gov

**Status:** Ruled out — no distinct admin API surface; auth mechanism not conclusively fingerprinted (non-blocking).

- **Scope note:** `images-admin.nasa.gov` (and, for context, `images.nasa.gov` /
  `images-api.nasa.gov` too) all CNAME to `*.nasawestprime.com` → CloudFront → AWS edge IPs.
  `nasawestprime.com` is a third-party/contractor-operated domain (out of scope per scope.yaml's
  "non-federal vendor/contractor systems are OUT OF SCOPE" clause) — however, the *hostnames*
  tested here are all `*.nasa.gov`, explicitly in scope per the wildcard, and every request was
  sent to the `nasa.gov` FQDN (never to `nasawestprime.com` directly by name). This is standard
  practice (in-scope domain fronted by third-party CDN/hosting) and the content served is
  unmistakably NASA's own public Image and Video Library app, not an unrelated vendor business
  system — so testing the `nasa.gov` hostname itself is consistent with scope. Kept this
  deliberately shallow (recon/characterization only, no fuzzing) given the ambiguity.
- `https://images-admin.nasa.gov/` → **301** → `https://images.nasa.gov/login`. The redirect is
  served by a lightweight custom origin (`server: goredirect/2013.08.12`) sitting behind
  CloudFront — not the same S3-backed origin that serves the SPA itself.
- `https://images.nasa.gov/login` → **200**, `server: AmazonS3` — a static Angular SPA shell
  (`main-*.js`, `polyfills-*.js`, `scripts-*.js`, several lazy-loaded `chunk-*.js`, 178KB
  index.html) served straight from S3/CloudFront. `/login` is a client-side route, not a distinct
  server endpoint.
- **Distinct admin-API surface check** — 7 plausible paths tested directly on
  `images-admin.nasa.gov` (`/api`, `/api/albums`, `/health`, `/status`, `/v1`, `/rest`,
  `/admin/api`): **all 404** (not the 301 seen at `/`). The `goredirect` origin only knows about
  `/` — everything else 404s. **No distinct unauthenticated admin API was found on this hostname.**
- **Auth mechanism characterization** (secondary/non-vulnerability question): fetched
  `images_login.html`, `main-4OELVCYU.js`, `scripts-TTWY4XDY.js` and grepped for
  okta/auth0/cognito/saml/launchpad/login.gov/oidc/clientId/authorize/idp/sso and for
  password/username/email form-field indicators — **no clear signal either way**. No SSO/SAML/Okta
  provider strings were found (weak evidence against a third-party IdP), but the minified Angular
  bundles also didn't yield obvious plain-form indicators via static grep — the real login
  component is very likely in one of the many lazy-loaded `chunk-*.js` files not fetched, or only
  resolves at runtime. Confirming this conclusively would need a live browser render, which felt
  disproportionate for a non-vulnerability characterization question. **Leaving open** — if this
  needs to be resolved later, load `/login` in an actual browser (e.g. via the stealth-browser
  tooling) and observe the network tab on submit rather than static-grepping more bundles.
- Evidence: `evidence/devtools-check/images_login.html`, `images_main_bundle.js`,
  `images_scripts_bundle.js`.
- **Verdict:** no auth bypass, no default creds tried (no distinct login surface of its own to
  test — it only redirects), no separate admin API. Nothing actionable.

---

## Summary table

| # | Target | Reachable? | Auth bypass / default creds / unauth CVE? | Verdict |
|---|---|---|---|---|
| 1 | keycloak.luna.nasa.gov | Yes | No — only `master` realm, no applicable CVE, login not attempted | Ruled out |
| 1 | keycloak.staging.luna.nasa.gov | Yes | Same as above | Ruled out |
| 2 | minio.luna.nasa.gov | DNS only, no live app | N/A — nothing to log into | Ruled out |
| 2 | console.er7.minio.luna.nasa.gov | DNS only, cert mismatch, no live app | N/A | Ruled out |
| 3 | grafana.staging.iot-general.appdat.jsc.nasa.gov | Yes | No — 401 on all APIs, admin/admin fails, CVE-2021-43798 blocked+not applicable | Ruled out |
| 4 | jupyter.aps.smce.nasa.gov | No — NXDOMAIN | N/A | Ruled out (doesn't exist) |
| 5 | images-admin.nasa.gov | Yes (redirect stub only) | No distinct API surface found | Ruled out |

**No validated findings produced from this pass.** No file was added to `validated-findings/`
because nothing here cleared the "confirmed access" bar. This entire class of targets
(internal-looking dev/ops tools under luna/smce/appdat) is worth re-visiting periodically since
cloud infra config drifts (e.g. MinIO/Grafana instances get spun up/down), but there is no
outstanding lead to chase from this specific pass.
