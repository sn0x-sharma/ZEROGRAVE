# luna.nasa.gov cluster — Keycloak / Grafana / GitLab (RULED OUT, with one useful discovery)

## Discovery worth keeping: the real Keycloak realm is `luna-api`, not just `master`

Earlier passes enumerated only `master` on `keycloak.luna.nasa.gov` / `keycloak.staging.luna.nasa.gov`
(guessed realm names `nasa`, `luna`, `earthdata`, `smce`, `sciencecloud` all 404'd). The real
application realm is **`luna-api`**, confirmed on **both staging and prod**, discovered not by
guessing but by following `monitoring.staging.luna.nasa.gov`'s login redirect chain — which
leaks the full OIDC authorize URL including realm and client_id:

```
https://keycloak.staging.luna.nasa.gov/realms/luna-api/protocol/openid-connect/auth
  ?client_id=grafana-client
  &redirect_uri=https%3A%2F%2Fmonitoring.staging.luna.nasa.gov%2Flogin%2Fgeneric_oauth
  &response_type=code&scope=openid&state=...
```

Lesson for future recon on this program: don't brute-force Keycloak realm names — find a
federating app and read its redirect. Both `keycloak.luna.nasa.gov/realms/luna-api/...` and the
staging equivalent return valid OIDC discovery documents.

## Grafana `monitoring.staging.luna.nasa.gov` / `monitoring.luna.nasa.gov` (prod, 302)

- Grafana **13.1.1** (`GET /api/health` → `{"database":"ok","version":"13.1.1","commit":"a9cee6e..."}`).
  Health endpoint is unauth by design in Grafana; version alone is not reportable on this program.
- Auth is OIDC-only via Keycloak `luna-api` realm, `client_id=grafana-client`.
- **redirect_uri validation: SOLID.** Baseline legit redirect → `200` (login page renders).
  `redirect_uri=https://evil-attacker-controlled.example.com/steal` → **`400`, Keycloak
  "Invalid parameter: redirect_uri"** error page. Exact-match enforced at the IdP. No
  open-redirect / code-theft chain here — this is the correct behavior the AppEEARS SAML
  integration is missing (see `validated-findings/02-...`).

## Keycloak anonymous Dynamic Client Registration — reachable but correctly policy-protected

`registration_endpoint` is advertised in the `luna-api` discovery doc:
`/realms/luna-api/clients-registrations/openid-connect`

**Initial signal looked serious:** POST with a deliberately malformed body (chosen precisely so
nothing could be created) returned `400 {"error":"invalid_request","error_description":"Cannot
parse the JSON"}` on **both staging and prod** — i.e. the request reached JSON parsing rather
than being rejected at an auth layer, which normally indicates anonymous reachability.

**Follow-up disproved the finding.** A single valid minimal registration request (staging only,
per this program's prefer-non-prod guidance) returned:
```
HTTP 403
{"error":"insufficient_scope","error_description":"Policy 'Trusted Hosts' rejected request to
 client-registration service. Details: Host not trusted."}
```
Keycloak's default **Trusted Hosts** client-registration policy is active and rejects
registration from untrusted source hosts. **No client was created; no state was left behind on
NASA infrastructure.** The endpoint being anonymously *reachable* is Keycloak's normal design —
the policy layer is the actual control, and it is enabled and working.

Verdict: **not a finding.** Do not report. The 400-vs-401 parse-order signal is a false positive
for "no auth" on this endpoint class — always follow it with a policy-level probe before
concluding.

## `code.luna.nasa.gov` (GitLab)

`GET /api/v4/projects?visibility=public&per_page=20` → `200 []` — GitLab instance is live and the
public-projects API is anonymous-readable, but **zero public projects exist**. Nothing to mine.
Consistent with the already-audited `gitlab.smce.nasa.gov` / `git.smce.nasa.gov` posture
(see `git-hosts-notes.md`).

## Other luna hosts checked
`data.luna.nasa.gov`, `api.staging.luna.nasa.gov`, `docs.luna.nasa.gov`,
`models.staging.luna.nasa.gov`, `info.staging.luna.nasa.gov` → all `404` (no app bound).
`registry.code.luna.nasa.gov`, `monitoring.er7.luna.nasa.gov` → `000` (network-filtered,
internal-only → explicitly out of scope per NASA VDP policy).
