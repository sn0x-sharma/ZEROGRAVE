# Unvalidated SAML `RelayState` accepted and embedded into live NASA Launchpad AuthnRequest AppEEARS

**Status:** Validated (input-handling bug confirmed live) full end-to-end ATO chain NOT completed (would require a real Launchpad-federated PIV/CAC or Login.gov login, which is outside what's available in this session see "What's not proven" below).
**Target:** `https://appeears.earthdatacloud.nasa.gov` (AppEEARS — EOSDIS's Application for Extracting and Exploring Analysis Ready Samples)
**Class:** SAML2 SSO — Missing RelayState validation (CWE-601-adjacent, SAML-specific)

## Summary
AppEEARS federates to NASA Launchpad using SAML2 (CA/Symantec SiteMinder Federation Web Services — `affwebservices`), a completely separate identity system from Earthdata Login/URS and from the `id.nasa.gov`/OAuth2 Launchpad path checked earlier this session. The endpoint that kicks off SP-initiated SSO accepts an arbitrary, fully-qualified external URL as `RelayState` with **zero validation** and embeds it verbatim into a real SAML AuthnRequest sent to NASA's live federal SSO IdP.

## PoC step 1: unauthenticated GET, arbitrary RelayState accepted
```bash
curl "https://appeears.earthdatacloud.nasa.gov/api/launchpad/login?RelayState=https://evil-attacker-controlled.example.com/steal"
```
- Baseline (no `RelayState`) → `400 {"message":"query param \"RelayState\" not present."}`
  — proves the app validates *presence* but does nothing to validate *content*.
- With attacker `RelayState` → **HTTP 200**:
  ```json
  {"url": "https://auth.launchpad.nasa.gov/affwebservices/public/saml2sso?SAMLRequest=<blob>&RelayState=https%3A%2F%2Fevil-attacker-controlled.example.com%2Fsteal"}
  ```

## PoC step 2: decoded AuthnRequest confirms the real ACS endpoint
The `SAMLRequest` is standard base64+raw-deflate (HTTP-Redirect binding). Decoded:
```xml
<samlp:AuthnRequest ... Destination="https://auth.launchpad.nasa.gov/affwebservices/public/saml2sso"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
  AssertionConsumerServiceURL="https://appeears.earthdatacloud.nasa.gov/api/launchpad/assert">
    <saml:Issuer>https://appeears.earthdatacloud.nasa.gov</saml:Issuer>
    <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" AllowCreate="true"/>
</samlp:AuthnRequest>
```
This confirms `RelayState` travels with the user to the real Launchpad login page and would
travel back with the SAML Response to `POST /api/launchpad/assert` per the SAML2
HTTP-POST binding spec (RelayState is spec'd to be echoed back unchanged by the IdP).

## PoC step 3: probed the real ACS endpoint directly
```bash
curl -X POST "https://appeears.earthdatacloud.nasa.gov/api/launchpad/assert" \
  --data-urlencode "SAMLResponse=<garbage-base64>" \
  --data-urlencode "RelayState=https://evil-attacker-controlled.example.com/steal"
```
→ `500 {"message": "<InternalServerError '500: Internal Server Error'>"}` (generic, no
stack trace, no redirect). Omitting `RelayState` entirely → clean `400` instead of `500`, confirming `RelayState` is a required, actively-processed field on this endpoint, not an inert pass-through. A garbage/unsigned `SAMLResponse` correctly fails to produce a redirect **could not** determine from this alone whether a real-but-still-attacker-influenced RelayState is honored after a *valid* SAML assertion, since that requires a real signed assertion from NASA's actual IdP.

## What's proven vs. not
**Proven:** `RelayState` is accepted from an unauthenticated client with no format/origin/ allowlist validation and flows into a live, real SAML AuthnRequest against NASA's federal SSO. This is a genuine gap — the SAML spec treats `RelayState` as opaque state the SP should still validate/restrict on return (OWASP SAML guidance + real-world CA SiteMinder Federation disclosures both call this out as a known anti-pattern), and this app's own legitimate
frontend code (`chunk-A5RESISR.js`) only ever constructs a same-origin path (`getRedirectUrl() → this._winService.createFullUrl("/login", true)`) — meaning the backend accepting a fully-qualified external URL here is *more permissive than the app's own client ever sends*, a strong signal the server-side check is simply missing rather than intentional.

**Not proven:** Whether `POST /api/launchpad/assert` actually 302-redirects to an attacker's `RelayState` value after processing a *real, validly-signed* SAML assertion that's the step that would turn this into a demonstrated open-redirect-after-real-auth (chain-table.md: "Control over URL/redirect → SAML/OAuth redirect_uri → steal assertion/session → ATO"). Completing it needs a real NASA Launchpad-federated identity (PIV/CAC, or a Login.gov account NASA has linked to Launchpad) — the Earthdata Login (URS) test accounts provided this session are a **separate identity system** and do not unlock Launchpad federation.

## Why this is still worth reporting as-is
This isn't a bare "open redirect" (which is on NASA's never-submit list standalone) it's a missing-validation finding on a specific, spec'd security parameter (`RelayState`) in a live federal SAML SSO integration, with a concrete decoded AuthnRequest as evidence and a documented real-world vulnerability class (unvalidated SAML RelayState) behind it. Flagging it for NASA's own security team to verify server-side (they have the visibility into the ACS implementation that I don't) is the appropriate outcome here, with the report explicit about what's confirmed (input acceptance) vs. what needs their confirmation (post-auth redirect behavior).

## Recommended fix
Validate `RelayState` server-side against an allowlist of same-origin, application-known return paths before embedding it in the AuthnRequest, and re-validate again when it's returned from the IdP at `/api/launchpad/assert` before using it for any redirect.

## Differential evidence — a sibling NASA Launchpad integration does this correctly `images-api.nasa.gov` (NASA Image and Video Library's "Log in as a Contributor" flow) uses the **exact same** SiteMinder `RelayState`-to-`auth.launchpad.nasa.gov` SAML pattern:
```bash
curl -sI "https://images-api.nasa.gov/auth/?env=prod"
# -> 302, Location: https://auth.launchpad.nasa.gov/affwebservices/public/saml2sso?SAMLRequest=...&RelayState=https%3A%2F%2Fimages.nasa.gov%2F%23%2Flogin
```
The default `RelayState` is a hardcoded, same-origin value. Attempting the identical override attack used against AppEEARS:

```bash
curl -so /dev/null -w "%{http_code}\n" "https://images-api.nasa.gov/auth/?env=prod&RelayState=https%3A%2F%2Fexample.com%2F"
# -> 403 "Request blocked" (WAF/app-level rejection)
curl -so /dev/null -w "%{http_code}\n" "https://images-api.nasa.gov/auth/?env=prod&foo=bar"
# -> 302 (normal — an unrelated extra param is fine, so this isn't blanket param-pollution protection)
```
Only the `RelayState` override specifically gets rejected here — confirming NASA's own infrastructure is capable of (and in this sibling app, actually does) reject client-supplied `RelayState` overrides on this exact SAML integration pattern. This is strong evidence AppEEARS's lack of validation is a genuine implementation gap in that specific app, not a platform-wide accepted design — raises confidence this is a real, fixable bug rather than intended behavior.

## Second corroborating data point — same IdP, OIDC integration path is solid A separate, independent pass this session ran a full pre-auth OAuth2/OIDC audit against `urs.earthdata.nasa.gov` (Earthdata Login's own OAuth2 authorize endpoint) and the
`id.nasa.gov` → Launchpad **OIDC** federation (a different protocol path than this SAML finding, but the same underlying Launchpad IdP). Result: `redirect_uri` validation is solid on both — 16 bypass variants tried (substring, userinfo@, path traversal, scheme/case tricks, parameter pollution, double-encoding) and all correctly rejected with exact-match enforcement; `state`/CSRF is genuinely enforced (not decorative) on the Spring OAuth2 client side. So across three integration paths against the same Launchpad IdP: **OIDC (id.nasa.gov) = solid, SAML via images-api.nasa.gov = solid, SAML via AppEEARS = broken.** This tightens the case that the AppEEARS gap is a one-off implementation mistake in that app's SAML client code, not a systemic IdP-side weakness — precisely the kind of isolated, fixable bug a VDP triage team can act on quickly.
