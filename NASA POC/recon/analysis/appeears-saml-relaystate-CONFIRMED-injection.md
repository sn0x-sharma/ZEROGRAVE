# CONFIRMED: Unvalidated SAML RelayState injection — AppEEARS → NASA Launchpad SSO

**Status:** Confirmed live behavior, severity/exploitability still being pinned down.
**Host:** `appeears.earthdatacloud.nasa.gov`
**Endpoint:** `GET /api/launchpad/login?RelayState=<ATTACKER_URL>`

## PoC
```bash
curl "https://appeears.earthdatacloud.nasa.gov/api/launchpad/login?RelayState=https://evil-attacker-controlled.example.com/steal"
```
Baseline (no RelayState) → `400 {"message":"query param \"RelayState\" not present."}`
With attacker RelayState → **HTTP 200**:
```json
{"url": "https://auth.launchpad.nasa.gov/affwebservices/public/saml2sso?SAMLRequest=<base64-deflated-AuthnRequest>&RelayState=https%3A%2F%2Fevil-attacker-controlled.example.com%2Fsteal"}
```
- No auth required to hit this endpoint.
- `RelayState` is embedded **verbatim, URL-encoded, unvalidated** into a real SAML
  AuthnRequest URL pointed at NASA's real federal SSO IdP (`auth.launchpad.nasa.gov`,
  CA/Symantec SiteMinder federation — `/affwebservices/public/saml2sso` is the SiteMinder
  Federation Web Services SSO path).
- This is a **different system** from the earlier-ruled-out Launchpad `target=`/`fed-idp`
  finding (that one is OAuth2/login.gov via Launchpad's own `/fed-idp` handler, which DOES
  validate redirect_uri server-side — see `launchpad-target-param-LEAD-needs-creds.md`).
  This one is SAML2 SSO via SiteMinder, a completely separate code path, and — unlike the
  other one — the value is NOT rejected/validated at this layer.

## What's NOT yet proven
Whether the RelayState value is honored by the SP (AppEEARS) **after** a real SAML
authentication completes — i.e., does AppEEARS's Assertion Consumer Service (ACS) blindly
302 to RelayState post-login, making this a live phishing/session-hijack primitive? That
needs either a real Launchpad-federated login (not available — needs PIV/CAC or a
Login.gov identity NASA has granted Launchpad access to, not something our Earthdata test
accounts unlock) or evidence from how the front-end constructs this call.

## In progress
Checking whether AppEEARS's own frontend derives the `RelayState` value from something
attacker-controllable on the page itself (e.g. current-URL-as-return-target after login —
a very common SPA pattern) — if so, the ENTIRE chain becomes exploitable via a single
crafted `appeears.earthdatacloud.nasa.gov` link with no additional steps, which would make
this a genuine phishing-grade open-redirect-in-federal-SSO finding worth reporting even
without completing a real login (chain-table.md: "Control over URL/redirect → OAuth/SAML
redirect_uri → steal auth code/assertion → ATO").
