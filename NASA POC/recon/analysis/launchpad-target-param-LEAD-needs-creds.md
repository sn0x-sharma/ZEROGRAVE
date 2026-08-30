# LEAD (unconfirmed, needs real Launchpad/Login.gov account) — `target=` param reflection on NASA Launchpad login

**Status:** Investigated, NOT yet exploitable pre-auth — needs an authenticated pass. Do not report as-is.
**Hosts:** `auth.launchpad-test.nasa.gov`, `auth.launchpad-sbx.nasa.gov`, `auth.launchpad.nasa.gov` (prod also affected per baseline check)

## What's real
`GET /kerblogin?level=20&target=<ATTACKER_URL>` reflects the raw, unsanitized
`target` value into multiple `href` attributes on the rendered login page,
including:
```
<a href="https://auth.launchpad-test.nasa.gov/login?level=20&target=<ATTACKER_URL>">Return to log in</a>
<a href="/help?level=20&target=<ATTACKER_URL>">Help</a>
<a href="https://auth.launchpad-test.nasa.gov/fed-idp?idp=login.gov&redirect_uri=<URLENCODED_ATTACKER_URL>">Login.gov</a>
```
The interesting one is the **Login.gov federated-IdP link** — `target` propagates
into `redirect_uri` on a real OAuth/OIDC federation call to login.gov (a federal
identity provider). If Launchpad honored that redirect_uri when actually
contacting login.gov, this would be a textbook OAuth-code-theft ATO chain
(chain-table.md: "Control over URL/redirect → OAuth redirect_uri → steal auth
code → ATO").

## What I disproved
- `GET /fed-idp?idp=login.gov&redirect_uri=<attacker>` (with or without a prior
  session/cookie from the kerblogin page — tested both) does **not** proceed to
  login.gov. It 302s to `/fed-idp/error?...&code=22011` (vs `code=22012` for no
  redirect_uri at all — different code, so it IS being parsed/validated, just
  rejected). Launchpad validates `redirect_uri` server-side before contacting
  login.gov. This specific chain does not work.
- `GET /login?level=20&target=<attacker>` and `GET /help?level=20&target=<attacker>`
  both just return 200 with the same self-referencing reflected links — no
  `Location` header, no actual navigation happens from an unauthenticated GET.

## Why it's unconfirmed, not ruled out
`target` is almost certainly consumed for real **after a successful Kerberos/PIV
login** (i.e., "where do I send the user once they've authenticated") — that's
the one code path I cannot reach without a real Launchpad-federated account
(NASA PIV/CAC or a linked Login.gov identity). If that post-login redirect uses
the same unsanitized `target` value to build the final `Location` header, this
would be a confirmed, high-severity open-redirect-in-SSO-flow finding (Tier 2+
per omni-killchain, ATO-adjacent). Cannot confirm or kill without credentials.

## Next step
Needs a real test account (Launchpad-federated NASA identity, or a login.gov
account NASA Launchpad accepts) to complete one real login with
`target=https://<burp-collaborator-or-controlled-domain>` and observe the
post-auth redirect. **I don't have test credentials for this program in this
session** (`credentials.md` referenced in the task brief isn't present in
`/home/sn0x/bb/targets/NASA/`) — flagged back to the user.
