# New leads surfaced from the 24k-host httpx sweep (partial results, sweep still running)

## Worth a deeper look later
- **`adminapp-govprod.prosams.nasa.gov`** — "NASA SBIR | STTR ProSAMS" admin app, live
  200, Vite/React SPA shell (no server-rendered content, would need real browser + API
  call inspection to see if the admin API enforces auth independently of the client-side
  route guard — classic SPA "hidden by client-side check, not actually protected"
  candidate). Not yet tested beyond confirming it's reachable and unauthenticated at the
  shell level.
- **`connect.jpl.nasa.gov`** — Palo Alto GlobalProtect VPN portal. `/global-protect/login.esp`
  404'd (wrong path or version-specific route) — needs proper GlobalProtect fingerprinting
  (try `/global-protect/portal/css/login.css`, `/php/login.php`, SSL cert CN, etc.) to get
  a PAN-OS version and check against known unauth CVEs (this product family has a real
  history of pre-auth RCEs — CVE-2019-1579, CVE-2021-3064 — worth the fingerprinting effort
  if picked back up).
- **`auth.sciencecloud.nasa.gov`** — another Keycloak instance (same `/admin/` pattern as
  keycloak.luna.nasa.gov). Realm-enumerated (master/sciencecloud/science/nasa/smce) — only
  `master` exists. No login attempted. Same posture as the luna instance — likely hardened,
  low priority to revisit without a specific CVE or credential to try.
- **`box-external-low.nasa.gov`** — ADFS IdP-initiated SSO into Box.net (`authfs.launchpad.nasa.gov/adfs/ls/IdpInitiatedSignOn.aspx?LoginToRP=box.net`).
  Third-party SaaS destination — the ADFS server itself (`authfs.launchpad.nasa.gov`) might
  be worth the same RelayState/redirect scrutiny as the SAML finding already written up, but
  not yet tested (ADFS IdP-initiated SSO has its own well-known bug classes — untested here).

## Ruled out / low value
- **Classic SiteMinder WebAgent hosts** (`cxhazard.nasa.gov`, `cxfmea-cil.nasa.gov`,
  `cxgmip.nasa.gov`, `cxpraca.nasa.gov`, `cpoms.nasa.gov`, `cplms-sim.mas.nasa.gov`) — these
  are legacy Constellation-Program-era internal apps, all SiteMinder-WebAgent-gated with a
  `TARGET=-SM-<url>` parameter. Unlike the AppEEARS finding, the `TARGET` value here is
  constructed server-side from the WebAgent's own host+path context, not from any
  client-supplied query parameter I could find — quick test on `cxhazard.nasa.gov/index.cgi`
  showed the TARGET always matches the requested host+path exactly, no injection point
  found via simple means. Not pursued further (diminishing returns vs. the confirmed
  AppEEARS gap); would need proxy-level Host-header/request-line manipulation to push
  further, which is unlikely to work externally due to TLS SNI binding.
- Many `*.earthdatacloud.nasa.gov` SIT/UAT API/dashboard hosts return CloudFront/Akamai
  `403 ERROR: The request could not be satisfied` — IP-allowlisted, not publicly testable.

## Sweep status
`recon/raw/all-public-httpx.txt` still growing (background job, 30-min hard cap) —
re-grep periodically for more `admin|login|dashboard|console|api` hits as it fills in.
