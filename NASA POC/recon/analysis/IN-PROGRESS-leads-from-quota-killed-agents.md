# Leads salvaged from agents killed by session quota limit (resets 6pm IST)

5 agents (SSRF, OAuth, SQLi, XSS, NTRS/TechPort IDOR) were mid-investigation when the
account hit its API session limit and all died simultaneously. None had written findings
files yet. Capturing their last-known leads here from notification text before continuing
the hunt directly (curl, not sub-agents, to conserve shared quota until reset).

## LEAD 1 — SQLi: custom search endpoint with naive denylist (HOTTEST LEAD)
Agent's last words: `"This is not a WAF — it's the plugin's own wp_die() with a custom
character blocklist: 'Search term contains invalid character(s): =' Critically, the single
quote passed straight through untouched (returned identical results to the unmodified
search). That's the signature of hand-rolled string-concatenation SQL with a naive denylist
rather than parameterized queries."`
- Exact endpoint/host NOT captured in the notification — the agent was briefed on NTRS
  citations search, CKAN dataset search, WP nasa-hds/v1 routes (faceted-filter-query,
  query-iotd), and techport.nasa.gov search. `wp_die()` in the error strongly implies
  **WordPress (www.nasa.gov)**, most likely one of the nasa-hds/v1 custom routes.
- NEXT STEP: re-probe each candidate search endpoint with a bare `=` in the query param to
  find which one throws "Search term contains invalid character(s): =", then confirm the
  denylist gap (quote passes through) and push toward UNION/boolean-blind confirmation.

## LEAD 2 — OAuth/SAML: RelayState open-redirect on AppEEARS
Agent's last words: `"GET /api/launchpad/login?RelayState=<attacker-url> on AppEEARS
returned 200 — this needs a closer look since it's a SAML RelayState pattern (open-redirect-
in-SSO precedent per the skill)."`
- Host: **appeears.earthdatacloud.nasa.gov**
- Exact endpoint: `GET https://appeears.earthdatacloud.nasa.gov/api/launchpad/login?RelayState=<ATTACKER_URL>`
- NEXT STEP: confirm what "returned 200" actually contains (error page vs real SAML request
  vs reflected RelayState in a form) and whether it chains to actual credential/assertion
  theft — same chain-table.md pattern as the earlier Launchpad `target=` lead (see
  `launchpad-target-param-LEAD-needs-creds.md`), but this one might not need real login to
  prove since it could be a pure reflected-redirect at the RelayState-handling layer.

## LEAD 3 — SSRF: harmony.earthdata.nasa.gov + CMR subscriptions webhook pattern
Agent's last words: `"harmony.earthdata.nasa.gov is live (CloudFront-fronted). CMR
subscriptions (webhook-URL-on-new-data pattern — matches the task's target shape) are also
worth a close look."`
- Harmony = EOSDIS's data transformation/subsetting service (harmony.earthdata.nasa.gov) —
  processes user-supplied processing requests against real granules, could have SSRF in
  callback/STAC-catalog-URL params.
- CMR subscriptions: authenticated feature where a user registers a query + notification
  endpoint; NASA's docs historically used an `EndPoint` field — worth testing with URS bearer
  token once obtained: `POST https://cmr.earthdata.nasa.gov/search/subscriptions` with an
  SSRF-payload endpoint value and see if CMR validates/pings it server-side.
- NEXT STEP: get URS bearer token working (blocked on a curl connectivity issue right now),
  then hit the subscriptions API directly with the SSRF-GODMODE payload ladder.

## LEAD 4 (ruled out, informational only) — NTRS distribution filter
Agent's last words: `"distribution IS a real backend query param... but combined with
search it always yields 0 — confirming the search backend silently ANDs an implicit
distribution=PUBLIC regardless of what the client requests (secure by design)."`
- Good negative result — NTRS properly enforces public-only distribution server-side even
  when the client tries to override the filter. Not exploitable. Low priority to revisit
  unless a fresh angle shows up (agent was about to check `field`/`attachment` params and a
  separate `pubspace` search space — could still be worth a quick look later).

## LEAD 5 (mostly ruled out) — NTRS XSS via value= attribute
Agent's last words: `"NTRS's value= attribute reflection only escapes ", matching standard
DOM-serialization behavior — likely SSR/prerendered from a real DOM snapshot and NOT
breakable via that specific attribute."`
- Was moving on to check the citation-detail-page rendering path specifically. Low priority,
  looked clean.

## Status
Continuing these directly via curl/Bash (not re-dispatching agents) until the 6pm IST quota
reset, to avoid burning shared session budget on agents that'll just fail immediately again.
