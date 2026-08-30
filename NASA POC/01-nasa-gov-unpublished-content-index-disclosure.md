# Unauthenticated Disclosure of Unpublished/Draft Content Index — www.nasa.gov

**Status:** Validated (confirmed live, low/informational impact — needs chain or accept as P3/P4)
**Target:** https://www.nasa.gov
**Endpoint:** `GET /wp-json/nasa-external-content/v1/unpublished-posts`
**Class:** Broken Access Control / Information Disclosure (CWE-862 Missing Authorization)

## Summary
Custom WordPress REST route ships with no `permission_callback` (or `__return_true`),
so it is reachable fully unauthenticated. It returns an internal index of ~3,940
posts across every registered content type (`post`, `page`, `mission`, `event`,
`press-release`, `people`, `gallery`, `blogs-migration`, etc.) each as `{id, time}`
— internal DB post ID + last-modified unix timestamp.

## PoC
```bash
curl -s https://www.nasa.gov/wp-json/nasa-external-content/v1/unpublished-posts
```
Returns HTTP 200 with body (truncated):
```json
{"post":[{"id":88468,"time":1784744877}],"event":[{"id":726870,"time":1785528468}],
"press-release":[{"id":878036,"time":1750170525}],"people":{"1":{"id":871051,...}}, ...}
```
No auth header, cookie, or nonce required. Query params are parsed but ignored —
response is identical regardless of input (tested `?type=`, `?full=1`, `?content=1`).

## Impact (what this does NOT give you)
Chained against `GET /wp-json/wp/v2/<type>/<id>` to see if the leaked IDs unlock
full draft content — they do **not**. Draft/non-public items correctly 401
(`rest_forbidden`) on the standard `wp/v2` routes. Already-published items (e.g.
press-release 878036) just return their normal public content. So this leaks
**existence + internal ID + edit-timestamp only**, not body/title/content.

## Impact (what it does give you)
- Enumerable internal post IDs for every content type, usable as an oracle for
  "NASA is actively editing/about to publish X" (mission pages, embargoed events,
  press releases, staff bio pages) ahead of public release — an embargo/timing
  leak, not a data leak.
- `blogs-migration` (3,884 of the 3,940 entries) is almost certainly inert
  migration bookkeeping from the site consolidation, not real editorial content.
- Confirms a missing-authorization pattern in NASA's custom `nasa-*` / `edac` /
  `synts` plugin family — worth a second pass on sibling routes (see below).

## Sibling routes checked (Rule 8 sibling sweep)
| Route | Method | Auth required? |
|---|---|---|
| `/nasa-external-content/v1/unpublished-posts` | GET | **No — leaks (confirmed above)** |
| `/nasa-hds/v1/query-gf-forms` | GET | Yes — 401 `rest_forbidden` |
| `/nasa-hds/v1/query-fds-tables` | GET | Yes — 401 `rest_forbidden` |
| `/edac/v1/fixes`, `/fixes/update` | GET/POST | Not yet tested live (POST — deferred, mutating) |
| `/synts/v1/find`, `/create` | POST | Not yet tested live (POST — deferred, mutating) |
| `/gwiz/v1/license/*` | GET/POST | Not yet tested — plugin licensing, low priority |

## Verdict
Real, reproducible, in-scope (www.nasa.gov is Target 1). Not on NASA's never-submit
list (not headers/CORS/version-disclosure/verbose-error). Severity is genuinely
low no PII, no auth bypass, no content body — so this is P4/P3 (Informational–Low)
on its own. Logged here rather than submitted standalone; revisit if a chain shows
up (e.g. an internal `content-lists` or preview route that accepts these IDs and
returns full body — `nasa-hds/v1/content-lists` untested, worth a follow-up).

