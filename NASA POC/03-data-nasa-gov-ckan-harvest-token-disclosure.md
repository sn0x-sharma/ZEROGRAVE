# Unauthenticated Disclosure of Live API Token via CKAN `harvest_source_list` — data.nasa.gov

**Status:** VALIDATED — confirmed live, credential-in-cleartext. **NOT an SSRF finding** — found
incidentally while auditing data.nasa.gov's CKAN `harvest` extension for SSRF (the documented
CKAN SSRF class: harvest-source URL fetched server-side by the harvester). Flagging per hard
rule ("stop and flag immediately, don't dig further, if you hit real internal credentials") and
per SSRF-GODMODE checklist ("If credentials found: DO NOT USE THEM, document and report
immediately"). **The token was NOT tested, used, or validated against any endpoint.**

**Target:** https://data.nasa.gov (CKAN 2.11.5)
**Endpoint:** `GET /api/3/action/harvest_source_list`
**Class:** Information Disclosure / Credential Exposure (CWE-200 / CWE-522 Insufficiently
Protected Credentials)

## Summary
CKAN's `ckanext-harvest` extension exposes `harvest_source_list` fully unauthenticated. This
action is meant to just list harvest-source metadata (title, URL, schedule) for transparency —
but the `config` field, which is meant to hold harvester-internal configuration (auth tokens for
the *source* being harvested), is returned verbatim in the public JSON response, including a
live-looking API token in cleartext.

## PoC
```bash
curl -s https://data.nasa.gov/api/3/action/harvest_source_list
```
Relevant excerpt from the HTTP 200 response body (no auth header, cookie, or session required):
```json
{
  "id": "b99e41c6-fe79-4c19-bbc3-9b6c8111bfac",
  "url": "https://science.data.nasa.gov/science-discovery-engine/api/dcat",
  "title": "Science Discovery Engine",
  "config": "{\r\n\"api_token\": \"ee2871eb4ec766c3b0c44593db0006d8feb5a6a926758fbcd408f074573c750f\"\r\n}",
  "type": "datajson",
  "frequency": "WEEKLY",
  "next_run": "2026-08-03 15:52:07.292388",
  "status": {"job_count": 42, "last_harvest_request": "..."}
}
```
The token is a 64-char hex string, formatted like a real bearer/API token, associated with the
"Science Discovery Engine" DCAT harvest source (`science.data.nasa.gov`). Full response contains
4 harvest sources total; this was the only one with a secret-shaped `config` value (checked via
automated scan of all 4 `config` fields for `token|password|secret|key|credential|auth`
substrings — no additional exposed secrets in the other 3 entries).

## What I did NOT do (by design, per hard rule)
- Did not send the token to `science.data.nasa.gov` or any other endpoint to check validity/scope.
- Did not attempt to determine what the token authorizes (read access to a harvest feed? write
  access? something broader?).
- Did not continue enumerating other CKAN actions looking for more exposed secrets beyond the
  single automated substring scan of the 4 already-returned harvest-source configs above.

## Why this happened (root cause)
CKAN's `harvest_source_show`/`harvest_source_list` actions return the full `HarvestSource.config`
column without redaction. This column is intended for *harvester*-side settings (e.g., "here's
the token *I* use to authenticate *to* the remote DCAT feed"), which is operationally sensitive
but CKAN's default auth function for these actions (`harvest_source_list` / `harvest_source_show`)
is `chained_auth_function` → effectively public/anonymous-readable in most CKAN harvest configs,
same as this instance. NASA's team put a live token into that field, and the public list action
faithfully echoes it back to anyone.

## Impact
An unauthenticated attacker obtains a live API credential tied to a NASA Earthdata-adjacent
service (`science.data.nasa.gov/science-discovery-engine`) with zero interaction. Depending on
the token's actual scope (unverified — see above), this could range from read access to an
internal/rate-limited API up to something more privileged. Regardless of scope, a live credential
in a public unauthenticated response is a genuine, immediately actionable finding — NASA should
rotate this token and either redact `config` from the public harvest-source-list/show actions or
move secrets out of the `config` JSON entirely (e.g., a CKAN "sysadmin-only" secrets store).

## Recommendation for NASA
1. **Rotate the exposed token immediately** (`ee2871eb...c750f`, Science Discovery Engine harvest
   source, id `b99e41c6-fe79-4c19-bbc3-9b6c8111bfac`).
2. Patch `harvest_source_list`/`harvest_source_show` to strip or redact the `config` field for
   anonymous/non-sysadmin callers (CKAN core precedent: `package_show` already redacts sensitive
   fields for non-owners; the harvest extension should follow the same pattern).
3. Audit whether any other harvest sources across data.nasa.gov's history have had tokens rotated
   through this same field (this finding only confirms the *current* 4 active sources checked
   above — did not check harvest job history / revision history for older exposed tokens).

## Severity justification
Not SSRF, not on the never-submit list (not headers/CORS/version-disclosure/verbose-error — this
is a literal live credential in a JSON response body). Real impact = credential exposure with a
concrete, reproducible PoC and zero preconditions. Recommend P2 (High) pending NASA's own
assessment of what the token actually grants — flagging conservatively high given "unauthenticated
+ live credential" regardless of eventual scope determination, consistent with not testing the
token's actual privileges ourselves.
