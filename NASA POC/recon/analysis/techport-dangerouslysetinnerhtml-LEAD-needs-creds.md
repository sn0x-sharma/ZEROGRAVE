# LEAD (unconfirmed, needs a TechPort editor/contributor account) — Unsanitized `dangerouslySetInnerHTML` on project rich-text fields

**Status:** Sink confirmed live in a real browser on organic public data. Write
path is auth-gated (401 unauthenticated) — cannot confirm or kill without a
TechPort account with edit access to at least one project/announcement/library
item. Do not report as-is (no attacker-controlled payload has been proven to
survive the write pipeline).
**Host:** `techport.nasa.gov` (React SPA, Vite build `techport-app` v4.4.2)
**Discovered via:** source review while testing the `search?q=` reflected-XSS
surface (see `xss-notes.md` §5) — not itself a search-reflection bug.

## What's real

`techport_main.js` (the app's main bundle, ~8.8MB minified) contains 68
occurrences of `dangerouslySetInnerHTML`. Confirmed multiple of them wire
directly to API-sourced fields with **no sanitizer call wrapping the value** —
e.g. (minified, byte offsets from the fetched copy in
`/tmp/.../scratchpad/xss/techport_main.js` at time of testing):

```js
S.jsx("div",{className:dr.projectDescription,dangerouslySetInnerHTML:{__html:(u=e.project)==null?void 0:u.description}})
S.jsx("div",{dangerouslySetInnerHTML:{__html:(h=e.project)==null?void 0:h.benefits}})
S.jsx("div",{dangerouslySetInnerHTML:{__html:e.announcement.description}})
S.jsx("div",{className:Yr.liModalTopHtml,dangerouslySetInnerHTML:{__html:g.description}})   // library item
S.jsx("div",{dangerouslySetInnerHTML:{__html:"Closeout Summary: "+Ve.details}})              // technology outcome
S.jsx("div",{dangerouslySetInnerHTML:{__html:"Closeout Link: "+Ve.closeoutLinkUrl}})
```

Fields confirmed wired to this sink: `project.description`, `project.benefits`,
`announcement.description` (×2, funding-opportunity modal + card),
library item `description` (×2, modal variants for different item types),
technology-outcome `details` and `closeoutLinkUrl`.

**Live-browser confirmation (no write performed):** navigated to a real,
already-public project page, `https://techport.nasa.gov/view/158578`
(reached organically via `GET /api/projects` → `GET /api/projects/158578`,
both public/unauthenticated). The API's `description` field contains
legitimate rich-text markup:

```
"<p><strong>Project Objective</strong>\xa0\xa0</p><p>This should be your
one-sentence project description.\xa0\xa0</p>..."
```

Rendered DOM (via Playwright, `page.evaluate` reading `outerHTML`) shows this
as **live DOM elements**, not escaped text:

```html
<div><p><strong>Project Objective</strong>&nbsp;&nbsp;</p><p>This should be
your one-sentence project description.&nbsp;&nbsp;</p>...
```

This proves the render-side sink is real and reachable by any unauthenticated
visitor (project pages are public) — the only unproven step is whether the
**write** side lets a low-privileged editor store something more dangerous
than `<p>`/`<strong>`/`<em>`/`<br>`/`<a>`.

## What I checked before flagging (to avoid a low-signal report)

- **Sampled 50 random projects** (of 20,218 total, via the public
  `/api/projects` index + per-project `GET /api/projects/{id}`) and scanned
  `description`+`benefits` for `<script`, `onerror=`, `onload=`, `onclick=`,
  `onmouseover=`, `<iframe`, `javascript:`, `onfocus=`, `<svg`, `<img`. **Zero
  hits.** Only tags observed across the sample: `a`, `br`, `em`, `p`,
  `strong` — consistent with a restricted WYSIWYG toolbar. This is *not*
  proof the write path sanitizes (an editor could bypass the toolbar and post
  raw HTML directly to the API), but it means there's no existing organic
  smoking gun I can point to without writing something myself.
- **Confirmed the write endpoint is auth-gated**: `PUT /api/projects/158578`
  with an empty JSON body → `HTTP 401` (unauthenticated). `OPTIONS` on the
  same path → 200 (route exists). `GET /api/verify`, `GET /api/users` → both
  404 on this API surface (not the auth mechanism — TechPort likely gates
  writes via a session cookie / SSO front door rather than a `/api/users`
  REST resource, or those live under a different, non-public base path).
  **I did not attempt to guess/brute the real auth mechanism or send any
  payload with intent to succeed** — this is exactly the "needs an account"
  wall per the engagement's data-safety rules.
- Confirmed the search **query parameter itself** does not reach this sink or
  any other dangerous sink (see `xss-notes.md` §5) — this lead is unrelated
  to the reflected-XSS testing that was the primary ask.

## Why this matters if it pans out

TechPort project pages are public (no auth to view). If the write path does
**not** sanitize server-side and only relies on the WYSIWYG editor's toolbar
restrictions client-side (a common real-world gap — editor UI limits what a
mouse-driven user can click, but the underlying `contentEditable`/rich-text
state can still be manipulated via devtools or a direct API call to bypass the
toolbar), then any TechPort contributor/editor account could store a payload
in `project.description` that fires against **every public visitor** to that
project page — including whoever on the NASA side reviews/approves project
content, if such a review step exists. That matches the "stored XSS in
lower-priv content → higher-priv reviewer → escalation" chain pattern
(listmonk GHSA-jmr4-p576-v565 class, per the `hunt-xss` skill's Chain 1). Also
worth checking once credentialed: whether `announcement` fields (funding
opportunities) are editable by a broader population than `project` records,
since that could be an easier/lower-privilege entry point.

## What to test once a TechPort account exists

1. Confirm whether the account has edit access to any `project.description`,
   `project.benefits`, `announcement.description`, a library item
   `description`, or a technology-outcome `details`/`closeoutLinkUrl` field.
2. Try submitting via the WYSIWYG editor first (toolbar-limited — expect
   failure/stripping).
3. **Then** try sending the same field directly via `PUT /api/projects/<id>`
   (or whatever the real authenticated write call is — re-derive from the
   authenticated network trace, the anonymous `PUT` above only confirms the
   route exists and requires auth) with a raw payload, e.g.
   `<img src=x onerror=alert(document.domain)>`, bypassing the editor's
   toolbar restrictions entirely.
4. If it saves, reload the project's public view page **unauthenticated in a
   separate browser context** and confirm execution (Tier 1 alert, or
   `document.title=` marker if dialogs are suppressed) — this is the step
   that turns this from a lead into a reportable stored XSS.
5. If it saves but only after edits are "approved" by a second role, that
   approval step is the higher-value target — same payload, but confirm
   execution fires in the **approver's** session, not just the author's own
   (self-XSS doesn't count per `rules/never-submit.md`; approver-context
   execution does).
6. Revert/clean up any test payload immediately after confirming, per the
   engagement's data-safety rules (no permanent modification of real
   project data).
