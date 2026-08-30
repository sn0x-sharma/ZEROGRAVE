# XSS Testing Notes — Search Surfaces (www.nasa.gov / NTRS / CKAN / images / TechPort)

**Date:** 2026-08-01
**Scope:** *.nasa.gov (in-scope per scope.yaml)
**Status:** All 5 assigned surfaces tested reflected/DOM XSS on search functionality.
No confirmed browser-executable XSS found on any of the 5. One high-value lead
(unsanitized `dangerouslySetInnerHTML` sink on TechPort project pages) flagged
separately — see `techport-dangerouslysetinnerhtml-LEAD-needs-creds.md` — it is
**not** a search-reflection bug, it needs credentialed write-path testing to
confirm/kill.

## Methodology

For every surface: (1) curl baseline with a unique canary (`xSsCaNaRy9911<>"'/`)
to map every reflection point and its exact encoding, (2) targeted payloads per
reflection context (tag injection, attribute breakout, encoding/WAF-bypass
variants per `rules/waf-bypass-protocol.md` and `rules/payloads.md`), (3) source
review of client-side JS bundles for dangerous sinks (`innerHTML`,
`dangerouslySetInnerHTML`, `bypassSecurityTrustHtml`, `[innerHTML]`/`v-html`),
(4) real-browser verification via Playwright (Chromium, `/usr/bin/chromium` —
see environment note below) walking detection Tiers 1/4/5 (dialog listener,
DOM-marker/global-var write via `onerror`/`onload`/`onfocus` triggers, and
direct DOM-tree inspection via `querySelectorAll` for injected elements) — not
just watching for a popped `alert()`, but inspecting `outerHTML` of the
reflection point directly to see whether the parser treated our input as
markup or as encoded text.

**Environment note:** Playwright's bundled browser cache at
`~/.cache/ms-playwright` is broken/incomplete on this machine (only lock files
present, no actual browser binary under the `chromium-1208` dir despite
`playwright.chromium.executable_path` reporting one exists). Use the system
Chromium instead: `p.chromium.launch(headless=True,
executable_path="/usr/bin/chromium", args=["--no-sandbox"])`.

---

## 1. www.nasa.gov site search — RULED OUT

**Real search param is `?search=`** (not `?s=` — that's WP's default search
which this theme doesn't use; `/search/` also 404s). Confirmed via homepage
quick-link hrefs (`/?search=Artemis`, `/?search=Climate%20Change`, etc.).

### `GET /?search=<payload>`
- Server-side rendered (unlike the other 4 SPA-ish targets). Reflected in
  exactly 4 places on the results page, consistently, regardless of payload
  shape (tested plain tags, `<script>`, `<img onerror>`, `<svg onload>`, nested
  tags, self-closing, incomplete/unbalanced tags, quote-only, angle-bracket
  soup):
  1. `<title>N Search Results for "&lt;payload text&gt;"</title>` — text-node
     content. Whatever generates this (page comment credits "Rank Math PRO" SEO
     plugin) runs something equivalent to WordPress's `wp_strip_all_tags()`
     (= `strip_tags()` + whitespace normalize): **complete `<tag>...</tag>`
     pairs are removed entirely** (inner text of `<script>` and `<img>`
     survives as literal text, e.g. `<script>alert(1)</script>` → title becomes
     `alert(1)`; self-closed/empty tags like `<img onerror=... >` or
     `<svg onload=...>` vanish completely, nothing survives). Raw `"`/`'`/`/`
     pass through **unescaped**, but this is a text node, not an attribute, so
     quotes are inert there.
  2. `<h1><span>` "Search Results for: X" — same behavior as #1 (same
     stripping, same unescaped quotes, same text-node context = inert).
  3. `<meta name="parsely-link" content="https://www.nasa.gov/?search=X">` —
     quote/tag characters are dropped entirely here (this one behaves like
     `esc_url()` — different, stricter code path than #1/#2). Not exploitable.
  4. `<form ... action='/?search=X' ...>` (Gravity Forms hidden field) — value
     stays **percent-encoded** here (`%22%27` etc., never decoded), so it can't
     break the single-quoted attribute. Not exploitable.
- **WAF present and doing real work**: any payload with an unbalanced/unclosed
  angle bracket (`<img src=x onerror=alert(1)` with no closing `>`, `<<<>>>`,
  `<<script>alert(1)</script>`) gets a flat **HTTP 400** before it even reaches
  the app. Well-formed (matched) tags pass the WAF and get neutralized by the
  app's own stripping instead.
- Tested via curl (10+ payload/encoding variants) and confirmed via Playwright:
  no dialog, no `window.__xss_proof` write, no injected `<script>`/`<svg
  onload>` element anywhere in the rendered DOM, for `<script>alert(document.domain)</script>`,
  `<svg onload=alert(document.domain)>`, and a `document.title=` DOM-marker
  variant.
- Also tested the **live autocomplete widget** on the homepage (typed
  `<img src=x onerror=window.__xss_proof=1337>` into the header search input,
  waited for suggestions) — no dropdown rendered, no injected element, no
  proof-of-execution global set.
- `wp-json/nasa-hds/v1/faceted-filter-query?search=` and
  `.../faceted-filter-autocomplete?search=` (the two REST routes named in the
  brief): confirmed real param name is `search` (other names like `q`, `term`,
  `s` are accepted but ignored — response length is identical to the
  no-param baseline). Neither endpoint reflects the query string anywhere in
  its JSON response body (0 raw/encoded hits for the canary) — they return
  post objects filtered by the query, not an echo of the query itself, so
  there's no reflected-XSS surface in the API response itself. (Both fields
  in the returned objects, `desc`/`markup`, are empty for organic content in
  this sample; `image` contains genuine pre-built `<img>` HTML from
  WordPress's media library, i.e. the CMS's own trusted markup, not
  user-input.)

**Verdict: RULED OUT.** Exhausted encoding/tag/attribute variants across 4
reflection points, mapped the WAF's specific block condition (unbalanced
angle brackets), and browser-confirmed zero execution and zero DOM injection.

---

## 2. NTRS (ntrs.nasa.gov) — RULED OUT

### `GET /search?q=<payload>` (Angular SPA, server-prerendered/SSR snapshot)
- Exactly **one** reflection point in the SSR HTML:
  `<input _ngcontent-sc103="" formcontrolname="q" ... value="PAYLOAD" class="ng-untouched ng-pristine ng-valid">`
- `"` is HTML-entity-encoded (`&quot;`); `<`, `>`, `'` are **not** encoded.
  This asymmetric pattern (only the delimiter char escaped) is exactly what
  you get when a headless-browser DOM snapshot is serialized back to a string
  via the browser's own `outerHTML`/attribute-serialization algorithm (which
  per the WHATWG spec only ever needs to escape `&` and the attribute's own
  quote character) — i.e. this value was almost certainly set via
  `element.value = query` (a safe DOM property write, not `innerHTML`) and
  then the whole page was serialized for SEO/prerendering. Structurally
  **cannot** be attribute-broken-out-of: there is no way to introduce a raw
  `"` into a `"`-delimited attribute that the browser's own serializer
  produced, by construction.
- Citation `title`/`abstract` fields (the "details page renders API-sourced
  fields as HTML" question from the brief): reviewed the Angular bundle
  (`main.js`, 1.98MB). Title is rendered via `s.Oqu(J.title)` = Angular's
  compiled `ɵɵtextInterpolate` (safe `{{ }}` binding → `textContent`, not
  `innerHTML`). `this.seo.updateTitle(this.record.title)` /
  `updateDescription(...)` use Angular's `Title`/`Meta` services (safe DOM
  APIs, not innerHTML). `DomSanitizer.bypassSecurityTrustHtml` appears exactly
  once in the whole bundle as the framework's own method *definition*; grepped
  for every call site — the only place it's invoked is
  `bypassSecurityTrustResourceUrl("/assets/STI_logo.svg")`, a hardcoded static
  asset, never citation data. No `[innerHTML]` binding tied to citation fields
  found anywhere in the bundle.
- Searched the live API for organic citations with `<`/`>` in the title (to
  check real-world rendering without needing to submit anything) — 0 results,
  so no organic test case existed, but the source review above is decisive
  regardless (framework-level safe binding, not a "no dangerous input seen
  yet" gap).
- Playwright-confirmed: `<script>`, `<svg onload>`, and a `"` +
  `autofocus onfocus=` attribute-breakout attempt on `q` — zero dialogs, zero
  injected elements, page title/DOM unchanged.

**Verdict: RULED OUT.** Both the static-analysis (safe Angular bindings) and
dynamic (Playwright) results agree.

---

## 3. data.nasa.gov (CKAN 2.11.5) — RULED OUT

Tested `/dataset?q=`, `/organization?q=`, `/group?q=`, `/dataset?tags=`,
`/organization/nasa?q=`.

- Every reflection point (search input `value=`, "N datasets found for X" H1,
  "Remove applied filter" aria-labels, sidebar facet-link hrefs, pagination
  links) consistently HTML-entity-encodes `<`, `>`, `"`, `'` (`&lt;` `&gt;`
  `&#34;` `&#39;`) — standard Jinja2 auto-escape, applied uniformly across
  every template/page checked (33 occurrences mapped on the main dataset
  search page alone, all safely encoded).
- Facet-link `href="/dataset/?q=...&organization=nasa"` values are
  URL-percent-encoded (`%3C%3E%22%27`), never decoded-then-reflected raw.
- Playwright-confirmed on `/dataset?q=<script>...` and a `"` +
  `autofocus onfocus=` attribute-breakout attempt: zero dialogs, zero
  `window.__xss_proof` write, search input in the live DOM carries no
  attacker-controlled `value` at all in the rendered page (a separate
  sitewide-search widget with no value binding, distinct from the
  server-rendered `ant-search` input seen via curl — also confirmed clean).
- This is a materially newer/harder CKAN than the "classic reflected XSS in
  search page" issues the skill file flags for older CKAN — 2.11.5 appears to
  have this consistently patched across dataset/org/group/tag templates.

**Verdict: RULED OUT.**

---

## 4. images.nasa.gov search — RULED OUT

Angular SPA (Angular Universal-style build), served from S3+CloudFront.
`Content-Security-Policy` header present is **report-only**
(`content-security-policy-report-only`), i.e. not actually enforced — noted
for awareness, but moot here since no injection point was found.

- `GET /search?q=<payload>` shell HTML (curl) never contains the query — it's
  a pure client-rendered SPA (confirmed via headers: `server: AmazonS3`,
  static shell only).
- Live-DOM dump (Playwright, `wait_until="load"` + settle time) found the
  **one** place the query renders client-side:
  `<h2> Showing ... for <strong>"QUERY"</strong>: </h2>`
- Decisive test: sent `<script>...</script>`, `<svg onload=...>`,
  `<img src=x onerror=...>`, and two attribute-breakout variants. Inspected
  the actual `<strong>` element's `outerHTML` after render in every case:
  content came back HTML-entity-encoded
  (`<strong>"&lt;script&gt;window.__xss_proof=1337&lt;/script&gt;"</strong>`),
  confirming genuine Angular `{{ }}` text interpolation (`textContent`
  write), not `innerHTML`. `window.__xss_proof` never set; no
  `<script>`/`<svg onload>`/`<img onerror>` element ever created in the DOM
  tree; zero dialogs across all 5 variants.
- Source review: fetched `main-*.js` + all 10 lazy `chunk-*.js` files
  (modulepreload list from the shell HTML). Zero app-level `innerHTML` uses
  across all 11 bundles combined — the only 3 `innerHTML` occurrences (in the
  largest chunk) are Angular's own internal `DomSanitizer` implementation
  (`getInertBodyElement`/`sanitizeChildren` — the framework's *own* defense
  mechanism). `bypassSecurityTrustHtml` never called anywhere in any bundle.

**Verdict: RULED OUT.**

---

## 5. techport.nasa.gov project search — search reflection RULED OUT; separate lead flagged

React SPA (Vite build, `techport-app`).

- `GET /search?q=<payload>`: static shell HTML never contains the query. Live
  DOM dump (Playwright) after full render: **the query does not appear
  anywhere in the rendered DOM or visible body text.** The "No results to
  display" messaging is a static string literal (`children:"No results to
  display"` in the bundle) — it does not interpolate the query at all.
  Grepped the 8.8MB main bundle for `searchTerm`/`searchQuery`/`results for`/
  `no results` near any dynamic value — nothing. Search-result-list project
  titles render via plain JSX `children:` (React auto-escaped text), not
  `dangerouslySetInnerHTML`.
- Playwright-confirmed on `<script>`/`<svg onload>` payloads on `?q=`: zero
  dialogs, zero DOM change, title unchanged.

**Verdict on the search `q` parameter itself: RULED OUT.**

**However** — while source-reviewing the bundle for the search path, found a
genuine, unsanitized `dangerouslySetInnerHTML` sink rendering **project
description/benefits/announcement/library-item content** (reached by
searching → clicking into a project, i.e. still within this surface's user
journey, just not the `q` param itself). Confirmed live via Playwright on
organic, already-public project data (real `<p><strong>` markup renders as
live DOM elements, not escaped text). This is a real stored-XSS-*shaped*
finding but the write endpoint (`PUT /api/projects/<id>`) is auth-gated
(confirmed 401 unauthenticated), so exploitability can't be confirmed or
killed without a TechPort account. **Full writeup:**
`techport-dangerouslysetinnerhtml-LEAD-needs-creds.md` in this same directory.
Flagging per the operator's request to surface promising stored-XSS-shaped
fields for credentialed follow-up — note this needs **TechPort's own
account** (its API references `/api/users`, `/api/verify` — a separate CMS
auth system), not necessarily Earthdata/GLOBE creds specifically.

---

## Summary Table

| Surface | Param | Reflected? | Context | Encoding/Defense | Browser-exec? |
|---|---|---|---|---|---|
| www.nasa.gov | `?search=` | Yes (4 spots) | text-node ×2, meta attr, form attr | `wp_strip_all_tags()`-style + WAF (400 on malformed tags) + esc_url + percent-encoding preserved | No |
| ntrs.nasa.gov/search | `?q=` | Yes (1 spot) | `value=` attribute (SSR/DOM-snapshot) | Browser-serialization-safe (only delimiter quote escaped, structurally unbreakable) | No |
| data.nasa.gov/dataset | `?q=`, `?tags=` | Yes (33+ spots) | text-node + attributes | Jinja2 auto-escape, consistent `&lt;&gt;&#34;&#39;` | No |
| images.nasa.gov/search | `?q=` | Yes (1 spot) | Angular text interpolation | `textContent`-only binding, confirmed via outerHTML inspection | No |
| techport.nasa.gov/search | `?q=` | No | — | Not reflected anywhere in DOM | No |

All 5 search surfaces: **no confirmed XSS.** No further action needed on
search reflection specifically. See the separate LEAD file for the TechPort
`dangerouslySetInnerHTML` follow-up item.
