# Authenticated, readable SSRF from the parent process via PageExtractorParent.getHeadlessExtractor

**Summary:** `PageExtractorParent.getHeadlessExtractor` applies its host validation only when
`anonymousFetch` is set, so the default path fetches any caller-supplied http/https URL — including
loopback and RFC1918 — from the parent process, with the profile's cookies, and returns the page text.

- **Firefox Version:** 153.0.1 (Build ID `20260727124451`); also confirmed at mozilla-central tip
- **OS:** Linux x86_64
- **Severity:** High — authenticated + readable + internal-reachable SSRF in the parent process
- **Component:** Toolkit :: General (`toolkit/components/pageextractor`), with a Firefox :: AI Window aspect

## Precondition (honest)

Requires script execution inside `about:welcome`, **plus** the AI Window enabled.
`browser.smartwindow.enabled` ships `false`.

The enable chain is reachable from `about:welcome` page scope over the ungated
`AWPage:SPECIAL_ACTION` route and was runtime-confirmed persisted to `prefs.js`:

```
browser.smartwindow.enabled                false -> true
browser.smartwindow.isDefaultWindow        false -> true
browser.smartwindow.firstrun.hasCompleted  false -> true
```

**Simpler still — the feature self-enables from one action, no `SET_PREF` allowlist needed.**
`SpecialMessageActions.sys.mjs:930-932` maps `FXA_AIWINDOW_SIGNIN_FLOW` to
`AIWindow.launchWindow(browser)`, and that function turns the pref on by itself
(`browser/components/aiwindow/ui/modules/AIWindow.sys.mjs:893-904`):

```js
async launchWindow(browser, openNewWindow = false, trigger = "other") {
  if (this.isBlocked) { return false; }
  // if browser.smartwindow.enabled is false
  // set the pref explicitly true
  if (!this.isAllowed) { Services.prefs.setBoolPref(PREF_SMARTWINDOW_ENABLED, true); }
```

`isAllowed` is just the pref itself (`:1117-1119`), and `isBlocked` is false unless enterprise AI
Control policy blocks it (`:1089-1094`). Runtime-confirmed on stock 153.0.1: issuing the single
action `AWSendToParent("SPECIAL_ACTION", {type:"FXA_AIWINDOW_SIGNIN_FLOW", data:{}})` from
`about:welcome` page scope, with **no `SET_PREF` call at all**, left this in the profile's own
`prefs.js`:

```
user_pref("browser.smartwindow.enabled", true);
user_pref("places.semanticHistory.smartwindow.featureGate", true);
```

So the "ships disabled" mitigation is one page-scope message away from being undone, by a code path
whose explicit purpose is to enable the feature.

**No web-content path into `about:welcome` was found and none is claimed.** That was closed with
runtime evidence: no query/hash/`window.name` reflection, CSP `script-src resource: chrome:` with no
`unsafe-inline`, page not frameable, `window.open` / `location.href` both denied.

The final LLM step — an indirect prompt injection causing the model to pick the tool argument — is
**not demonstrated**. It is established prior art against AI browser assistants.

## Root Cause

`toolkit/components/pageextractor/PageExtractorParent.sys.mjs:147`

```js
static async getHeadlessExtractor({ urlString, callback, anonymousFetch }) {
  const url = URL.parse(urlString);
  if (!url) throw new Error("A valid URL must be provided.");
  if (!["http:", "https:"].includes(url.protocol)) { throw ... }   // always
  if (anonymousFetch && url.protocol === "http:") {                // ONLY when anonymousFetch
    const principal = Services.scriptSecurityManager.createContentPrincipal(url.URI, {});
    if (!principal.isLoopbackHost && !principal.isLocalIpAddress) { throw ... }
  }
  return lazy.HiddenBrowserManager.withHiddenBrowser(...)
}
```

The host check is inside the `anonymousFetch` branch. The default path has **no host restriction**.

The caller-side gate that decides which path is used fails open —
`browser/components/aiwindow/models/Tools.sys.mjs:922-926`:

```js
if (!mentionedUrls.has(url) &&
    conversation.securityProperties.untrustedInput &&
    conversation.securityProperties.privateData) { ...restricted... }
return PageExtractorParent.getHeadlessExtractor({ urlString: url, ... });   // unrestricted
```

Five of seven tools raise only one of the two flags:

| tool | line | flags set |
|---|---|---|
| `getOpenTabs` | `Tools.sys.mjs:422` | privateData only |
| `searchBrowsingHistory` | `Tools.sys.mjs:491` | privateData only |
| `getUserMemories` | `Tools.sys.mjs:1025` | privateData only |
| `worldCupMatches` | `Tools.sys.mjs:1090` | untrustedInput only |
| `worldCupLive` | `Tools.sys.mjs:1121` | untrustedInput only |
| `runSearch` / `#runExtraction` | `Tools.sys.mjs:666-667`, `:983-984` | both |

The team's own decision table at `Tools.sys.mjs:809-821` records ALLOW for both the "Private only"
and "Untrusted only" rows under "any urls".

## Impact

An attacker who controls the tool argument obtains, executed **by the parent process**:

- fetch of any `http:`/`https:` URL, including `127.0.0.1` and RFC1918;
- the victim's **cookies** attached to that request;
- the **response body text** returned back.

That is a read-any-authenticated-page primitive against internal services that web content cannot
reach at all.

## Steps to Reproduce

1. Extract stock `firefox-153.0.1.tar.xz` (linux-x86_64).
2. Start the listener: `python3 listener.py` (binds `0.0.0.0:8999`).
3. Prime a cookie for the origin so the profile's jar holds one (the PoC does this by visiting
   `/victim-visit`, which responds `Set-Cookie: sessionid=VICTIM_SESSION_abc123`).
4. Launch Firefox on `about:welcome` with Marionette (see `video-poc-steps.md` for exact flags).
5. Run `python3 poc.py`. It applies the enable chain, then drives
   `GetPageContent.getPageContent` — the real entry point — once per security-flag state.

## Expected Result

A parent-initiated fetch to an internal address, on behalf of a page, should be refused; and a
conversation tainted with either private data or untrusted input should not be able to reach an
arbitrary host.

## Actual Result

| conversation state | tool return | internal server received request? |
|---|---|---|
| **privateData only** | "Could not retrieve the content for the page: …" | **YES — `Cookie: sid=VICTIM_COOKIE_xyz`** |
| **untrustedInput only** | "Could not retrieve the content for the page: …" | **YES — `Cookie: sid=VICTIM_COOKIE_xyz`** |
| both flags | "Access is not allowed … untrusted and private content" | **no request at all** |

The "Could not retrieve the content" string is the *extraction* failing on stub HTML, not a block —
the authenticated request had already been made.

## Proof

Scheme/target matrix, driven from chrome scope on a clean profile:

| # | call | result | out-of-band evidence |
|---|---|---|---|
| A | `http://127.0.0.1:8999/SSRF-INTERNAL` (no `anonymousFetch`) | **ALLOWED** | local listener hit |
| B | `http://<collab>/SSRF-external-http` | **ALLOWED** | Collaborator HTTP hit |
| C | `http://<collab>/…` **+ `anonymousFetch`** | REFUSED — *"Only https: URLs are supported for anonymous fetches."* | control |
| D | `http://127.0.0.1:8999/…` + `anonymousFetch` | **ALLOWED** | local listener hit |
| E | `file:///etc/passwd` | REFUSED — *"Only http: and https: URLs are supported."* | control |
| F | `https://<collab>/FIREFOX-PARENT-SSRF-unrestricted` | **ALLOWED** | Collaborator HTTP hit |

C and E are the controls proving the validation exists and functions — it is simply not wired to the
default path.

Readability: `getHeadlessExtractor({urlString:"http://127.0.0.1:9100/authed-nonanon", callback:extract})`
returned `SECRET_ACCOUNT_BALANCE_99999`.

Authentication, observed server-side:

| request made by the parent | `Cookie` header |
|---|---|
| `/victim-visit` (victim's own browsing) | `sessionid=VICTIM_SESSION_TOKEN_abc123` |
| **`/SSRF-AUTHED-nonanon`** (default path) | **`sessionid=VICTIM_SESSION_abc123`** |
| `/SSRF-AUTHED-anon` (`anonymousFetch:true`) | *(none)* |

`http://169.254.169.254/latest/meta-data/` was **not refused by validation** — it reached the load
stage and failed only because the test host is not a cloud instance.

## Patch Suggestion

The corrective pattern already ships in-tree. `toolkit/components/ipprotection/fxa/GuardianClient.sys.mjs:81-100`
re-validates the origin on **every navigation** and calls `browser.stop(); throw` on violation.

1. Apply the host/scheme policy on **every** path of `getHeadlessExtractor`, not only
   `anonymousFetch`; refuse loopback, RFC1918 and link-local for parent-initiated fetches.
2. Do not attach the profile cookie jar when the URL did not come from the user.
3. Change the `Tools.sys.mjs:922-926` gate from `&&` to `||` — either taint alone should restrict an
   outbound fetch — and audit the tool table so every tool raises the flags its data warrants.

Related: `intl/locale/LangPackMatcher.sys.mjs:178-196` is a second parent-side fetcher with no host
policy (filed separately as finding 02), so a fix should be scoped as a pattern, not a one-off.

---

## The 152 → 153 diff shows the protections were written, then applied to the wrong path

This is not an oversight of "nobody thought about it". Firefox 153 **added** a full protection suite to
this exact function — and placed every part of it behind `if (anonymousFetch)`.

In 152.0.6 the signature and body were:

```js
static async getHeadlessExtractor(urlString, callback) {
  const url = URL.parse(urlString);
  if (!url) { throw new Error("A valid URL must be provided."); }
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Only http: and https: URLs are supported.");
  }
  return lazy.HiddenBrowserManager.withHiddenBrowser(async browser => {
    ...
    browser.loadURI(url.URI, {
      triggeringPrincipal: Services.scriptSecurityManager.getSystemPrincipal(),
    });
```

153 adds the `anonymousFetch` option and, gated on it, all of the following:

```js
if (anonymousFetch && url.protocol === "http:") {
  // Only loopback (e.g. localhost) and local network URLs are allowed to use http
  const principal = Services.scriptSecurityManager.createContentPrincipal(url.URI, {});
  if (!principal.isLoopbackHost && !principal.isLocalIpAddress) {
    throw new Error("Only https: URLs are supported for anonymous fetches.");
  }
}
...
if (anonymousFetch) {
  browser.setAttribute("disableglobalhistory", "true");   // keep out of history
  browser.mute();
  browsingContext.useTrackingProtection = true;
  browsingContext.defaultLoadFlags =
      Ci.nsIRequest.LOAD_ANONYMOUS              // strip cookies, HTTP auth, credentials
    | Ci.nsIRequest.INHIBIT_CACHING
    | Ci.nsIRequest.INHIBIT_PERSISTENT_CACHING;
  browsingContext.sandboxFlags |=
      SANDBOXED_AUXILIARY_NAVIGATION | SANDBOXED_TOPLEVEL_NAVIGATION | SANDBOXED_FORMS
    | SANDBOXED_POINTER_LOCK | SANDBOXED_AUTOMATIC_FEATURES | SANDBOXED_MODALS
    | SANDBOXED_ORIENTATION_LOCK | SANDBOXED_PRESENTATION | SANDBOXED_STORAGE_ACCESS
    | SANDBOXED_DOWNLOADS;
}
...
if (anonymousFetch) {
  referrerInfo.init(Ci.nsIReferrerInfo.NO_REFERRER, true, null);   // suppress Referer
  // ...and no session-history entry
}
```

The posture that results is inverted:

| | anonymous path | **default path (this report)** |
|---|---|---|
| host restriction (loopback / local IP only for `http:`) | **yes** | **no** |
| cookies / HTTP auth stripped (`LOAD_ANONYMOUS`) | **yes** | **no — user's cookies are sent** |
| tracking protection | yes | no |
| response kept out of cache | yes | no |
| kept out of browsing history | yes | no |
| 10 sandbox flags on the loaded page | yes | no |
| `Referer` suppressed | yes | no |

Every protection is on the request that carries **no** user identity, and none is on the request that
carries the user's cookies. The restriction this report asks for already exists in the file — it is
three lines above, applied to the wrong branch.

(153 also changed the triggering principal from `getSystemPrincipal()` to
`createNullPrincipal({})` for both paths, which is a genuine hardening and is not disputed here.)
