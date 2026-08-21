# AWEnsureLangPackInstalled: unvalidated caller-supplied URL fetched by the parent process (blind SSRF + internal port-scan oracle)

**Summary:** `about:welcome` exports `AWEnsureLangPackInstalled`, which passes a page-supplied
`langPack.url` through to `AddonManager.getInstallForURL` with no scheme, host or allowlist check,
producing a parent-process fetch of any http/https target including loopback and RFC1918.

- **Firefox Version:** 153.0.1 (Build ID `20260727124451`); also confirmed at mozilla-central tip
  (`_installAddon` byte-identical, zero validation added)
- **OS:** Linux x86_64
- **Severity:** Moderate–High — blind SSRF from the parent process with a reliable internal
  port-scan oracle, on a default-on page
- **Component:** Core :: Internationalization (`intl/locale/LangPackMatcher.sys.mjs`), reached via
  Firefox :: Messaging System (`about:welcome`)

## Precondition (honest)

Script execution inside `about:welcome`. **No feature flag is required** — `about:welcome` is
default-on and is shown to every new profile, and the sink needs nothing enabled. This is the
weakest precondition of the five findings in this package.

**No web-content path into `about:welcome` was found and none is claimed.** Closed with runtime
evidence: no query/hash/`window.name` reflection, CSP `script-src resource: chrome:` with no
`unsafe-inline`, page not frameable, `window.open` and `location.href` both denied.

## Root Cause

Full chain, every hop verified in the shipping source:

```
page scope (about:welcome)
  AWEnsureLangPackInstalled({langPack:{url, hash, target_locale}}, {})
   -> AboutWelcomeChild.sys.mjs:345-351   sendQuery("AWPage:ENSURE_LANG_PACK_INSTALLED", negotiated.langPack)
   -> AboutWelcomeParent.sys.mjs:358      LangPackMatcher.ensureLangPackInstalled(data)   [no principal check]
   -> LangPackMatcher.sys.mjs:205-209     _installAddon(langPack.url, {hash: langPack.hash})
   -> LangPackMatcher.sys.mjs:178-196     AddonManager.getInstallForURL(url, {hash}); install.install()
```

`intl/locale/LangPackMatcher.sys.mjs:178-196`:

```js
async _installAddon(url, { hash, source }) {
  let install;
  try {
    install = await lazy.AddonManager.getInstallForURL(url, {   // <- url is caller-supplied
      hash,
      telemetryInfo: { source },
    });
  } catch (error) { console.error(error); return false; }
  try {
    await install.install();                                    // <- the fetch happens here
  } catch (error) { console.error(error); return false; }
  return true;
}
```

No scheme check, no host check, no allowlist. `AboutWelcomeParent.receiveMessage` performs no
principal check and does not validate `data`.

The early-out in `_ensureLangPackInstalledImpl` (`:140-148`) returns before fetching only when
`availablelocales.includes(langPack.target_locale)`; supplying an uninstalled locale bypasses it.

## Impact

From page scope, executed **by the parent process**:

- fetch of any `http:`/`https:` URL, including `127.0.0.1` and RFC1918 addresses;
- **redirects are followed**, so a permitted first hop can be steered elsewhere;
- a **reliable timing oracle** separating open / closed / filtered ports, giving full internal host
  and port enumeration — including services bound to loopback that web content cannot reach at all.

The fetch is **blind and anonymous**: no cookies are attached and the response body is not returned
to the page. This is weaker than finding 01 and is stated plainly rather than inflated.

## Steps to Reproduce

1. Extract stock `firefox-153.0.1.tar.xz` (linux-x86_64).
2. Start the listener: `python3 listener.py` (binds `0.0.0.0:8798`, serves a `/redir` 302 and logs
   every request).
3. Launch Firefox on `about:welcome` with Marionette (exact flags in `video-poc-steps.md`).
4. Run `python3 poc.py`. From page scope it calls `AWEnsureLangPackInstalled` once per matrix row.

## Expected Result

A page-supplied URL should never cause the parent process to contact an arbitrary host, and
loopback/RFC1918 should be refused outright.

## Actual Result

The parent fetched every http target supplied, including internal ones. The returned promise
rejects afterwards, but the rejection is the post-download hash/signature failure — **not** a
pre-fetch block. The request has already left the browser.

## Proof

Captured by the listener — note `Sec-Fetch-Site: none`, i.e. parent-initiated, not a page load:

```
=== GET /LANGPACK-SSRF
    Host: 127.0.0.1:8799
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:153.0) Gecko/20100101 Firefox/153.0
    Accept: */*
    Sec-Fetch-Dest: empty
    Sec-Fetch-Mode: no-cors
    Sec-Fetch-Site: none
```

### Property matrix (measured)

| property | result |
|---|---|
| arbitrary `http:` URL fetched by parent | **YES** |
| loopback (`127.0.0.1`) reachable | **YES** — listener hit |
| **RFC1918 (`10.0.2.15`) reachable** | **YES** — listener hit |
| **redirects followed** | **YES** — `/redir` → hop 2 `/REDIR-HOP2-INTERNAL`, both received |
| cookies attached | **NO** — `Cookie: None` even after priming the jar |
| response body readable by page | **NO** — page observes only resolve/reject |

### Internal port-scan timing oracle

Elapsed measured in page script from call to promise settle:

| target | elapsed | classification |
|---|---|---|
| `http://127.0.0.1:8798` (open) | **6 ms** | open |
| `http://10.0.2.15:8798` (open, RFC1918) | **9 ms** | open |
| `http://127.0.0.1:9` (closed) | **2 ms** | closed — RST |
| `http://10.255.255.1:80` (filtered) | **21 017 ms** | filtered — no route |
| `http://169.254.169.254/latest/meta-data/` | 16 ms | reachable; **not refused by validation** |

Open / closed / filtered separate by one to four orders of magnitude, which is more than enough to
enumerate an internal network from page scope. The metadata IP failed only because the test host is
not a cloud instance — nothing in the code refused it.

## No code execution on this path — stated explicitly

The chain ends at `install.install()`, so the obvious question is whether an attacker XPI installs.
It does not, on a branded release build:

```js
// toolkit/mozapps/extensions/internal/AddonSettings.sys.mjs:32-34
if (AppConstants.MOZ_REQUIRE_SIGNING && !Cu.isInAutomation) {
  makeConstant("REQUIRE_SIGNING", true);
  makeConstant("LANGPACKS_REQUIRE_SIGNING", true);   // frozen, not pref-controlled
}
```

`makeConstant` freezes the value, so `xpinstall.signatures.required` cannot relax it on release. An
unsigned attacker langpack fails signature verification and `install.install()` rejects.

**This report therefore claims SSRF, not RCE, and ships no code-execution proof.** No calculator
PoC is included because none is honestly available here.

## Related sink, same call path, same missing validation

`AWSetRequestedLocales(locales)` → `AWPage:SET_REQUESTED_LOCALES` →

```js
// LangPackMatcher.sys.mjs:298-300
setRequestedAppLocales(locales) {
  Services.locale.requestedLocales = locales;   // no validation
}
```

Page scope sets the browser's requested UI locales directly — a persistent, browser-wide change
without consent. Lower severity, same root cause; noted so one fix covers both.

## Patch Suggestion

The corrective pattern already ships in-tree:
`toolkit/components/ipprotection/fxa/GuardianClient.sys.mjs:81-100` re-validates the origin on
**every navigation** and calls `browser.stop(); throw` on violation.

1. Validate the URL in `_installAddon` before `getInstallForURL`: require `https:`, restrict the
   host to the AMO / RemoteSettings origins that legitimately serve langpacks, and refuse loopback,
   RFC1918 and link-local.
2. Re-apply that policy **per redirect hop** via an `nsIChannelEventSink`, mirroring `GuardianClient`.
3. Better: do not accept a URL from page scope at all. The parent already has the authoritative
   list from `AddonRepository.getAvailableLangpacks()` — have the page send a `target_locale` and
   let the parent resolve the URL itself.
4. Validate the locale array in `setRequestedAppLocales` against available locales.

---

## Third instance of the same pattern — `INSTALL_ADDON_FROM_URL` (found while writing this report)

`getHeadlessExtractor` (finding 01) and `_installAddon` (this finding) are not the only two. A third
parent-side fetcher takes a caller-supplied URL with no scheme, host or allowlist check, and it is
reachable from the same `about:welcome` page scope.

`toolkit/components/messaging-system/lib/SpecialMessageActions.sys.mjs:99-121`:

```js
async installAddonFromURL(browser, url, telemetrySource = "amo") {
  try {
    this.loadAddonIconInURLBar(browser);
    const aUri = Services.io.newURI(url);                    // <- no scheme/host validation
    const systemPrincipal = Services.scriptSecurityManager.getSystemPrincipal();
    const telemetryInfo = { source: telemetrySource };
    const install = await lazy.AddonManager.getInstallForURL(aUri.spec, { telemetryInfo });
    await lazy.AddonManager.installAddonFromWebpage(
      "application/x-xpinstall", browser, systemPrincipal, install);   // <- SYSTEM principal
  } catch (e) { console.error(e); }
}
```

Reached at `:817-822` (`case "INSTALL_ADDON_FROM_URL"`), i.e. through the same ungated
`AWPage:SPECIAL_ACTION` route used by `SET_PREF`.

### Why it is reachable from page scope

`AboutWelcomeChild.sys.mjs:300-302` is a **generic passthrough**:

```js
AWSendToParent(type, data) {
  return this.sendQueryAndCloneForContent(`AWPage:${type}`, data);
}
```

so page script reaches **all 27** `AWPage:` handlers, including the five that have no dedicated
exported wrapper (`SPECIAL_ACTION`, `GET_ADDON_DETAILS`, `HANDLE_CAMPAIGN_ACTION`,
`SET_WELCOME_MESSAGE_SEEN`, `TELEMETRY_EVENT`), and through `SPECIAL_ACTION` reaches all 49
`SpecialMessageActions` types.

### Runtime confirmation, stock 153.0.1, clean profile

Called from `about:welcome` page scope as
`AWSendToParent("SPECIAL_ACTION", {type:"INSTALL_ADDON_FROM_URL", data:{url:…}})`:

```
=== GET /INSTALL-ADDON-SSRF
    Host: 127.0.0.1:8795
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:153.0) Gecko/20100101 Firefox/153.0
    Sec-Fetch-Site: none
```

| target | fetched |
|---|---|
| loopback `127.0.0.1:8795` | **YES** |
| **RFC1918 `10.0.2.15:8795`** | **YES** |

The request was made with **no user interaction and before any install doorhanger**.

Differences from the langpack sink: the action resolves immediately (fire-and-forget), so it yields
**no timing oracle**; and it is not a useful *install* primitive on release because signing is still
enforced. Its value here is that it is a **third independent instance of the identical missing
host-policy defect**.

### Why this matters for the fix

Three separate components — `toolkit/components/pageextractor`, `intl/locale`, and
`toolkit/components/messaging-system` — each hand a caller-supplied URL to a parent-process fetch
with no host policy, while `toolkit/components/ipprotection/fxa/GuardianClient.sys.mjs:81-100`
demonstrates the correct per-navigation origin check in the same tree.

A per-call-site patch will leave the pattern in place. The durable fix is a shared, mandatory
host-policy helper for any parent-initiated fetch whose URL did not originate from the user, applied
per redirect hop.

### The same feature area already validates elsewhere — internal inconsistency

`GET_ADDON_DETAILS`, reachable over the same `AWSendToParent` passthrough, lands in
`browser/components/aboutwelcome/modules/AboutWelcomeDefaults.sys.mjs:1319-1323`:

```js
async function getAddonFromRepository(data) {
  const [addonInfo] = await lazy.AddonRepository.getAddonsByIDs([data]);
  if (addonInfo.sourceURI.scheme !== "https") {     // <- explicit scheme check
    return null;
  }
```

So within the *same* onboarding feature, one addon path refuses a non-`https` source URI, while
`SpecialMessageActions.installAddonFromURL` accepts any URL at all and `LangPackMatcher._installAddon`
accepts any URL at all. The check is understood to be necessary; it is simply missing on the two
paths that take the URL from the caller rather than from AMO.

(Unrelated robustness note in the same function: `addonInfo` is not null-checked before
`addonInfo.sourceURI`, so an unknown add-on ID throws a `TypeError` rather than returning `null`.
Not a security issue — noted only because the ID is caller-supplied.)

### Fourth instance — `AIChatContent:RequestAssets` renders an arbitrary URL in the parent

`browser/components/aiwindow/ui/actors/AIChatContentParent.sys.mjs:285-292`:

```js
async #handleRequestAssets({ messageId, items }) {
  const images = await Promise.all(
    (items ?? []).map(async ({ url, thumbnail }) => ({
      url,
      image: await lazy.captureThumbnail(thumbnail),      // <- content-supplied
      hasFavicon: await this.#pageHasFavicon(url),        // <- content-supplied
    }))
  );
  this.sendAsyncMessage("AIChatContent:AssetsReady", { messageId, images });
}
```

`captureThumbnail` (`models/HistoryThumbnails.sys.mjs:30-53`) calls
`BackgroundPageThumbs.captureIfMissing(thumbnail, …)`, which **loads and renders the URL in a
background browser in the parent**. Neither `url` nor `thumbnail` is validated by the actor.

Unlike the other three, this one performs a full **page load and render**, not just a fetch.

**Ceiling — stated honestly, this is weaker than it first appears:**

- The capture runs in a **private contextual identity** whose data is cleared afterwards
  (`BackgroundPageThumbs.sys.mjs:377-381`, `:763-769`) ⇒ **no cookies**, no authenticated capture.
- `PageThumbUtils.shouldStoreContentThumbnail:359-425` requires a **2xx** status, rejects
  `Cache-Control: no-store`, rejects `about:` and XML documents, and **skips `https:`** unless
  `browser.cache.disk_cache_ssl` (default `false`) ⇒ effectively **plain `http:` targets only**.
- The resulting `moz-page-thumb://` URL is returned to the page, but **no AI Window CSP allows that
  scheme** (`aiChatContent.html`: `img-src chrome: page-icon:`;
  `aiWindow.html`: `img-src chrome: blob: data: moz-remote-image: page-icon:`) ⇒ the page **cannot
  display or read the screenshot**. There is no visual disclosure.

**What it does yield:** an unauthenticated parent-side page load of any `http:` URL including
loopback and RFC1918 — which additionally *executes that page's JavaScript* in the background
browser — plus a boolean oracle, since `captureThumbnail` returns non-null only when the target
answered 2xx. `#pageHasFavicon` (`:311-321`) independently discloses whether Places holds a favicon
for an arbitrary URL, i.e. a browsing-history existence oracle.

It is included here because it is the **fourth** component exhibiting the same missing host policy —
`toolkit/components/pageextractor`, `intl/locale`, `toolkit/components/messaging-system` and now
`browser/components/aiwindow` — which is the argument for fixing the pattern centrally rather than
per call site.
