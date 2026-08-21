# Systemic `ValidatePrincipal` log-and-continue: 13 IPC handlers accept spoofed principals on release builds; `RecvCreateWindowInDifferentProcess` has NO validation at all and loads attacker-controlled URIs with spoofed triggering principal

**Component:** Core :: DOM: Content Processes  
**Affected:** mozilla-central tip (verified 2026-08-13), and all shipping branches  
**Severity (my assessment):** Critical — a compromised content process can open new windows/tabs with a spoofed system principal as the triggering principal, enabling privileged URI loads. The same systemic bug class affects 13 additional handlers.  
**CVSS 3.1:** AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N — **9.3 (Critical)**  
**Precondition:** a compromised content process (renderer RCE). No web-content JS path is claimed.

---

## Summary

`ContentParent::ValidatePrincipal` is the intended mechanism for rejecting spoofed `nsIPrincipal*` values from content processes (including the system principal, which content should never be able to claim). However, across all 13 call sites where `ValidatePrincipal` fails, the code calls `LogAndAssertFailedPrincipalValidationInfo` — which only logs telemetry and fires a `MOZ_ASSERT(false)` that is **compiled out on release builds** — and then **continues execution with the spoofed principal**. None of the 13 call sites return `IPC_FAIL`.

Separately, `RecvCreateWindowInDifferentProcess` accepts `nsIPrincipal* aTriggeringPrincipal` with **no `ValidatePrincipal` call at all** and passes it to `CommonCreateWindow` with `aLoadUri = true`, causing the parent process to load an attacker-controlled URI with the spoofed principal as the triggering principal.

---

## The log-and-continue pattern

```cpp
// ContentParent.cpp:1270-1313
void ContentParent::LogAndAssertFailedPrincipalValidationInfo(
    nsIPrincipal* aPrincipal, const char* aMethod) {
  // ... telemetry, logging ...
#ifdef DEBUG
  MOZ_ASSERT(false, "Receiving unexpected Principal");  // STRIPPED ON RELEASE
#endif
}
```

Every call site follows this pattern — ValidatePrincipal fails, log, continue:

```cpp
if (!ValidatePrincipal(aPrincipal)) {
    LogAndAssertFailedPrincipalValidationInfo(aPrincipal, __func__);
}
// NO return IPC_FAIL — execution continues with spoofed principal
```

---

## All 13 log-and-continue call sites

| Line | Handler | Impact of spoofed principal |
|------|---------|---------------------------|
| **5401** | **`RecvCreateWindow`** | **Spoofed triggering principal passed to `CommonCreateWindow` — window creation with attacker's principal** |
| 4128 | `RecvConstructPopupBrowser` | Spoofed initial principal for popup browser construction |
| 3157 | `RecvSetClipboardDataOnClipboard` | Clipboard write with spoofed data principal |
| 3356 | `RecvGetClipboardDataSnapshot` | Clipboard read with spoofed requesting principal |
| 5709 | `RecvNotifyPushObservers` | Push notification dispatch with spoofed principal |
| 5724 | `RecvNotifyPushObserversWithData` | Push notification dispatch with spoofed principal |
| 5741 | `RecvPushError` | Push error dispatch with spoofed principal |
| 5756 | `RecvNotifyPushSubscriptionModifiedObservers` | Push subscription modification with spoofed principal |
| 5846 | `RecvStoreAndBroadcastBlobURLRegistration` | Blob URL registered under spoofed principal (AllowSystem!) |
| 5868 | `RecvUnstoreAndBroadcastBlobURLUnregistration` | Blob URL unregistered with spoofed principal |
| 6320 | `RecvStartURLClassifier` | URL classification with spoofed principal |
| 6494 | `RecvAutomaticStorageAccessPermissionCanBeGranted` | Storage access check with spoofed principal |
| 6668 | `RecvStoreUserInteractionAsPermission` | User interaction stored for spoofed principal |

---

## CRITICAL: `RecvCreateWindowInDifferentProcess` — NO validation, loads URI

```cpp
// ContentParent.cpp:5513-5578
mozilla::ipc::IPCResult ContentParent::RecvCreateWindowInDifferentProcess(
    PBrowserParent* aThisTab, const MaybeDiscarded<BrowsingContext>& aParent,
    const uint32_t& aChromeFlags, const bool& aCalledFromJS,
    const bool& aIsTopLevelCreatedByWebContent, nsIURI* aURIToLoad,
    const nsACString& aFeatures, const UserActivation::Modifiers& aModifiers,
    const nsAString& aName, nsIPrincipal* aTriggeringPrincipal,  // ← NO VALIDATION
    nsIContentSecurityPolicy* aCsp, nsIReferrerInfo* aReferrerInfo,
    const OriginAttributes& aOriginAttributes, bool aUserActivation,
    bool aTextDirectiveUserActivation) {
  // ...
  // NO ValidatePrincipal call at all!
  // ...
  mozilla::ipc::IPCResult ipcResult = CommonCreateWindow(
      aThisTab, *parent, /* aSetOpener = */ false, aChromeFlags, aCalledFromJS,
      /* aForPrinting = */ false, /* aForWindowDotPrint = */ false,
      aIsTopLevelCreatedByWebContent,
      aURIToLoad, aFeatures, aModifiers,
      /* aNextRemoteBrowser = */ nullptr, aName, rv, newRemoteTab, &windowIsNew,
      openLocation, aTriggeringPrincipal, aReferrerInfo,
      /* aLoadUri = */ true,   // ← URI IS LOADED with spoofed principal
      aCsp, aOriginAttributes, aUserActivation, aTextDirectiveUserActivation);
}
```

Compare with `RecvCreateWindow` which at least has the (broken) log-and-continue check and passes `aLoadUri = false`.

---

## Attack chain: privileged URI load via spoofed system principal

### Flow through CommonCreateWindow

`CommonCreateWindow` uses `aTriggeringPrincipal` in two critical paths:

**Path A: OPEN_NEWTAB (line 5263-5312)**
```cpp
params->SetTriggeringPrincipal(aTriggeringPrincipal);  // line 5273
if (aLoadURI) {
    browserDOMWin->OpenURIInFrame(aURIToLoad, params, ...);  // line 5279
}
```

This reaches `BrowserDOMWindow.sys.mjs` → `#openURIInNewTab`:
```javascript
// BrowserDOMWindow.sys.mjs:108-120
let tab = win.gBrowser.addTab(aURI.spec, {
    triggeringPrincipal: aTriggeringPrincipal,  // ← SPOOFED SYSTEM PRINCIPAL
    // ...
});
```

**Path B: OPEN_NEWWINDOW (line 5364-5380)**
```cpp
if (aURIToLoad && aLoadURI) {
    newBrowserDOMWin->OpenURI(
        aURIToLoad, openInfo, OPEN_CURRENTWINDOW, OPEN_NEW,
        aTriggeringPrincipal,  // ← SPOOFED SYSTEM PRINCIPAL
        aCsp, ...);
}
```

This reaches `BrowserDOMWindow.sys.mjs` → `getContentWindowOrOpenURI`:
```javascript
// BrowserDOMWindow.sys.mjs:347-352 (OPEN_CURRENTWINDOW default case)
this.win.gBrowser.fixupAndLoadURIString(aURI.spec, {
    triggeringPrincipal: aTriggeringPrincipal,  // ← SPOOFED SYSTEM PRINCIPAL
    // ...
});
```

### What the system principal enables

With the system principal as `triggeringPrincipal`, `nsContentUtils::CheckLoadURIWithPrincipal` allows loading URIs that content principals cannot access. The attacker supplies both the URI and the principal:

1. **chrome:// URIs** — load browser chrome XUL/JS. The `BrowserDOMWindow` chrome:// check (line 195) only fires when `isExternal` is true; in this flow, `aFlags = OPEN_NEW (0x0)`, so `isExternal = false`.
2. **about: URIs** with restricted access — privileged about pages
3. **resource:// URIs** — internal resources

### Concrete attack

1. Compromised content process sends `RecvCreateWindowInDifferentProcess` with:
   - `aTriggeringPrincipal = system principal` (deserializable via `ParamTraits<nsIPrincipal*>::Read` — no restriction)
   - `aURIToLoad = about:config` (or other privileged URI)
2. Parent process — **no ValidatePrincipal** — calls `CommonCreateWindow` with `aLoadUri = true`
3. Parent loads `about:config` in a new tab with the system principal as triggering principal
4. Security checks pass because system principal is unrestricted

---

## Comparison with RecvCreateWindow

| Aspect | RecvCreateWindow | RecvCreateWindowInDifferentProcess |
|--------|-----------------|-----------------------------------|
| ValidatePrincipal called | Yes (line 5400) | **NO** |
| return IPC_FAIL on failure | **NO** — log-and-continue | N/A (no check exists) |
| aLoadUri | **false** — URI not loaded | **true** — URI IS loaded |
| Attack severity | High | **Critical** |

---

## Historical context: CVE-2019-11708

This finding is in the same class as CVE-2019-11708 (the Firefox sandbox escape used in the Coinbase attack), where a compromised content process used `Prompt:Open` to open a new tab/window with attacker-controlled parameters, achieving privileged code execution. The IPC mechanism differs, but the primitive is identical: content process controls the principal and URI for a parent-process window open operation.

---

## The file:// scheme check is ineffective

`RecvCreateWindowInDifferentProcess` has one URI check (line 5536-5557):
```cpp
if (aURIToLoad && aURIToLoad->SchemeIs("file") &&
    GetRemoteType() != FILE_REMOTE_TYPE &&
    Preferences::GetBool("browser.tabs.remote.enforceRemoteTypeRestrictions", false))
```

This only blocks `file:` scheme, only from non-file remote types, and only when `enforceRemoteTypeRestrictions` is enabled (defaults to **false**). It does not check chrome://, about://, resource://, or any other privileged scheme.

---

## Suggested fix

### Immediate: add ValidatePrincipal + IPC_FAIL to RecvCreateWindowInDifferentProcess

```cpp
mozilla::ipc::IPCResult ContentParent::RecvCreateWindowInDifferentProcess(
    ..., nsIPrincipal* aTriggeringPrincipal, ...) {
  if (!aTriggeringPrincipal) {
    return IPC_FAIL(this, "No triggering principal");
  }
  if (!ValidatePrincipal(aTriggeringPrincipal)) {
    return IPC_FAIL(this, "Invalid triggering principal");
  }
  // ...existing code...
}
```

### Systemic: fix all 13 log-and-continue sites

Every `LogAndAssertFailedPrincipalValidationInfo` call should be followed by `return IPC_FAIL`:

```cpp
if (!ValidatePrincipal(aPrincipal)) {
    LogAndAssertFailedPrincipalValidationInfo(aPrincipal, __func__);
    return IPC_FAIL(this, "Invalid principal");  // ← ADD THIS
}
```

Or better, change `LogAndAssertFailedPrincipalValidationInfo` to return `IPC_FAIL` directly, making the correct pattern impossible to misuse:

```cpp
mozilla::ipc::IPCResult ContentParent::ValidateAndFail(
    nsIPrincipal* aPrincipal, const char* aMethod) {
  LogAndAssertFailedPrincipalValidationInfo(aPrincipal, aMethod);
  return IPC_FAIL(this, "Invalid principal from content");
}
```

### Also: add URI scheme allowlist to CommonCreateWindow

```cpp
if (aURIToLoad && aLoadURI) {
  if (!aURIToLoad->SchemeIs("http") && !aURIToLoad->SchemeIs("https") &&
      !aURIToLoad->SchemeIs("about") && !aURIToLoad->SchemeIs("data")) {
    return IPC_FAIL(this, "Disallowed URI scheme for window open");
  }
}
```

---

## Additional handlers with NO ValidatePrincipal at all

Beyond `RecvCreateWindowInDifferentProcess`, these IPC handlers accept `nsIPrincipal*` from content with zero validation (not even log-and-continue):

| Line | Handler | Principal parameter(s) | Impact |
|------|---------|----------------------|--------|
| **5513** | **`RecvCreateWindowInDifferentProcess`** | `aTriggeringPrincipal` | **Loads URI with spoofed principal (see above)** |
| **4609** | **`RecvLoadURIExternal`** | `aTriggeringPrincipal`, `aRedirectPrincipal` | **External protocol handler launch with spoofed principal — can trigger OS-level app launch** |
| **5101** | **`AllocPContentPermissionRequestParent`** | `aPrincipal`, `aTopLevelPrincipal` | **Permission request forged for arbitrary origin — geolocation, camera, etc. prompt shows wrong origin** |
| 6501 | `RecvStorageAccessPermissionGrantedForOrigin` | `aTrackingPrincipal` | Grants storage access for arbitrary tracking origin (Finding 16) |
| 6541 | `RecvCompleteAllowAccessFor` | `aTrackingPrincipal` | Completes storage access grant for arbitrary tracking origin (Finding 16) |
| 6569 | `RecvSetAllowStorageAccessRequestFlag` | `aEmbeddedPrincipal` | Writes ALLOW permission for arbitrary origin pair |
| 6615 | `RecvTestAllowStorageAccessRequestFlag` | `aEmbeddingPrincipal` | Probes + removes storage access permissions for arbitrary principal |
| 6674 | `RecvTestCookiePermissionDecided` | `aPrincipal` | Probes cookie permission state for arbitrary principal |
| 6696 | `RecvTestStorageAccessPermission` | `aEmbeddingPrincipal` | Probes storage access permissions for arbitrary principal |
| 7458 | `RecvBlobURLDataRequest` | `aTriggeringPrincipal`, `aLoadingPrincipal` | Retrieves blob URL data using spoofed principals — cross-origin data theft |

Total: **10 handlers with NO validation + 13 handlers with ineffective log-and-continue = 23 handlers** where a compromised content process can use a spoofed principal (including the system principal).

### RecvLoadURIExternal (line 4609) — external app launch with frame access bypass

```cpp
mozilla::ipc::IPCResult ContentParent::RecvLoadURIExternal(
    nsIURI* uri, nsIPrincipal* aTriggeringPrincipal,     // ← NOT VALIDATED
    nsIPrincipal* aRedirectPrincipal,                      // ← NOT VALIDATED
    const MaybeDiscarded<BrowsingContext>& aContext, ...) {
  // Only null-checks URI
  extProtService->LoadURI(uri, aTriggeringPrincipal, aRedirectPrincipal, bc,
                          aWasExternallyTriggered, ...);
}
```

**Critical detail**: In `nsExternalHelperAppService::LoadURI` (line 1088-1092), a spoofed **system principal** causes the frame access check to be **entirely skipped**:

```cpp
if (aBrowsingContext && aTriggeringPrincipal &&
    !BasePrincipal::Cast(aTriggeringPrincipal)->AddonPolicy() &&
    !aTriggeringPrincipal->IsSystemPrincipal()) {  // ← SYSTEM PRINCIPAL SKIPS THIS BLOCK
  // ... browsing context access validation (lines 1093-1146) ...
  // This entire block is skipped when system principal is spoofed
}
```

With system principal spoofed, the external protocol handler launches with NO browsing context ownership check. For schemes where the user previously checked "always open with this application" (mailto:, zoommtg:, slack:, ms-word:, etc.), the external app launches **without any prompt** with an attacker-controlled URI.

### AllocPContentPermissionRequestParent (line 5101) — permission prompt spoofing

```cpp
PContentPermissionRequestParent*
ContentParent::AllocPContentPermissionRequestParent(
    const nsTArray<PermissionRequest>& aRequests,
    nsIPrincipal* aPrincipal,          // ← NOT VALIDATED
    nsIPrincipal* aTopLevelPrincipal,  // ← NOT VALIDATED
    const bool& aIsHandlingUserInput, ...) {
  // Passes unvalidated principals to permission system
  return nsContentPermissionUtils::CreateContentPermissionRequestParent(
      aRequests, tp->GetOwnerElement(), aPrincipal, topPrincipal, ...);
}
```

A compromised content process can trigger permission prompts (geolocation, camera, microphone, notifications) that display a trusted origin (e.g., "google.com wants to use your camera") while the actual requesting origin is the attacker's. If the user grants permission, it's stored for the spoofed origin.

### RecvBlobURLDataRequest (line 7458) — cross-origin blob theft

```cpp
mozilla::ipc::IPCResult ContentParent::RecvBlobURLDataRequest(
    const nsACString& aBlobURL,
    nsIPrincipal* aTriggeringPrincipal,  // ← NOT VALIDATED
    nsIPrincipal* aLoadingPrincipal,     // ← NOT VALIDATED
    ...) {
  BlobURLProtocolHandler::GetDataEntry(
      aBlobURL, ..., aLoadingPrincipal, aTriggeringPrincipal, ...);
}
```

---

## Branch verification

All handlers verified on mozilla-central tip (2026-08-13):

- `RecvCreateWindowInDifferentProcess` (line 5513): confirmed NO ValidatePrincipal
- `RecvCreateWindow` (line 5400): confirmed ValidatePrincipal with NO IPC_FAIL
- `LogAndAssertFailedPrincipalValidationInfo` (line 1270): confirmed `#ifdef DEBUG` assert only
- All 13 log-and-continue sites: confirmed NO IPC_FAIL after LogAndAssert

---

## What I did not prove

- I did not runtime-confirm that loading a chrome:// or privileged about:// URI with a spoofed system triggering principal achieves code execution in the parent process. The claim is based on code analysis of the principal flow through CommonCreateWindow → BrowserDOMWindow → gBrowser.addTab/fixupAndLoadURIString.
- There may be additional downstream security checks in `DocumentLoadListener` or `nsDocShell::InternalLoad` that would catch some URI/principal combinations. The core vulnerability (missing/ineffective principal validation at the IPC boundary) exists regardless.
- I did not test whether `ParamTraits<nsIPrincipal*>::Read` successfully deserializes a system principal from a content process wire format. Based on code analysis, there is no process-based restriction in the deserialization path; `ValidatePrincipal` is the intended check.
