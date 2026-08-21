# `SessionStoreParent::RecvIncrementalSessionStoreUpdate` accepts any BrowsingContext with no ownership check; a compromised content process can poison session data for arbitrary tabs, with escalation to system principal code execution via about:sessionrestore

**Component:** Toolkit :: Session Restore
**Severity:** S2 (High), S1 with escalation chain
**Type:** defect
**Keywords:** sec-high, csectype-sandbox

## Summary

`SessionStoreParent::RecvIncrementalSessionStoreUpdate` (`toolkit/components/sessionstore/SessionStoreParent.cpp:197`) accepts a `MaybeDiscarded<BrowsingContext>` parameter from a content process and resolves it via the global `CanonicalBrowsingContext::Get(id)` lookup — with no check that the sending content process owns that BrowsingContext. A compromised content process can inject arbitrary FormData into the session store of any tab in any process.

The sibling handler `RecvResetSessionStore` (`:227`) has the identical pattern and allows deleting another tab's session store data.

**Precondition:** compromised content process (renderer RCE).

## Steps to Reproduce

A compromised content process sends:

```
PSessionStore::IncrementalSessionStoreUpdate(
    victimBCId,                    // any tab's BrowsingContext ID
    FormData{
        hasData: true,
        id: [{id: "field", value: "attacker-value"}],
        uri: "https://victim.com"
    },
    None,                          // no scroll position
    0                              // epoch 0 = fresh tabs
)
```

### Expected behavior

The handler should reject updates targeting BrowsingContexts not owned by the sending content process.

### Actual behavior

The handler resolves the BrowsingContext via global lookup and stores attacker-controlled FormData for the victim tab.

## Compare with safe sibling

`RecvSessionStoreUpdate` (`:175`) correctly uses `mBrowsingContext` (the actor's own BC):

```cpp
mozilla::ipc::IPCResult SessionStoreParent::RecvSessionStoreUpdate(...) {
  if (!mBrowsingContext) { return IPC_OK(); }
  DoSessionStoreUpdate(mBrowsingContext, ...);  // actor's own BC — CORRECT
}
```

## FormData struct is fully attacker-controlled

```
struct FormData {
  bool hasData;
  FormEntry[] id;        // form entries keyed by element ID
  FormEntry[] xpath;     // form entries keyed by XPath
  nsString innerHTML;    // innerHTML for design-mode documents
  nsCString uri;         // URL — controls CanRestoreInto check
};
```

The `uri` field controls the restore-time URL check (`CanRestoreInto`). Attacker sets it to match victim tab's URL — check passes trivially.

## Epoch bypass

Fresh tabs have epoch 0. Attacker sends epoch 0. For restored tabs (epoch 1-5), spray all values.

## BrowsingContext ID enumeration

Parent-process BCs (about:config, about:preferences, about:sessionrestore) have sequential IDs with process prefix 0. Easily enumerable.

## Escalation: about:sessionrestore → system principal

1. Inject FormData targeting about:sessionrestore's BC: `{id: [{id: "sessionData", value: CRAFTED_JSON}]}`
2. CRAFTED_JSON contains tabs with `userTypedValue` set to privileged URI
3. `aboutSessionRestore.js:59` reads: `gStateObject = JSON.parse(sessionData.value)`
4. User clicks "Restore Session" → `SessionStore.setWindowState(top, stateString, true)`
5. `_restoreTabEntry` (`SessionStore.sys.mjs:7920`) loads `userTypedValue` with **system triggering principal**

## Suggested fix

Validate that the sending content process owns the target BrowsingContext:

```cpp
BrowserParent* senderBrowser = static_cast<BrowserParent*>(Manager());
ContentParent* senderContent = senderBrowser->Manager()->AsContentParent();
if (bc->GetContentParent() != senderContent) {
  return IPC_FAIL(this, "Content process does not own target BrowsingContext");
}
```

Or use `mBrowsingContext` like `RecvSessionStoreUpdate` does.

## Verified on

mozilla-central tip (142.0a1), 2026-08-13. Lines 197, 227 confirmed vulnerable.
