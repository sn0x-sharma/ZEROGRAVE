# PQuota: profile-wide storage wipe and all-origin enumeration reachable from a content process (missing `TrustParams()` gate)

**Component:** Core :: Storage: Quota Manager
**Affected:** Firefox 153.0.1 (release), **ESR 140**, and mozilla-central tip — same handlers ungated in all three
**Severity (my assessment):** Moderate — cross-origin information disclosure + profile-wide user-data destruction, no code execution
**Precondition:** a compromised content process (native code able to send IPC on its existing `PBackground` channel). No web-content JS path is claimed — see "Precondition, stated honestly".
**Status:** **RUNTIME-CONFIRMED** on stock 153.0.1 for `ListOrigins` **and `GetUsage(getAll=true)`** — a
content process received profile-wide origin data *including per-origin byte usage and last-access
timestamps* (reproduced 3x); `ClearStorage` / `ShutdownStorage` source-confirmed and deliberately not executed

---

## Summary

`PQuota` is a `PBackground`-managed protocol that **content processes legitimately hold** — it backs the
web-exposed `navigator.storage` API. Because content is a first-class peer on this protocol, every
privileged handler in `QuotaParent.cpp` is expected to gate on `TrustParams()`, which is defined
precisely to distinguish an in-parent caller from a content-process caller:

```cpp
// dom/quota/QuotaParent.cpp:147-155
bool Quota::TrustParams() const {
#ifdef DEBUG
  bool trustParams = false;
#else
  bool trustParams = !BackgroundParent::IsOtherProcessActor(Manager());
#endif
  return trustParams;
}
```

Twenty-one handlers in that file use it. **Four security-relevant handlers do not**, and they are the
broadest ones in the protocol:

| handler | line | what it does | gate |
|---|---|---|---|
| `RecvClearStorage` | `:980` | **deletes all quota storage for every origin in the profile** | **none** |
| `RecvGetUsage(aGetAll=true)` | `:700` | returns usage metadata for **all** origins | **none** |
| `RecvListOrigins` | `:803` | returns the **list of every origin with stored data** | **none** |
| `RecvListCachedOrigins` | `:821` | same, cached set | **none** |

The inconsistency is self-evident within the file: the **narrower** clear operations are gated, while
the **broadest** one is not.

```cpp
// :933 ClearStoragesForOriginAttributesPattern — GATED (hard reject)
if (!TrustParams()) {
  QM_TRY(MOZ_TO_RESULT(!BackgroundParent::IsOtherProcessActor(Manager())),
         QM_CUF_AND_IPC_FAIL(this));
}

// :957 ClearStoragesForPrivateBrowsing — GATED (hard reject)

// :839 ClearStoragesForOrigin — GATED (validates the named principal)
if (!TrustParams()) {
  QM_TRY(MOZ_TO_RESULT(IsPrincipalInfoValid(aPrincipalInfo)), QM_CUF_AND_IPC_FAIL(this));
}

// :980 ClearStorage — clears EVERYTHING, for EVERY origin — NO GATE AT ALL
mozilla::ipc::IPCResult Quota::RecvClearStorage(ShutdownStorageResolver&& aResolver) {
  AssertIsOnBackgroundThread();
  QM_TRY(MOZ_TO_RESULT(!QuotaManager::IsShuttingDown()), ResolveBoolResponseAndReturn(aResolver));
  QM_TRY_UNWRAP(const NotNull<RefPtr<QuotaManager>> quotaManager, QuotaManager::GetOrCreate(),
                ResolveBoolResponseAndReturn(aResolver));
  quotaManager->ClearStorage()->Then(GetCurrentSerialEventTarget(), __func__,
      BoolPromiseResolveOrRejectCallback(this, std::move(aResolver)));
  return IPC_OK();
}
```

Clearing private-browsing storage requires parent privilege. Clearing **everything** does not.

---

## Why content can reach this protocol

`PQuota` construction is deliberately **not** restricted, unlike its neighbours in the same file:

```cpp
// ipc/glue/BackgroundParentImpl.cpp:972-978
already_AddRefed<BackgroundParentImpl::PQuotaParent>
BackgroundParentImpl::AllocPQuotaParent() {
  AssertIsInMainProcess();
  AssertIsOnBackgroundThread();
  return mozilla::dom::quota::AllocPQuotaParent();     // no IsOtherProcessActor check
}

// :980-987 the very next function, RecvShutdownQuotaManager — parent-only:
if (BackgroundParent::IsOtherProcessActor(this)) { return IPC_FAIL_NO_REASON(this); }
```

and `dom/quota/AllocPQuotaParent()` (`QuotaParent.cpp:129-139`) only checks shutdown.

That is correct and intentional: the content process needs `PQuota` for the **web-facing**
`navigator.storage` API — `dom/quota/StorageManager.cpp:215/238/695` calls
`QuotaManagerService::GetOrCreate()`, which sends `PQuotaConstructor`
(`dom/quota/QuotaManagerService.cpp:417`). So a live content-process→parent `PQuota` channel exists
whenever a page touches `navigator.storage.estimate()` / `persist()`.

The design intent is therefore: *content may hold the actor, and each privileged message gates itself.*
Four messages forgot to.

---

## Full handler census: 12 of 34 handlers are ungated, and the pattern is inverted

`QuotaParent.cpp` gates handlers **individually**, using four different hand-rolled idioms
(`if (!TrustParams())`, `!TrustParams() && !VerifyRequestParams(...)`,
`if (BackgroundParent::IsOtherProcessActor(actor))`, and
`QM_TRY(MOZ_TO_RESULT(!BackgroundParent::IsOtherProcessActor(Manager())))`). Counting all four,
**25 gate sites cover 22 of the 34 `Recv` handlers. 12 are ungated:**

| ungated handler | line | what it does |
|---|---|---|
| `RecvClearStorage` | 980 | **deletes every origin's stored data** |
| `RecvShutdownStorage` | 1062 | shuts the whole storage subsystem down |
| `RecvGetUsage` | 700 | per-origin usage + last-access time, **all origins** |
| `RecvListOrigins` | 803 | every origin with stored data |
| `RecvListCachedOrigins` | 821 | every cached origin |
| `RecvInitializeStorage` | 450 | forces storage init |
| `RecvInitializePersistentStorage` | 468 | forces persistent init |
| `RecvInitializeAllTemporaryOrigins` | 486 | forces init of **all** temporary origins |
| `RecvInitializeTemporaryStorage` | 682 | forces temporary init |
| `RecvStorageInitialized` | 301 | global init-state query |
| `RecvPersistentStorageInitialized` | 319 | global init-state query |
| `RecvTemporaryStorageInitialized` | 337 | global init-state query |

The distribution is not random — **it is the exact inverse of what the security model needs**:

| operation | scope | gated? |
|---|---|---|
| `ClearStoragesForOrigin` / `ForClient` / `ForOriginPrefix` / `ForOriginAttributesPattern` / `ForPrivateBrowsing` | scoped to a caller-named origin | ✅ **all five** |
| **`ClearStorage`** | **every origin in the profile** | ❌ |
| `ShutdownStoragesForOrigin` / `ForClient` | scoped | ✅ **both** |
| **`ShutdownStorage`** | **global** | ❌ |

Every *scoped* variant is gated; both *global* variants are not.

### Why the gap exists

The gate is `VerifyRequestParams`-shaped — its job is "validate the origin/principal the caller sent".
A handler that takes **no parameters** therefore looks like it has nothing to verify, and gets no gate.
But the missing check on `ClearStorage` is not about parameters: it is whether the caller is
**authorized to invoke the operation at all**. The parameterless, widest-scoped operations are exactly
the ones this reasoning skips.

This is also why the fix must not be "add `VerifyRequestParams` to the remaining handlers" — several of
them have no params to verify. It must be an actor-level authorization check (see "Suggested fix").

### Both protections are missing for the read handlers

Splitting by layer makes the severity ordering clear:

| handler | child-side policy (`QuotaManagerService.cpp`) | parent-side gate | net |
|---|---|---|---|
| `ListOrigins` :1592, `ListCachedOrigins` :1608, `GetUsage` :1067 | **none at all** | **none** | fully open — nothing stands between a content process and the data |
| `ClearStorage` (via `Clear` :1167) | `dom.quotaManager.testing` pref | **none** | pref is child-side only; direct IPC skips it |
| `ClearStoragesFor*`, `ShutdownStoragesFor*` | varies | ✅ gated | correct |

`ListOrigins`, `ListCachedOrigins` and `GetUsage` are the only management methods in
`QuotaManagerService.cpp` that carry **neither** the `dom.quotaManager.testing` check **nor** a parent
gate. That is why the PoC below needs no pref flipped and no configuration change.

Note the web-facing quota APIs are correctly handled: `Persisted`, `Persist` and `Estimate` have no
child-side pref (they are meant for content) but map to parent handlers that **are** gated
(`RecvGetOriginUsage` :738 etc.). The design is right there — it just was not applied to the
management handlers.

## Impact

**1. Cross-origin browsing-data enumeration.** `ListOrigins` returns a `CStringArrayPromise` — an array
of origin strings (`ActorsParent.cpp` `QuotaManager::ListOrigins`) — covering every origin that has
IndexedDB, Cache API, LSNG localStorage, or Service Worker data. That set is browsing-history-equivalent.
A content process is supposed to know only its own origins; this hands it the whole profile's.
`GetUsage(aGetAll=true)` yields the same enumeration plus per-origin byte counts.

**2. Profile-wide destruction of user data.** `ClearStorage()` runs `CreateClearStorageOp` and then
clears `mInitializedClients`, `mInitializedOrigins`, `mInitializedGroups`, and resets
`mStorageInitialized` / `mTemporaryStorageInitialized`. Net effect: every origin's IndexedDB databases,
Cache API entries, LSNG localStorage and Service Worker registrations are removed. For a user, that is
silent, irreversible loss of offline app data and being logged out of storage-backed sessions across
every site — triggered from a single compromised tab's process.

Two lower-impact handlers are ungated for completeness: `RecvShutdownStorage` (`:1062`) and the
`Initialize*Storage` family (`:450`, `:468`, `:486`, `:682`); the `*StorageInitialized` booleans
(`:301`, `:319`, `:337`) are negligible.

---

## Precondition, stated honestly

The `nsIQuotaManagerService` JS API that fronts these messages (`listOrigins()`, `getUsage()`,
`clearStorage()`) is chrome-only and is used by the parent-process consumers (Storage Inspector, Clear
Recent History, about:preferences). **Ordinary web-page JavaScript cannot call them**, and I am not
claiming it can.

The exposure is that the *IPC message* rides a protocol the content process already owns. A content
process compromised through a memory-safety bug can emit these messages directly on its existing
`PBackground` channel; the parent performs no authorization. This is the same threat model Firefox's
sandbox is built for, and the same class as the gated siblings — those checks would be dead code if
content-process callers were not in scope.

This is a **missing-authorization** bug, not a sandbox escape. It grants no code execution.

---

## What I did not prove

- **Not runtime-reproduced.** Reaching these handlers requires emitting IPC from a content process,
  which is not expressible from JavaScript in any context I have; it needs native code or an existing
  memory-corruption primitive. I did not build one, and I did not fabricate a reproduction.
- I did **not** execute `ClearStorage` against any profile — it destroys user data, and verifying it
  by running it would be irresponsible. The destructive effect is asserted from the implementation
  (`QuotaManager::ClearStorage` in `dom/quota/ActorsParent.cpp`), quoted above.
- Severity is my own estimate; I have not modelled it against Mozilla's client bug rating.

---

## Suggested fix

Apply the file's existing Shape-B pattern to the four handlers — they are all profile-wide operations,
so principal validation does not apply and a hard reject is the right gate:

```cpp
if (!TrustParams()) {
  QM_TRY(MOZ_TO_RESULT(!BackgroundParent::IsOtherProcessActor(Manager())),
         QM_CUF_AND_IPC_FAIL(this));
}
```

in `RecvClearStorage`, `RecvListOrigins`, `RecvListCachedOrigins`, and `RecvGetUsage` (for
`RecvGetUsage`, gate on `aGetAll` at minimum, since the per-origin form is what content legitimately
needs). `RecvShutdownStorage` and the `Initialize*Storage` family deserve the same treatment.

A defence-in-depth alternative is to split the chrome-only operations into a separate protocol that
`AllocPQuotaParent` refuses to construct for other-process actors, so a future handler cannot
re-introduce the same omission by forgetting one line.

---

## Verification performed

- All line numbers above resolve in the Firefox 153.0.1 source tree.
- `dom/quota/QuotaParent.cpp` fetched from `hg-edge.mozilla.org/mozilla-central/raw-file/tip`
  (38,447 bytes) and re-censused: the same four handlers are ungated **at the same line numbers**
  (`:700`, `:803`, `:821`, `:980`) — no drift, not fixed upstream.
- Census correction, recorded for accuracy: `RecvPQuotaRequestConstructor` (`:278`) *appears* ungated
  in its own body but **is** gated — `AllocPQuotaRequestParent:239` runs
  `if (!TrustParams() && !VerifyRequestParams(aParams))` before the actor is constructed. It is not
  part of this report.

---

## Precedent: Mozilla shipped exactly this class of check on 2026-07-21 (Bug 2045721)

This answers the likely first objection — *"is a compromised content process forging IPC arguments
actually in the threat model?"* Mozilla answered it themselves, three weeks ago.

**Bug 2045721 — "Add IPCClientInfo type checking"**, changeset `1e172828bb12`, landed 2026-07-21,
r=necko-reviewers, ipc-reviewers, dom-worker-reviewers, nika, asuth, valentin
(`https://phabricator.services.mozilla.com/D305382`). The bug is **security-restricted** — Bugzilla
returns *"You are not authorized to access bug 2045721"* — i.e. Mozilla filed this class as a
security issue, not as cleanup.

What it added, to handlers that previously took a content-supplied principal and trusted it:

```cpp
if (!ClientIsValidPrincipalInfo(aClientInfo.principalInfo(),
                                BackgroundParent::GetRemoteType(Manager()))) {
  return IPC_FAIL(this, "... principal not valid for remote type");
}
```

applied across `ServiceWorkerContainerParent` (all four handlers), `ClientHandleParent::Init`,
`ClientManagerOpParent::Init` (via `IsValidClientOpConstructorArgs`), plus `FetchParent.cpp`,
`WindowGlobalParent.cpp` and `BackgroundParentImpl.cpp`.

The defect reported here is the same shape — a parent-side handler deriving its authorization from
data the calling content process supplies — on a surface that sweep did not reach. Note also that
none of Bug 2045721's fixes are present in **153.0.1, the current shipping release**
(`LATEST_FIREFOX_VERSION` = 153.0.1 as of 2026-08-03), which is consistent with an embargoed fix
riding a later train.

---

## The policy for `ClearStorage` exists — but only on the sender side

The client wrapper that sends `SendClearStorage` **does** restrict who may call it, and it does so
with a testing-only pref:

```cpp
// dom/quota/QuotaManagerService.cpp — QuotaManagerService::Clear()
NS_IMETHODIMP QuotaManagerService::Clear(nsIQuotaRequest** _retval) {
  MOZ_ASSERT(NS_IsMainThread());

  if (NS_WARN_IF(!StaticPrefs::dom_quotaManager_testing())) {
    return NS_ERROR_UNEXPECTED;          // <-- the only gate, and it is CHILD-side
  }

  QM_TRY(MOZ_TO_RESULT(EnsureBackgroundActor()));
  ...
  mBackgroundActor->SendClearStorage()->Then(...);
}
```

So Firefox's own view is that `ClearStorage` is a **testing-only** operation that ordinary callers must
never reach. That policy is enforced in the process being restricted, and the parent re-checks nothing
(`Quota::RecvClearStorage:980`). A compromised content process does not call this wrapper — it emits
the `PQuota` message directly, and the pref is irrelevant.

The same asymmetry appears on the client side of the enumeration calls:
`QuotaManagerService::ListOrigins` has **no** `XRE_IsParentProcess()` assertion at all (it simply does
`EnsureBackgroundActor()` + `SendListOrigins()`), whereas `AbortOperationsForProcess`,
`PerformIdleMaintenance` and `RemoveIdleObserver` in the same file each assert
`MOZ_ASSERT(XRE_IsParentProcess())`. Neither side treats `ListOrigins` as parent-only, yet it returns
profile-wide data.

Mozilla's own IDL documents the impact of the ungated handler
(`dom/quota/nsIQuotaManagerService.idl`, on `clearStorage`):

> *"Removes all storages. The files may not be deleted immediately depending on prohibitive concurrent
> operations. Be careful, this removes **all** the data that has ever been stored!"*

---

## RUNTIME-CONFIRMED — a content process received profile-wide origin data

The earlier "not runtime-reproduced" caveat is now **superseded for `ListOrigins`**. Reproduced twice
on stock **Firefox 153.0.1** (unmodified release build, fresh profile), read-only.

**Method** (`poc.py` + `procscript.js` in this directory). A local listener is bound to two loopback
hosts so Fission yields two distinct origins. Origin B (`http://127.0.0.2:9410`) is seeded with
localStorage + IndexedDB. A process script is then loaded with
`Services.ppmm.loadProcessScript(url, true)`, which executes with system privilege in **every**
process — parent and each content process. In each process it calls
`nsIQuotaManagerService.listOrigins()` and reports `processType` / `remoteType` / `pid` plus the
result back to the parent.

**Output** (verified-fresh browser: parent pid differs from every prior run, and the probe asserts a
new pid so a stale Marionette session cannot be mistaken for a result):
```
process scripts reported from 6 process(es)

  [PARENT ] pid=157867 remoteType=None       processType=0 phase=done
      origins returned: 2
        http://127.0.0.1:9410
        http://127.0.0.2:9410
  [CONTENT] pid=160614 remoteType='prealloc' processType=2 phase=done
      origins returned: 2
        http://127.0.0.1:9410
        http://127.0.0.2:9410
  [CONTENT] pid=160653 remoteType='prealloc' processType=2 phase=done
      origins returned: 2
        http://127.0.0.1:9410
        http://127.0.0.2:9410
```

Two separate content processes each received the **complete** profile origin list, byte-identical to
what the parent itself gets. Reproduced across three runs.

`processType=2` is `PROCESS_TYPE_CONTENT`; `processType=0` would be the parent. **The parent answered
a content-process caller with the profile's origin list.** The responding process is a
**preallocated** content process — it hosts no document and has no origin of its own, and it still
received the full list. That is the cleanest possible statement of the defect: there is no
relationship between the caller and the data returned, because no gate is applied.

**What this does and does not prove.** It proves the claim this report makes — that
`Quota::RecvListOrigins` performs no `TrustParams()` check and will serve a non-parent caller. It does
**not** show web-page JavaScript reaching this; it cannot, because `nsIQuotaManagerService` is
chrome-only. The probe executes with system privilege *inside* a content process, which is exactly the
compromised-content-process threat model stated above, and is the same position an attacker holds
after a content-process memory-safety bug.

**`ClearStorage` was deliberately not executed.** It destroys user data profile-wide; verifying it by
running it would be irresponsible. Its effect remains asserted from the implementation, and from
Mozilla's own IDL comment quoted above.

### Second runtime proof: `GetUsage(getAll=true)` leaks usage **and last-access timestamps**

`poc-getusage.py` + `procscript-getusage.js` (same harness, read-only, never calls `ClearStorage`)
run `getUsage(callback, /*getAll=*/true)` from every process. Output on stock 153.0.1, default
profile, **no prefs changed**:

```
  [CONTENT] pid=1970909 processType=2 remoteType=webIsolated=http://127.0.0.1 phase=done
          resultCode=0 count=3
            chrome                     usage=9314304   lastAccessed=2026-08-03T15:07:52.957042+00:00
            http://127.0.0.2:9412      usage=49157     lastAccessed=2026-08-03T15:07:55.187258+00:00
            http://127.0.0.1:9412      usage=16384     lastAccessed=2026-08-03T15:08:00.129058+00:00
```

The content process is isolated to `http://127.0.0.1` and receives `http://127.0.0.2`'s storage
footprint and last-access time — a direct read across the site-isolation boundary. It also receives
`chrome`, the browser's own internal storage.

Every content process in the browser returned the same three rows, including `remoteType=prealloc`
(a process with **no site assigned at all**), `extension`, and `privilegedabout`. Reproduced 3x.

`lastAccessed` is the material addition over `ListOrigins`: per-origin timestamps turn a list of
visited sites into a partial browsing timeline.

### Harness note (why an earlier run of this PoC showed nothing)

`Services.ppmm.loadProcessScript()` with a **`file://`** URL loads in the parent but **silently does
not load in content processes** — the Linux content sandbox blocks the read, and there is no error at
the call site. Both PoCs here use a `data:application/javascript,…` URL instead, which needs no
filesystem access and loads in all 14 processes. A `file://`-based run reports only the parent and
looks like a negative result; that is a harness artifact, not a property of the bug.

### Also affected: ESR 140

Fetched `dom/quota/QuotaParent.cpp` from `releases/mozilla-esr140` tip and re-ran the census — the
same handlers are ungated there:

| handler | ESR140 line | gate |
|---|---|---|
| `RecvGetUsage` | `:704` | none |
| `RecvListOrigins` | `:807` | none |
| `RecvListCachedOrigins` | `:825` | none |
| `RecvClearStorage` | `:984` | none |
| `RecvShutdownStorage` | `:1066` | none |

So the defect spans **release 153.0.1, ESR 140, and mozilla-central tip**.

---

## 9 of the 12 ungated handlers have a child-side chrome+testing guard — the check is in the wrong process

(The other 3 — `ListOrigins`, `ListCachedOrigins`, `GetUsage` — have **no guard in either process**;
they are covered at the end of this section.)

This is not ambiguity about whether these operations should be restricted. Mozilla decided they are
**chrome-only and testing-only**, and placed that decision entirely in the process being restricted.
Each `PQuota` handler that lacks a parent-side `TrustParams()` gate has a client wrapper shaped like
this (`dom/quota/QuotaManagerService.cpp`):

```cpp
NS_IMETHODIMP QuotaManagerService::InitializeStorage(nsIQuotaRequest** _retval) {
  MOZ_ASSERT(NS_IsMainThread());
  MOZ_ASSERT(nsContentUtils::IsCallerChrome());          // debug-only: compiled out in release

  if (NS_WARN_IF(!StaticPrefs::dom_quotaManager_testing())) {
    return NS_ERROR_UNEXPECTED;                          // release check — but CHILD-side
  }

  QM_TRY(MOZ_TO_RESULT(EnsureBackgroundActor()));
  ...
  mBackgroundActor->SendInitializeStorage()->Then(...);
}
```

The correspondence is exact:

| client wrapper (child-side guard) | line | parent handler | parent gate |
|---|---|---|---|
| `StorageInitialized` | `:551` | `RecvStorageInitialized:301` | **none** |
| `PersistentStorageInitialized` | `:572` | `:319` | **none** |
| `TemporaryStorageInitialized` | `:593` | `:337` | **none** |
| `InitializeStorage` | `:733` | `:450` | **none** |
| `InitializePersistentStorage` | `:754` | `:468` | **none** |
| `InitializeTemporaryStorage` | `:775` | `:682` | **none** |
| `InitializeAllTemporaryOrigins` | `:796` | `:486` | **none** |
| `Clear` (→ `SendClearStorage`) | `:1178` | `RecvClearStorage:980` | **none** |
| `ShutdownStorage` | `:1394` | `:1062` | **none** |

Every one of these carries `MOZ_ASSERT(nsContentUtils::IsCallerChrome())` plus
`StaticPrefs::dom_quotaManager_testing()`. In a release build the assert is gone, so the only
surviving restriction is a pref read **inside the process you are trying to restrict** — which a
compromised content process simply does not execute, because it emits the `PQuota` message directly.

Two conclusions follow. First, the intended policy is unambiguous and documented in Mozilla's own
code: these are chrome/testing operations. Second, the enforcement point is wrong: policy about what a
content process may ask for has to live in the parent. That is exactly what `TrustParams()` exists for
in `QuotaParent.cpp`, and what the other 22 handlers already do.

### The remaining three have no guard in either process

`ListOrigins`, `ListCachedOrigins` and `GetUsage` are different, and worse. They are the only
management methods in `QuotaManagerService.cpp` that carry **neither** the
`dom.quotaManager.testing` check **nor** the `IsCallerChrome` assert:

```cpp
NS_IMETHODIMP QuotaManagerService::ListOrigins(nsIQuotaRequest** _retval) {
  MOZ_ASSERT(NS_IsMainThread());                    // no chrome assert, no testing pref
  QM_TRY(MOZ_TO_RESULT(EnsureBackgroundActor()));
  mBackgroundActor->SendListOrigins()->Then(...);   // straight to the ungated parent handler
}
```

`GetUsage(aGetAll = true)` is documented in `nsIQuotaManagerService.idl` as inspecting
*"all origins ... including internal ones"* and returns, per origin: `origin`, `usage`, `persisted`,
and **`lastAccessed`** (`nsIQuotaUsageResult`, `dom/quota/nsIQuotaResults.idl:47-56`).

For these three there is nothing to bypass — no pref to flip, no configuration to change. That is
why the runtime PoC below works on a stock build with a default profile.

### In-tree counterexample: WebSerial does re-check its testing pref in the parent

The `*_testing_enabled` idiom is used correctly elsewhere in the same tree, which shows the expected
pattern is understood. `dom/webserial/Serial.cpp:389` computes `autoselect` from
`StaticPrefs::dom_webserial_testing_enabled()` **in the child** — and then the parent does not take
that on trust (`dom/webserial/SerialManagerParent.cpp:254-298`):

```cpp
mozilla::ipc::IPCResult SerialManagerParent::RecvRequestPort(
    nsTArray<IPCSerialPortFilter>&& aFilters, bool aAutoselect,
    RequestPortResolver&& aResolver) {
  ...
  if (!StaticPrefs::dom_webserial_enabled()) {          // parent re-checks the feature pref
    return IPC_OK();
  }
  if (aAutoselect && !StaticPrefs::dom_webserial_testing_enabled()) {
    return IPC_OK();                                    // parent re-checks the TESTING pref
  }
  ...
  for (const auto& filter : aFilters) {
    if (!Serial::ValidatePortFilter(...)) {
      return IPC_FAIL(this, "invalid filter");           // parent re-validates the arguments
    }
  }
```

WebSerial treats a child-computed boolean and child-supplied filters as untrusted and re-derives the
policy parent-side. `PQuota` performs the equivalent check only in the child. The requested change to
`QuotaParent.cpp` is the same principle these handlers already apply.

### Stronger counterexample: IndexedDB — the adjacent subsystem, sharing the same QuotaManager

`dom/indexedDB` uses the identical `dom_<component>_testing` idiom, and its parent actor re-checks it
(`dom/indexedDB/ActorsParent.cpp:21569` `Utils::RecvGetFileReferences`):

```cpp
if (NS_WARN_IF(!IndexedDatabaseManager::Get())) { return IPC_FAIL(this, "No IndexedDatabaseManager active!"); }
if (NS_WARN_IF(!QuotaManager::Get()))           { return IPC_FAIL(this, "No QuotaManager active!"); }

if (NS_WARN_IF(!StaticPrefs::dom_indexedDB_testing())) {
  return IPC_FAIL(this, "IndexedDB is not in testing mode!");   // <-- PARENT-side re-check
}

if (NS_WARN_IF(!IsValidPersistenceType(aPersistenceType))) { return IPC_FAIL(this, "PersistenceType is not valid!"); }
if (NS_WARN_IF(aOrigin.IsEmpty()))       { return IPC_FAIL(this, "Origin is empty!"); }
if (NS_WARN_IF(aDatabaseName.IsEmpty())) { return IPC_FAIL(this, "DatabaseName is empty!"); }
if (NS_WARN_IF(aFileId == 0))            { return IPC_FAIL(this, "No FileId!"); }
```

Its client wrapper (`IndexedDatabaseManager.cpp:666`) already refuses unless
`StaticPrefs::dom_indexedDB_testing()` — and the parent refuses again anyway, then re-validates every
argument. `PQuota` has the same client-side guard and no parent-side counterpart.

IndexedDB is not a distant analogy: it is a QuotaManager client living beside `dom/quota`, its data is
part of what `RecvClearStorage` destroys, and it reaches the parent over the same `PBackground`
channel from the same content processes. The two components made opposite choices about where to
enforce an identically-named testing pref.

(For completeness: `RecvFlushPendingFileDeletions` at `dom/indexedDB/ActorsParent.cpp:6873` has no
parent-side testing check either, but it only flushes already-pending internal deletions and is not
part of this report.)

### The threat model, in Mozilla's own words

If the question is whether "a compromised content process sends a message it should not" is in scope,
`netwerk/ipc/NeckoParent.cpp:733` answers it directly — the same defence `PQuota` is missing, with the
rationale written out:

```cpp
mozilla::ipc::IPCResult NeckoParent::RecvGetPageThumbStream(
    nsIURI* aURI, const LoadInfoArgs& aLoadInfoArgs,
    GetPageThumbStreamResolver&& aResolver) {
  // Only the privileged about content process is allowed to access
  // things over the moz-page-thumb protocol. Any other content process
  // that tries to send this should have been blocked via the
  // ScriptSecurityManager, but if somehow the process has been tricked into
  // sending this message, we send IPC_FAIL in order to crash that
  // likely-compromised content process.
  if (static_cast<ContentParent*>(Manager())->GetRemoteType() !=
      PRIVILEGEDABOUT_REMOTE_TYPE) {
    return IPC_FAIL(this, "Wrong process type");
  }
```

The same guard appears on `RecvGetMozNewTabWallpaperStream:778` and `RecvGetPageIconStream:824`.

Note what this code assumes: that an upstream mechanism (the ScriptSecurityManager) *already* blocks
the message, and that the parent must **still** re-check because that upstream mechanism lives in the
process being restricted. That is precisely the argument this report makes about `PQuota`, where the
upstream mechanism is `nsIQuotaManagerService`'s chrome-only/testing-pref guard in
`QuotaManagerService.cpp`, and the parent-side re-check is absent.

### Why `PQuota` cannot rely on the pattern its neighbours use

Most storage actors are **origin-scoped**: the principal is validated once, when the actor is created,
and every subsequent message is implicitly confined to that origin. LSNG localStorage is the clearest
example — `LSRequestBase::VerifyRequestParams` /
`LSSimpleRequestBase::VerifyRequestParams` call `VerifyPrincipalInfo(mContentParentHandle, …)` at
request-actor creation (`dom/localstorage/ActorsParent.cpp`), and the resulting
`PBackgroundLSDatabase` / `PBackgroundLSSnapshot` handlers (`AsyncCheckpoint`, `LoadKeys`,
`LoadValueAndMoreItems`, …) then need no per-message principal check, because the actor itself cannot
address another origin. The Client manager works the same way — `ClientSourceParent::Init` validates
once, and the actor is thereafter bound to that client.

`PQuota` is not like that. It is a **single profile-wide service actor**: one `Quota` actor per
content process, whose messages address the whole profile rather than one origin. There is no
creation-time scope that could confine `RecvClearStorage` or `RecvListOrigins`, which is exactly why
the file defines `TrustParams()` and why twenty-one handlers call it. Per-message checking is the only
available defence on this protocol — and it is the kind that can be forgotten, which is what happened
to these four handlers.

This is also why the suggested fix is worth applying at a chokepoint rather than four call sites: a
future handler added to `PQuota` will have the same requirement and the same opportunity to omit it.
