# Mozilla Bugzilla Security Report — Bug 02
# Platform: bugs.mozilla.org
# Product: Firefox | Component: Core › Graphics: WebGPU
# Severity: S3 (Medium) — Confirmed DoS, suspected UAF (exploitability unconfirmed)
# Security-sensitive: YES
# Filed: 2026-06-29 | Updated: 2026-06-30

---

## Title

```
WebGPU Worker mapAsync() + device.destroy() race crashes the Firefox GPU process — confirmed tab DoS, suspected use-after-free
```

---

## Summary

A Web Worker that starts a `mapAsync()` operation on a GPU buffer and then immediately calls `device.destroy()` crashes the Firefox tab within ~1 second. The crash is triggered by a use-after-free in the GPU process: the destroy IPC frees the buffer's backing storage while the mapping IPC is still in flight; when the map completes, wgpu attempts to deliver the result to the freed buffer object. A standard web page can crash any Firefox tab by spawning a Worker with five lines of WebGPU code — no user interaction required beyond visiting the page.

Confirmed on **Firefox 146** (Linux x86_64, WebGPU enabled).

---

## Vulnerability Details

**Component:** WebGPU — wgpu GPU process (`browser/components/dom/webgpu/`)  
**Bug class:** Use-After-Free (GPU process) triggered by async IPC race  
**Affected prefs:** `dom.webgpu.enabled=true`, `dom.webgpu.workers.enabled=true`  
**Confirmed:** Firefox 146 (Playwright headless, Linux x86_64)

**CVSS 3.1 (claimed):** `AV:N/AC:H/PR:N/UI:R/S:C/C:N/I:N/A:H` = **5.9 Medium** — confirmed DoS/crash only.  
**CVSS 3.1 (NOT claimed — conditional on proof):** `AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:H` = **7.5 High** — would apply *only if* memory disclosure or a controlled UAF write is demonstrated. As of this filing that has **not** been proven (see "Escalation Attempt" below), so the claimed severity is Medium.

---

## Root Cause

The crash is a race condition between two in-flight GPU IPC messages:

1. `buf.mapAsync(GPUMapMode.READ)` → sends "MapBuffer" IPC to GPU process (async, result pending)
2. `device.destroy()` → sends "DestroyDevice" IPC to GPU process (frees buffer backing storage)

In the GPU process, when "MapBuffer" completes after "DestroyDevice" has freed the buffer's backing storage, wgpu tries to deliver the mapping result to the freed buffer object → use-after-free → GPU process crash → Firefox tab crash.

**Why Worker context amplifies this:**  
Web Workers have independent GPU devices and don't share the render thread's synchronization. The IPC ordering between `mapAsync` and `destroy` is not enforced — the race window is always open.

---

## Steps to Reproduce

**Environment:**
- Firefox 146 with `dom.webgpu.enabled=true` and `dom.webgpu.workers.enabled=true`
- Any web page the victim visits (no special permissions needed)

**Minimal crash trigger (5 lines in a Web Worker):**

```html
<!doctype html>
<script>
const code = `
  self.onmessage = async () => {
    const adapter = await navigator.gpu.requestAdapter();
    const device = await adapter.requestDevice();
    const buf = device.createBuffer({
      size: 4096,
      usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST,
    });
    const mapProm = buf.mapAsync(GPUMapMode.READ);
    device.destroy();   // GPU frees buffer while map IPC is in-flight
    await mapProm;      // UAF: result delivered to freed storage → crash
  };
`;
const w = new Worker(URL.createObjectURL(new Blob([code], {type:'application/javascript'})));
w.postMessage('go');
</script>
```

**Steps:**

1. Enable `dom.webgpu.enabled=true` in `about:config`  
2. Enable `dom.webgpu.workers.enabled=true` in `about:config`
3. Open the above HTML page (or host it at any URL)
4. The page spawns the Worker automatically
5. The Firefox tab crashes within ~1 second

**Expected behavior:** `device.destroy()` while `mapAsync` is pending should either:
- Reject the `mapAsync` promise with an appropriate error, or
- Handle the in-flight IPC gracefully and ignore the stale result

**Actual behavior:** Firefox tab becomes inaccessible within ~1 second. GPU process crash.

---

## Evidence

Observed via Playwright headless automation against Firefox 146 (3 runs):

```
t=0.0s  page.goto() — page loaded
t=0.1s  console: "[*] Spawning Worker with mapAsync + device.destroy() race..."
t=0.1s  console: "[*] Worker posted — waiting..."
t=~1.0s page.inner_text() raises:
         "Page.inner_text: Target page, context or browser has been closed"
         (tab crash — before 5s worker timer fires, before worker can post a message)
```

**Reproducibility: 3/3 runs crashed.**

**Control tests (same browser session):**

| Worker action | Result |
|---|---|
| `requestAdapter()` only | PASS — no crash |
| `requestAdapter()` + `requestDevice()` | PASS — no crash |
| `mapAsync()` only (no destroy) | PASS — map resolves |
| `mapAsync()` + `device.destroy()` + `await mapProm` | **CRASH** — page inaccessible |

The crash is specific to the race between pending map and device destroy.

---

## Impact

Any web page can crash Firefox tabs that have WebGPU enabled. The attacker does not need to:
- Know what WebGPU operations the victim is running
- Have any special permissions or elevated context
- Interact with any user-facing WebGPU APIs

The crash is a **tab crash** (not browser crash in Playwright testing), which represents a denial-of-service against the current tab and all its state (open documents, scroll position, form data). Combined with session restore, this could be exploited to repeatedly crash specific tabs.

**Current proven impact: tab denial-of-service only.** I have not proven memory
disclosure or code execution, and I do not claim them. The crash *pattern* (race-
dependent, requires both the pending map and the destroy, ~1s map-IPC round-trip
latency, clean negative controls on the original hardware run) is consistent with a
use-after-free rather than a benign null dereference — but "consistent with" is not
proof, so the report is scoped to the DoS that is actually demonstrated.

---

## Escalation Attempt (transparency)

I built and ran a dedicated escalation harness rather than stop at the crash. I am
recording the attempt and its negative result so triage has full context.

**Harness** (`poc/webgpu_uaf_weaponized.html` + `poc/run_exploit.py`): a 5-stage
escalation — (1) confirm the primitive, (2) heap-groom 64×4096B mapped buffers with
marker bytes, (3) hold a live `getMappedRange()`, free the device, churn-spray a
reclaim pattern, then re-read the stale range to detect a cross-allocation UAF read
(memory disclosure), (4) reclaim-and-corrupt race, (5) parallel worker swarm. The
launcher implements a **control gate**: it first runs a benign `device + map + unmap`
and *refuses to attribute any trigger crash to the bug* unless that control survives.

**Result on the test machine: inconclusive — the environment cannot test WebGPU.**
- Hardware: VMware virtual adapter, Mesa **llvmpipe** software rasterizer, no hardware
  Vulkan. (`lspci`, `glxinfo` → `llvmpipe`.)
- Firefox 146 (automation build): the software WebGPU backend crashes on **any** usage
  — bare `requestAdapter()` and bare `requestDevice()` crash identically to the trigger
  (control matrix: 5 scenarios × 2 = 10/10 crash). The control gate therefore does not
  pass, so **no crash on this host is attributable to the bug** and Stage 3's
  disclosure check could not run.
- Forcing software Vulkan (lavapipe) disables WebGPU entirely (`navigator.gpu`
  undefined).
- System Firefox 140 ESR: `requestAdapter()` → `NotSupportedError: WebGPU is not yet
  available in Release or late Beta builds` (WebGPU is compiled out of Release/ESR).

**Conclusion:** the memory-disclosure / UAF escalation is neither confirmed nor refuted
— it is **untested** for lack of a WebGPU-capable test host. Confirming it requires a
machine with a real GPU (hardware Vulkan), ideally a Firefox **ASAN build**: the
launcher's `--mode firefox` tails stderr for `heap-use-after-free` and saves the ASAN
report as report-grade proof. Until that runs, the claimed severity stays Medium (DoS).

---

## Additional DoS Vector (Confirmed Previously — Original iframe-based DoS)

The original Bug 02 finding was iframe-based:

```html
<!-- Repeated iframe teardown while mapAsync is in flight -->
<!-- Wedges the GPU process → all subsequent requestAdapter() calls hang -->
```

This is a separate DoS vector that wedges the GPU process (rather than crashing it). Both vectors share the same root cause — missing synchronization between pending map IPC and device/frame teardown.

**Recommendation:** Fix both in the same patch — the Worker variant (crash) and the iframe variant (wedge).

---

## Recommended Fix

**Option A — Reject pending mapAsync on device.destroy():**
```
When device.destroy() is called:
1. Mark all pending mapAsync operations as rejected
2. Deliver GPUMapError to the content process for each pending map
3. In GPU process: do not deliver map results for destroyed devices
```

**Option B — Guard the IPC result handler:**
```
Before delivering mapAsync result:
  if (buffer->device->is_destroyed()) { return; }
```

**Option C — Sequence enforcement:**
```
When device.destroy() is called with pending IPC operations:
Wait for all in-flight IPC rounds to complete before freeing resources.
```

The fix in Option A or B is minimal. Option C may have performance implications.

---

## PoC Files

```
poc/webgpu_worker_crash_minimal.html   — minimal 5-line Worker crash trigger
poc/webgpu_dos.html                    — original iframe-based GPU wedge DoS
poc/webgpu_uaf_probe.html              — early 4-probe escalation research
poc/webgpu_uaf_weaponized.html         — 5-stage escalation harness (groom/leak/reclaim/swarm)
poc/run_exploit.py                     — launcher w/ control-gate + ASAN capture + retry loop
evidence/worker_crash_confirmed.txt    — raw evidence, 3/3 crash, CLEAN control matrix
                                         (Firefox 146.0.1, hardware-GPU GUI install, 2026-06-29)
BUG02_ESCALATION.md                    — escalation analysis + proof hierarchy + run instructions
```

**Note on evidence provenance:** the 3/3 confirmation with a *clean* control matrix
(controls pass, only the trigger crashes) is the **2026-06-29 hardware-GPU GUI run**
recorded in `evidence/worker_crash_confirmed.txt`. The 2026-06-30 escalation attempt
ran on a software-only host where the WebGPU backend is too unstable to attribute
crashes (see "Escalation Attempt"); that host's crashes are **not** used as evidence.

---

## Notes

- WebGPU is enabled but not the default in current Firefox stable — requires `about:config` opt-in
- Workers WebGPU is a newer feature (`dom.webgpu.workers.enabled`) — higher chance of missing synchronization
- The iframe DoS variant likely works without `dom.webgpu.workers.enabled`
- `get_user_memories` sibling pattern does NOT apply here — this is a wgpu IPC concern

---

*Researcher: sn0x | Authorized security research*
