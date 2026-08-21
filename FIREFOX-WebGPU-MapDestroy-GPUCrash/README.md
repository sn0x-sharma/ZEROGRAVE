# WebGPU Mapped-Buffer Teardown DoS + Escalation Research

## Confirmed Bug

Repeated mapped-buffer teardown through iframes (or workers) wedges WebGPU so
subsequent `navigator.gpu.requestAdapter()` / `requestDevice()` calls hang or fail.
Reachable from a normal web page with no user interaction beyond visiting.

**Affected**: Firefox (confirmed by sn0x, exact build TBD)
**Reachability**: Normal web content — no special permissions

## PoC Files

- `poc/webgpu_dos.html` — DoS proof, measures hang time
- `poc/webgpu_uaf_probe.html` — Escalation research: UAF / OOB probe on stale mapped buffer
- `poc/webgpu_timing_oracle.html` — Cross-origin GPU timing oracle probe

## Escalation Paths

### Path A — UAF on Stale Mapped Buffer (GPU Process)

When an iframe (or worker) is torn down while a `mapAsync()` is in flight:

1. Content process sends IPC to GPU process: "map this buffer"
2. Content process destroys iframe → buffer JS object gc'd → content-side cleanup fires
3. GPU process completes the map → tries to deliver result to now-dead content reference
4. If wgpu's buffer object is freed during step 2 but the GPU process holds a raw pointer to it for the
   in-flight operation → **use-after-free in GPU process**

**Test**: `webgpu_uaf_probe.html` instruments this race.

### Path B — OOB Read via getMappedRange() After Destroy

If `getMappedRange()` returns an `ArrayBuffer` that points into a freed wgpu arena
after `device.destroy()` is called:

- Read `ArrayBuffer` bytes → GPU process heap disclosure
- Could leak adjacent buffer contents from other origins sharing the GPU process heap

### Path C — Cross-Origin GPU Timing Oracle

If the wedge affects ALL origins sharing the GPU process (WebGPU is typically
per-process, not per-origin):

- Load cross-origin iframe, start a GPU operation inside it
- Time how long it takes relative to baseline
- Timing delta reveals cross-origin GPU activity → side-channel

## Impact

| Variant | CVSS | Class |
|---------|------|-------|
| DoS only | 6.5 (Med) | Availability |
| UAF → GPU process crash | 7.5 (High) | Memory safety |
| UAF → GPU process code exec | 9.8 (Crit) | Remote code execution |
| Cross-origin timing oracle | 4.3 (Med) | Information disclosure |

## Chain to 04

GPU process compromise via UAF → able to send unsolicited
WebRender IPC messages → ExternalImageId owner bypass → read/write
cross-origin pixels. See `04-webrender-externalimage/README.md`.

## Run

Open `poc/webgpu_dos.html` in Firefox. Open the browser console.
The page runs automatically and reports results.
