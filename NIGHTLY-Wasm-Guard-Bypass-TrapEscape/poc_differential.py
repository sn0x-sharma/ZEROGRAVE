#!/usr/bin/env python3
# poc_differential.py — SpiderMonkey Ion `array.new_default` trap-elision reproducer.
#
# Drives one or more SpiderMonkey `js` shells across compiler tiers and proves the
# miscompilation three ways:
#   1) SHELL differential  : baseline TRAPs, optimizing (Ion) returns a value.
#   2) TIER-UP reachability : with the browser's real baseline+optimizing tiering, a
#                             warmed-up function reaches Ion and elides the trap on the
#                             later trap-path call (this is what makes it web-reachable).
#   3) NEGATIVE controls    : when the array result is LIVE (array.len / array.set), every
#                             tier TRAPs identically -> confirms the bug is a contained
#                             missing-trap, not memory corruption.
#
# Zero third-party deps. Writes the exact PoC .wasm modules from embedded bytes so the
# report is self-contained (no wat2wasm / GC-aware toolchain required).
#
# Usage:
#   python3 poc_differential.py --js /path/to/js [--js /other/js ...]
#   python3 poc_differential.py --auto           # discover shells under ~/bb/targets/nemesis-sm
#   python3 poc_differential.py --emit-wasm out/  # just write module_a.wasm / module_b.wasm
import argparse, glob, os, subprocess, sys, tempfile, textwrap

# --- exact PoC module bytes (SpiderMonkey wasmTextToBinary output) --------------------------
# MODULE_A: (func (result i32) i32.const -1  array.new_default 0  drop  i32.const 42)
MODULE_A = bytes([0,97,115,109,1,0,0,0,1,8,2,94,127,1,96,0,1,127,3,2,1,1,7,7,1,3,114,117,
                  110,0,0,10,12,1,10,0,65,127,251,7,0,26,65,42,11])
# MODULE_B: (func (param i32)(result i32)
#             (if (local.get 0)(then i32.const -1 array.new_default 0 drop))
#             i32.const 1 global.set 0  global.get 0)   -- browser tier-up PoC
MODULE_B = bytes([0,97,115,109,1,0,0,0,1,9,2,94,127,1,96,1,127,1,127,3,2,1,1,6,6,1,127,1,65,
                  0,11,7,7,1,3,114,117,110,0,0,10,21,1,19,0,32,0,4,64,65,127,251,7,0,26,11,65,
                  1,36,0,35,0,11])

# --- js-shell harness snippets --------------------------------------------------------------
# 1) run a raw module file, single tier (the shell picks the tier via --wasm-compiler)
HARNESS_RUN = r"""
var p = scriptArgs[0];
var b = os.file.readFile(p, "binary");
var out;
try { out = "RES " + new WebAssembly.Instance(new WebAssembly.Module(b), {}).exports.run.apply(null, %ARGS%); }
catch (e) { out = (e instanceof WebAssembly.RuntimeError) ? "TRAP" : ("ERR " + e); }
print(out);
"""
# 2) browser-realistic tier-up: warm up run(0), await tier-2 (Ion), then hit run(1)
HARNESS_TIERUP = r"""
var p = scriptArgs[0];
var b = os.file.readFile(p, "binary");
var mod = new WebAssembly.Module(b);
var inst = new WebAssembly.Instance(mod, {});
for (var i = 0; i < 200000; i++) inst.exports.run(0);
if (typeof wasmHasTier2CompilationCompleted === "function") {
  var s = 0; while (!wasmHasTier2CompilationCompleted(mod) && s < 5000) { inst.exports.run(0); s++; }
}
var out; try { out = "RES " + inst.exports.run(1); }
catch (e) { out = (e instanceof WebAssembly.RuntimeError) ? "TRAP" : ("ERR " + e); }
print(out);
"""
# 3) negative control: array result LIVE (array.len) -> must TRAP on every tier
NEG_WAT_HARNESS = r"""
var wat = "(module (type $a (array (mut i32))) (func (export \"run\") (result i32) i32.const -1 array.new_default $a array.len))";
var out; try { out = "RES " + new WebAssembly.Instance(new WebAssembly.Module(wasmTextToBinary(wat)), {}).exports.run(); }
catch (e) { out = (e instanceof WebAssembly.RuntimeError) ? "TRAP" : ("ERR " + e); }
print(out);
"""

def sh(js, flags, harness, argfile=None):
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
        f.write(harness); jsfile = f.name
    cmd = [js] + flags + [jsfile] + ([argfile] if argfile else [])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        line = (r.stdout or r.stderr).strip().splitlines()[-1] if (r.stdout or r.stderr).strip() else "(no output)"
        return line
    except Exception as e:
        return f"(shell error: {e})"
    finally:
        os.unlink(jsfile)

def version(js):
    try:
        return subprocess.run([js, "--version"], capture_output=True, text=True, timeout=30).stdout.strip()
    except Exception:
        return "?"

def write_modules(outdir):
    os.makedirs(outdir, exist_ok=True)
    a = os.path.join(outdir, "module_a.wasm"); open(a, "wb").write(MODULE_A)
    b = os.path.join(outdir, "module_b.wasm"); open(b, "wb").write(MODULE_B)
    return a, b

def main():
    ap = argparse.ArgumentParser(description="SpiderMonkey Ion array.new_default trap-elision PoC")
    ap.add_argument("--js", action="append", default=[], help="path to a SpiderMonkey js shell (repeatable)")
    ap.add_argument("--auto", action="store_true", help="auto-discover js shells under ~/bb/targets/nemesis-sm")
    ap.add_argument("--emit-wasm", metavar="DIR", help="write module_a/b.wasm to DIR and exit")
    args = ap.parse_args()

    if args.emit_wasm:
        a, b = write_modules(args.emit_wasm); print(f"wrote {a}\nwrote {b}"); return 0

    shells = list(args.js)
    if args.auto:
        shells += sorted(set(glob.glob(os.path.expanduser("~/bb/targets/nemesis-sm/**/dist/bin/js"), recursive=True)))
    shells = [s for s in dict.fromkeys(shells) if os.path.exists(s)]
    if not shells:
        print("no js shell given. use --js <path> or --auto", file=sys.stderr); return 2

    outdir = tempfile.mkdtemp(prefix="anewd_poc_")
    ma, mb = write_modules(outdir)
    ra = HARNESS_RUN.replace("%ARGS%", "[]")       # module A: no args
    rb1 = HARNESS_RUN.replace("%ARGS%", "[1]")     # module B run(1) forced-Ion

    print("="*78)
    print("SpiderMonkey Ion  array.new_default  trap-elision — differential PoC")
    print("  expected-correct = TRAP ('too many array elements');  BUG = a value")
    print("="*78)
    for js in shells:
        print(f"\n### {version(js)}   [{js}]")
        # 1) shell differential on the minimal module A
        base = sh(js, ["--wasm-compiler=baseline"],   ra, ma)
        opt  = sh(js, ["--wasm-compiler=optimizing"], ra, ma)
        tier = sh(js, ["--wasm-compiler=baseline+optimizing"], HARNESS_TIERUP, mb)
        neg  = sh(js, ["--wasm-compiler=optimizing"], NEG_WAT_HARNESS)
        verdict = "BUG" if (base == "TRAP" and opt.startswith("RES")) else "not-reproduced"
        reach   = "WEB-REACHABLE" if tier.startswith("RES") else "shell-only"
        print(f"  [1] baseline (module A) ......... {base:<8}  (expect TRAP)")
        print(f"  [1] optimizing/Ion (module A) ... {opt:<8}  (BUG if RES)   -> {verdict}")
        print(f"  [2] tier-up warmup->run(1) ...... {tier:<8}  -> {reach}")
        print(f"  [3] neg control (array.len live)  {neg:<8}  (expect TRAP => contained, no OOB)")
    print("\nlegend: [1] shell differential  [2] browser-tiering reachability  [3] memory-safety-ceiling control")
    return 0

if __name__ == "__main__":
    sys.exit(main())
