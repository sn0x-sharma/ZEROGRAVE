# SpiderMonkey Ion (WarpMonkey) trap-elision of `array.new_default` — Wasm-GC JIT miscompilation

**Component:** JavaScript: WebAssembly (SpiderMonkey optimizing JIT / Ion-Warp)
**Class:** JIT miscompilation — mandatory trap eliminated by dead-code elimination (CWE-670 / CWE-758)
**Found by:** nemesis differential fuzzer (SpiderMonkey target, cross-engine + cross-tier oracle)
**Affected (confirmed, dynamic):** Firefox **152.0.6** (target, `JavaScript-C152.0.6`), **153.0** release, **155.0a1** Nightly — all UNPATCHED.
**Reference class:** CVE-2026-12321 (JIT miscompilation in JS: WebAssembly, MFSA 2026-57).

---

## Summary
SpiderMonkey's optimizing Wasm compiler (Ion/WarpMonkey) models `array.new_default` as a
side-effect-free, removable MIR node — it omits the opcode's **mandatory allocation-size trap**.
When the array result is dead (dropped, or transitively dead through a dropped `struct.new` /
`ref.cast`), dead-code elimination removes the allocation **together with its guaranteed trap**.
The baseline (Rabaldr) compiler and both V8 tiers correctly trap. A trap is an observable
WebAssembly outcome that must be preserved; removing it lets code that must be unreachable execute.

## Root cause (one line)
Ion's effect model marks `array.new_default` as pure/removable, dropping its
"too many array elements" trap; baseline and V8 preserve it.

## Minimal PoC (`poc.wat` / `repro.js`)
```wat
(module
  (type $a (array (mut i32)))
  (func (export "run") (result i32)
    i32.const -1            ;; length 0xFFFFFFFF -> array too large, MUST trap
    array.new_default $a
    drop                    ;; result dead
    i32.const 42))
```
Run: `js --wasm-compiler=<tier> repro.js`

| engine / tier | result |
|---|---|
| SpiderMonkey baseline (Rabaldr) | **TRAP** "too many array elements" |
| SpiderMonkey **optimizing (Ion)** | **RES 42** ← trap eliminated (BUG) |
| SpiderMonkey baseline+optimizing (tier-up) | TRAP |
| V8 Liftoff | TRAP |
| V8 TurboFan | TRAP |

Consensus of 4 correct tiers vs the lone Ion outlier. Deterministic (5/5).

## Version matrix (dynamically verified on prebuilt js shells)
| build | baseline | Ion |
|---|---|---|
| `JavaScript-C152.0.6` (target) | TRAP | **RES 42** |
| `JavaScript-C153.0` (current release) | TRAP | **RES 42** |
| `JavaScript-C155.0a1` (Nightly/central) | TRAP | **RES 42** |

Unpatched across release **and** central at time of writing.

## Novelty (not a duplicate)
- Reproduces on **`JavaScript-C155.0a1` (latest Nightly / mozilla-central), today** — unfixed on
  the newest tree. Mozilla fixes Wasm miscompiles quickly on central; presence on today's
  central indicates the bug is unreported (or filed too recently to be fixed). Any *already
  reported* instance would be on an older, already-fixed build — this reproduces on the newest.
- No public / Bugzilla / search hit for "array.new_default trap elimination / DCE miscompile".
- The differential fuzzer re-discovered this same root cause across many module shapes (drop /
  struct.new / ref.cast / local.set dead result) — internal fuzzer dedup, not prior art.
- Caveat: Bugzilla hides security-restricted bugs from public search, so recent private filings
  can't be excluded; the "affects latest Nightly" fact is the anti-duplicate argument.

## Scope / variant analysis
| construct (result dead) | Ion | note |
|---|---|---|
| `array.new_default` + drop | **trap elided** | the bug |
| `array.new_default` → `struct.new` → drop | **trap elided** | DCE transitive through pure GC constructor |
| `array.new_default` → `ref.cast` → drop | **trap elided** | DCE transitive through cast |
| `array.new` (explicit init) + drop | TRAP | correctly modeled (control) |
| `array.new_data` OOB + drop | TRAP | correctly modeled |
| `array.new_elem` OOB + drop | TRAP | correctly modeled |

The defect is **specific to `array.new_default`** and propagates through pure GC
constructors/casts when the final result is dead.

## Impact — honest ceiling (rigorously tested, NOT memory-unsafe)
The observable effect is a **missing trap**: a `array.new_default` guaranteed to trap does not,
so any instruction *after* the guaranteed trap executes.

Demonstrated (`escalation-matrix.js`, all on 152.0.6):
- **Dead-code-after-trap executes** — `... array.new_default(-1) drop; global.set $g (1); return $g` → baseline TRAP, Ion **returns 1** (post-trap `global.set` ran). A Wasm program using a guaranteed trap as a guard is bypassed.
- **Loop side effects execute** — per-iteration guaranteed trap removed; loop body runs to completion (Ion returns 3 where baseline traps).

Escalation attempts that were **negative** (bug is contained — no memory-safety path):
- CSE / aliasing of two same-length arrays → **distinct** (no type confusion).
- OOB read (`array.get`) / write (`array.set`) on the ref → **TRAP** (materialization re-checks).
- Element-size-overflow / under-allocation across i32/i64 at every boundary length (0x0FFFFFFF…0xFFFFFFFF) → **baseline == Ion** (no divergence when the result is live).
- Struct field-read / ref materialization → **TRAP** (no bogus/null array ref).

**Conclusion:** correctness / spec-violation (missing trap → unreachable code reachable), **no
host memory corruption**. Realistic Mozilla rating: **sec-low to sec-moderate** (same class and
rating as CVE-2026-12321). Trap-elision between Wasm tiers is nonetheless a bug Mozilla acts on
(tier divergence must be zero); exploitability assessment deferred to the SpiderMonkey team.

## Web reachability (browser tier-up — NOT shell-only)
The shell result uses `--wasm-compiler=optimizing` (Ion-only). A real browser runs **baseline
first, then tiers up to Ion in the background**. Because baseline traps on the trap path, a
naive PoC never reaches Ion. The realistic exploit shape uses a **conditional** trap path
(`module_b.wasm`): warm the function on the non-trapping path to drive baseline→Ion tier-up,
then call the trap path.

Verified under the browser's actual tiering mode (`--wasm-compiler=baseline+optimizing`,
tier-2 completion confirmed via `wasmHasTier2CompilationCompleted`) on **152.0.6, 153.0 and
155.0a1**: after warm-up, `run(1)` returns **1** (the post-trap `global.set` executed) instead
of trapping. `exploit.html` reproduces this in Firefox itself. So the bug is **web-content
triggerable**, not a shell artifact.

## CVSS 3.1 (indicative)
`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` → **3.1 (Low)** on paper (integrity of an in-sandbox Wasm
computation only; no host confidentiality/availability impact). The meaningful metric is
Mozilla's internal sec-rating: given confirmed web-reachability and that tier divergence must be
zero, realistically **sec-moderate**, same class as CVE-2026-12321. Not memory-safety.

## Suggested MFSA-style description
> "JIT miscompilation in the JavaScript: WebAssembly component. The optimizing compiler could
> eliminate the mandatory trap of an `array.new_default` instruction whose result was unused,
> causing a WebAssembly module to continue executing where it should have trapped."

## How it was found
`nemesis` (typed Wasm-GC differential fuzzer) was wired to a SpiderMonkey target (new
`NEMESIS_ENGINE=sm|xengine` mode + `run_wasm_sm.js` harness). Cross-engine V8-vs-SpiderMonkey +
SpiderMonkey baseline-vs-optimizing oracle, seed 6 / iter 48 produced a divergence
(`nemesis-original-divergence.wasm`), delta-reduced by hand to the 3-instruction PoC above.

## Files / artifacts
- `poc.wat` — minimal WAT (shell repro).
- `repro.js` — standalone one-shot repro (any SpiderMonkey js shell).
- `poc_differential.py` — multi-shell, multi-tier differential driver: prints the
  `[1] shell-differential / [2] browser-tiering-reachability / [3] memory-safety-ceiling`
  matrix; `--auto` discovers shells; `--emit-wasm DIR` writes the modules. Zero deps.
- `exploit.html` — **browser PoC**: warms up to force Ion tier-up, then triggers the trap
  path; visual BUG/SAFE verdict. Open in Firefox.
- `wasm_poc_builder.cpp` — dependency-free C++ builder that emits the exact PoC `.wasm`
  bytes (byte-annotated Wasm-GC structure) and drives the js-shell differential.
- `escalation-matrix.js` — escalation + negative-result battery (guard-bypass positive;
  aliasing/OOB/under-alloc negative → contained).
- `nemesis-original-divergence.wasm` — the raw fuzzer hit (95 bytes) before minimization.

## Reproduce
```sh
# 1. get the exact target shell
fuzzfetch --target js --branch release --build 2026-07-13 -n sm152   # JavaScript-C152.0.6
JS=$(find . -name js -path '*sm152*' | head -1)

# 2. one-line shell differential
$JS --wasm-compiler=baseline   repro.js   # TRAP  (correct)
$JS --wasm-compiler=optimizing repro.js   # RES 42 (bug)

# 3. full matrix incl. browser-tiering reachability
python3 poc_differential.py --js "$JS"

# 4. dependency-free C++ builder + differential
g++ -std=c++17 -O2 wasm_poc_builder.cpp -o wasm_poc_builder && ./wasm_poc_builder "$JS"

# 5. browser proof: open exploit.html in Firefox 152.0.6 / 153.0
```
