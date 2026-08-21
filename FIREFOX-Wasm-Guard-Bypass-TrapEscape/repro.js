// SM Ion trap-elision repro. Run under a single --wasm-compiler shell.
// Expected: baseline -> TRAP ; optimizing -> RES 42 (BUG).
var wat = `(module (type $a (array (mut i32)))
  (func (export "run") (result i32)
    i32.const -1 array.new_default $a drop
    i32.const 42))`;
var bin = wasmTextToBinary(wat);
var out;
try { out = "RES "+ new WebAssembly.Instance(new WebAssembly.Module(bin),{}).exports.run(); }
catch(e){ out = (e instanceof WebAssembly.RuntimeError) ? ("TRAP ("+e.message+")") : ("ERR "+e); }
print(out);
