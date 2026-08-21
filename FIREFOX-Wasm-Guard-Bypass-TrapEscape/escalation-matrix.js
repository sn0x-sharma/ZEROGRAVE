function one(wat, args) {
  var bin; try{bin=wasmTextToBinary(wat);}catch(e){return "WAT-ERR "+e;}
  try { var i=new WebAssembly.Instance(new WebAssembly.Module(bin),{});
        return "RES "+i.exports.run.apply(null,args||[]); }
  catch(e){ return (e instanceof WebAssembly.RuntimeError)?("TRAP"):("ERR "+e); }
}
var C = {
 // C1 CSE-ALIASING (critical if bug): two distinct arrays merged -> write x visible in y
 C1_cse_alias: `(module (type $a (array (mut i32)))
   (func (export "run") (result i32)
     (local $x (ref null $a))(local $y (ref null $a))
     i32.const 4 array.new_default $a local.set $x
     i32.const 4 array.new_default $a local.set $y
     local.get $x i32.const 0 i32.const 111 array.set $a
     local.get $y i32.const 0 array.get $a))`,   // baseline 0 ; bug if 111
 // C2 CODE-AFTER-GUARANTEED-TRAP executes (guard bypass)
 C2_deadcode_after_trap: `(module (type $a (array (mut i32)))
   (global $g (mut i32) (i32.const 0))
   (func (export "run") (result i32)
     i32.const -1 array.new_default $a drop
     i32.const 1 global.set $g
     global.get $g))`,                            // baseline TRAP ; bug if 1
 // C3 LICM/loop: side-effect loop body runs despite per-iter trap
 C3_loop_sideeffect: `(module (type $a (array (mut i32)))
   (global $g (mut i32) (i32.const 0))
   (func (export "run") (result i32) (local $i i32)
     (loop $L
       i32.const -1 array.new_default $a drop
       global.get $g i32.const 1 i32.add global.set $g
       local.get $i i32.const 1 i32.add local.tee $i i32.const 3 i32.lt_s br_if $L)
     global.get $g))`,                            // baseline TRAP ; bug if 3
 // C4 does struct.new_default get same DCE? (no length-trap, control)
 C4_arraynewfixed_huge: `(module (type $a (array (mut i32)))
   (func (export "run") (result i32)
     i32.const -1 array.new_default $a
     i32.const -1 array.new_default $a
     array.len i32.add))`,                         // both used -> expect TRAP both
};
for (var k in C) print(k+"  ->  "+one(C[k]));
