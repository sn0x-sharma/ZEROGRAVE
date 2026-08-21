;; SpiderMonkey Ion (WarpMonkey optimizing) trap-elision — array.new_default
;; baseline/V8 -> TRAP "too many array elements" ; Ion -> RES 42 (trap wrongly removed)
(module
  (type $a (array (mut i32)))
  (func (export "run") (result i32)
    i32.const -1            ;; length = 0xFFFFFFFF (must trap: array too large)
    array.new_default $a    ;; MANDATORY trap here
    drop                    ;; result dead -> Ion DCEs the alloc AND its trap
    i32.const 42))
