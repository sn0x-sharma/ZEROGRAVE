#!/usr/bin/env python3
"""
Minimal HTTP server for serving the PoC files.
Usage: python3 server.py [port]
Default port: 8080
"""
import http.server
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080

handler = http.server.SimpleHTTPRequestHandler
handler.extensions_map.update({".html": "text/html", ".js": "application/javascript"})

with http.server.HTTPServer(("127.0.0.1", PORT), handler) as httpd:
    print(f"[*] Serving on http://127.0.0.1:{PORT}")
    print("[*] NOTE: This IPC bug requires renderer RCE. The HTML PoC documents")
    print("[*]       the IPC message structure — it cannot be triggered from JS.")
    httpd.serve_forever()
