#!/usr/bin/env python3
import http.server
import urllib.parse

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8', 'replace')
        print(f"POST {self.path} body={body}", flush=True)
        if self.path == '/login':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Logged in (fake)</h1></body></html>")
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"ok")

    def log_message(self, fmt, *args):
        with open('server.log', 'a') as f:
            f.write("%s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), fmt % args))

if __name__ == '__main__':
    http.server.HTTPServer(('127.0.0.1', 8901), Handler).serve_forever()
