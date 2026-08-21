# Mozilla Bugzilla Submission — Bug 03 (rewritten, confirmed-vector only)
# Platform: bugs.mozilla.org — Product: Core / Component: DOM: Networking (Cookies)
# Severity: S3 (Medium) | Security-sensitive: YES
# Filed: 2026-06-29 | Rewritten: 2026-06-30

---

## Title

```
CookieStore 'change' event fires across port-distinct origins — a document at http://host:A/ receives name+value of non-HttpOnly cookies set by http://host:B/
```

---

## Description

`cookieStore.addEventListener('change', ...)` delivers a cookie-change notification
(including the cookie **name and value**) to a document at `http://host:PORT_A/` when
the cookie is set by the distinct Web Origin `http://host:PORT_B/`. The event router
matches on the RFC 6265 cookie domain (host only, port-agnostic) instead of the Web
Origin (scheme + host + **port**).

Confirmed on **Firefox 146.0.1** (automated Playwright test, 2026-06-30): a listener
attached at `http://127.0.0.1:9101/` received the `change` event for a cookie set at
`http://127.0.0.1:9102/` **after** the listener was attached — so this is the push
event firing, not a `getAll()` snapshot.

### What is and isn't novel here

- **Reading** cross-port cookies is NOT novel. `document.cookie` and
  `cookieStore.getAll()` are both port-agnostic by RFC 6265 design; a page at
  `:9101` can already read `:9102`'s non-HttpOnly cookies. This is not the bug.
- **The novel issue:** the `change` **event** is a new, push-based interface that, per
  the Web Origin model, should be port-scoped — and is not. It lets a page at one port
  learn the name+value of cookies set by another port **the instant they change, with
  no polling** (no `setInterval` over `getAll()`, no CPU/timing fingerprint).

### Scope limitation (stated honestly)

- **HttpOnly cookies are correctly excluded** — confirmed; the flag is respected.
- **Sibling hosts are correctly isolated** — `a.host` does not receive `b.host` events.
- The **Service Worker `cookiechange` persistent variant is NOT part of this report.**
  It requires `registration.cookies.subscribe()` and a background-SW delivery I could
  not demonstrate in the test environment; it is explicitly not claimed here.

---

## Steps to Reproduce

**Automated (deterministic, ~10 s) — attached `document_vector_repro.py`:**

```bash
python3 document_vector_repro.py
# Spins up two origins on one host:
#   http://127.0.0.1:9101/  (attacker — attaches the change listener)
#   http://127.0.0.1:9102/  (victim   — sets a cookie)
```

**Manual (browser, no tooling):**

1. Serve any page at two ports on the same host, e.g. `http://localhost:9101/` and
   `http://localhost:9102/`.
2. Open `http://localhost:9101/`. In its DevTools console, attach the listener:

   ```javascript
   cookieStore.addEventListener('change', e => {
     for (const c of e.changed) console.warn('cross-port change:', c.name, '=', c.value);
   });
   ```

3. In a second tab open `http://localhost:9102/` and set a cookie there:

   ```javascript
   cookieStore.set({ name: 'victim_session', value: 'SESSTOKEN', path: '/', sameSite: 'lax' });
   ```

4. Return to the `:9101` tab. The console logs `cross-port change: victim_session = SESSTOKEN`
   — a cookie set by a different Web Origin (`:9102`), delivered to `:9101` in real time.

---

## Expected vs Actual

**Expected:** the `change` event should respect the subscriber's Web Origin. A document
at `http://host:9101/` should receive events only for cookies whose effective delivery
scope matches `http://host:9101/` — not for cookies set by `http://host:9102/`. Port is
part of the Web Origin (HTML spec §7.5).

**Actual:** the event fires for any port sharing the same scheme+host. The `:9101`
document receives the full name and value of the `:9102` cookie.

**Raw captured output — Firefox 146.0.1 (attached `document_vector_confirmed.txt`):**

```
Attacker origin: http://127.0.0.1:9101/   Victim origin: http://127.0.0.1:9102/
[attacker:9101] listener-attached via cookieStore.addEventListener('change')
[attacker:9101] change events received for cookies set at :9102:
   CHANGED  name='victim_session'  value='SESSTOKEN_set_at_9102'   <- set by DIFFERENT ORIGIN :9102
RESULT: CONFIRMED — cross-port change event delivered name+value.
Note: listener was attached BEFORE the cookie was set → this is the push 'change'
      event firing, not a getAll() snapshot.
HttpOnly cookies: excluded (flag respected).  Sibling hosts (a.host vs b.host): isolated.
```

---

## Impact

A page at one port can monitor, in real time and without polling, every non-HttpOnly
cookie change at a sibling port on the same host. Concrete setting where this matters:
a host runs a trusted app on one port (e.g. an admin SPA on `:8443` that keeps its
session token in a non-HttpOnly cookie) and a lower-trust or attacker-influenced app on
another port (`:8080`). A page on `:8080` that attaches the `change` listener captures
the admin token the moment it is set — silently, with no polling fingerprint.

The cookie **value** (potentially a session token) is exposed across the Web Origin
boundary through a new event API that should have been port-scoped.

**Honest severity bounding:** the cookie values are *already* readable cross-port via
`getAll()`/`document.cookie` (RFC 6265), so the event vector does not expose a new
*class* of data — its unique contribution is reliable, real-time, no-poll capture. I
therefore score the incremental confidentiality as **Low**, not High.

---

## CVSS 3.1

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N = 4.7 (Medium)
```

| Metric | Value | Rationale |
|---|---|---|
| AV:N | Network | Attacker serves the listening page over the web |
| AC:L | Low | No special conditions beyond a shared host |
| PR:N | None | No account or privileges |
| UI:R | Required | Victim must set a cookie at the sibling port while the attacker page is open |
| S:C | Changed | A page at port A observes port B's (different Web Origin) cookie data |
| C:L | Low | Cross-port read pre-exists via getAll; the event adds real-time push, not a new data class |
| I:N / A:N | None | Read-only, no availability impact |

> Not claimed: a C:H framing (`…/C:H/…` = 7.4 High) is defensible if one counts the raw
> session-value exposure and ignores the pre-existing `getAll()` baseline. I claim the
> conservative Medium because the incremental capability over the status quo is the
> push/no-poll notification, not new data access.

---

## Root Cause

RFC 6265 §4.1.2 excludes port from the cookie domain. The CookieStore `change` event
dispatch inherits that port-agnostic matching rather than applying the Web Origin model.
A subscriber at `http://host:9101/` is matched against cookies whose domain is `host`,
which covers every port. The WHATWG CookieStore spec
(https://wicg.github.io/cookie-store/) does not require port filtering on event
delivery, which is why both Firefox and Chrome reproduce identically.

---

## Remediation

1. **Spec fix (preferred):** file an issue at https://github.com/WICG/cookie-store/issues
   requiring `change`/`cookiechange` event delivery to filter on the subscriber's full
   Web Origin (scheme + host + port). Fixes all engines uniformly.
2. **Gecko implementation fix:** when dispatching a `change` event, compare the cookie's
   effective setter port against the subscriber's origin port and suppress mismatches.

---

## Versions

| Browser | Version | Status |
|---|---|---|
| Firefox | 146.0.1 | CONFIRMED (automated Playwright, document vector) |
| Firefox | all with `cookieStore` change event (101+) | likely affected (same engine path) |

---

## Cross-report note

Also reported to Chrome VRP (Chromium 145 / Chrome 147 reproduce identically). The
identical behaviour in two engines indicates a WHATWG CookieStore spec-level issue.

---

## Attachments

```
1. cookiestore_xport_poc.html       — single-file browser PoC (serve on 2 ports, open lower; auto-demos the change event cross-port)
2. document_vector_repro.py         — deterministic automated reproduction (run it)
3. document_vector_confirmed.txt    — raw captured output (Firefox 146, this vector)
4. comparison_docvscookiestore.txt  — proves getAll() == document.cookie (read is NOT novel)
```

---

*Research by sn0x — authorized security research. Read-only PoC, no user data touched.*
