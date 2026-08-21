# Password Manager's "wait for a fresh user gesture" gate never resets across a Back/Forward Cache restore, letting a saved password reveal into script-readable `element.value` with no interaction on the restored page

# Summary

Chromium's password autofill deliberately withholds a saved password's real value from `element.value` until it believes the user has freshly, intentionally interacted with the page (`PasswordAutofillAgent::PasswordValueGatekeeper`). The flag this gate depends on is reset in exactly one place, tied to a brand-new document being committed (`ReadyToCommitNavigation`) but a Back/Forward Cache (BFCache) restore resumes the same frozen document instead of committing a new one, and notifies observers through a completely separate channel (`DidSetPageLifecycleState`) that this component never listens to. The result: once any single, unrelated gesture has ever occurred on a page, the gate stays open forever across BFCache round trips. I built an end-to-end PoC that adds a real saved password, gets one incidental click, then has the page navigate itself away and immediately call `history.back()` with **zero further interaction** and confirmed the real password
lands in a freshly-created password field's `.value`, readable by any script on that origin, on the very first check after the restore. Reproduced 7/7 times across three variants with two different credentials.

# Affected Version(s)

- **Product:** Chromium / Google Chrome
- **Platform:** Linux (tested); the mechanism (renderer-side C++, no Linux-specific code path involved) is not platform-gated and is expected to reproduce on Windows/macOS/ChromeOS builds sharing the same `components/autofill` and `content/renderer` source not independently verified on those platforms in this pass.
- **Binary tested:** `/usr/bin/chromium` **147.0.7727.101**, stock Debian/Kali package (`chromium` `147.0.7727.101-1`, maintainer: Debian Chromium Team). Confirmed via `dpkg -s`/`file` that this is the unmodified distro package launcher, not a custom build **Note:** a newer packaged version
  (149.0.7827.114-1) is available in the Kali repo but was not independently re-tested — see Limits.
- **Source audited:** Chromium `main` commit **`d90fdef3ca61a075b5a36f413b61e75035ccc5a8`**. Re-verified against a same-day-later `main` fetch (`28c79d915cc052f2034eb1df9d3896a58986b839`, ~2 hours later) — byte-identical diff on
  every file this report cites, i.e. not already patched as of that re-fetch.

# Vulnerability Class / Category

Logic flaw / broken security-state invalidation: a security control that withholds a stored plaintext password from readable DOM state until a fresh user gesture is bypassed via a Back/Forward Cache restore, resulting in disclosure of the saved credential to same-origin page script with no fresh interaction. Not a memory-safety bug — a logic bug in state-machine / lifecycle-hook wiring.

**Proposed severity: Medium** "exposure of sensitive user information that an attacker can
exfiltrate," per Chromium's Severity Guidelines. This is deliberately *not* claimed as the
Low example "bypass requirement for a user gesture" (issue 256057): see the Impact Statement
for why the sensitive-data-exposure consequence places it in Medium, and the "Non-Qualifying
Categories" section for why it is not the bare-gesture-bypass Low bucket. It is also *not*
claimed as High/Critical a two-angle escalation investigation (cross-origin read;
memory-corruption chain) was performed and both are genuine dead ends (details in the Impact
Statement and in the attached `docs/research-inventory.md` item #12). Reporting the honest
Medium rather than an inflated severity that would be downgraded on triage.

# Detailed Technical Description

Chromium's password autofill does not put a saved password's real value into the DOM the
moment a matching login form is recognized at page load. Instead
(`components/autofill/content/renderer/password_autofill_agent.cc`):

1. `FillFieldAutomatically()` (line 2351) sets a **suggested value** only
   (`WebInputElement::SetSuggestedValue()`, not JS-readable) and registers the field with
   `PasswordValueGatekeeper::RegisterElement()` (line 2367) — with the code's own comment:
   *"Wait to fill until a user gesture occurs. This is to make sure that we do not fill in
   the DOM with a password until we believe the user is intentionally interacting with the
   page."*
2. `PasswordValueGatekeeper` (line 724) tracks one boolean, `was_user_gesture_seen_`.
   `RegisterElement()` reveals the real value immediately (`SetAutofillValue()`, JS-readable
   via `.value`) if the flag is already true, else queues the field. `OnUserGesture()` (line
   740) sets the flag **permanently** true and flushes every queued field. This is fed by
   `AutofillAgent::UserGestureObserved()` — a frame-wide, untargeted "a gesture happened
   somewhere in this frame" signal, driven ultimately by `LocalFrame::NotifyUserActivation()`
   (`third_party/blink/renderer/core/frame/local_frame.cc:2891`) calling
   `Client()->NotifyUserActivation()`.
3. The flag has **exactly one reset call site in the entire codebase** —
   `gatekeeper_.Reset()` inside `PasswordAutofillAgent::ReadyToCommitNavigation()` (line
   1589), guarded by `frame->GetWebFrame()->IsOutermostMainFrame()`, with the comment:
   *"This is a new navigation, so require a new user gesture before filling in passwords."*
   (Verified exhaustively: `grep -rn "was_user_gesture_seen_"` and
   `grep -rn "gatekeeper_"` across the entire fetched source tree — components/autofill,
   components/password_manager, third_party/blink/renderer/core/{dom,frame,html/forms,
   loader,exported}, content/renderer, content/public/renderer — return only the lines
   quoted above. Full transcript in
   `evidence/2026-07-05-gatekeeper-reset-path-source-trace.txt`.)
4. `ReadyToCommitNavigation()` is dispatched from `content/renderer/render_frame_impl.cc:4009`,
   inside `RenderFrameImpl::didStartProvisionalLoad()` — guarded by
   `DCHECK(!navigation_state->WasWithinSameDocument())` and immediately followed by
   `observer.DidCreateNewDocument()`. This fires only when a **brand-new Document** is being
   installed into the frame.
5. BFCache freeze/restore does not install a new Document — it resumes the exact same frozen
   one — and is dispatched through a **separate** renderer observer method:
   `RenderFrameImpl::DidSetPageLifecycleState(BFCacheStateChange)`
   (`render_frame_impl.cc:4352-4356`), declared as an independent virtual on
   `content::RenderFrameObserver` alongside (but distinct from) `ReadyToCommitNavigation`
   (`content/public/renderer/render_frame_observer.h:120,124`).
6. Neither `AutofillAgent`, `PasswordAutofillAgent`, nor `FormTracker` overrides
   `DidSetPageLifecycleState()` or `WillFreezePage()` anywhere (confirmed by exhaustive grep,
   zero hits).

**Net effect, proven by construction, not inference:** `was_user_gesture_seen_` can only be
cleared by a call chain that requires installing a new Document — which a BFCache restore,
by design, never does. Once true, it stays true across an unlimited number of BFCache round
trips on that document.

Separately confirmed: `history.back()`/`forward()`/`go()`
(`third_party/blink/renderer/core/frame/history.cc`) contain **zero** references to
activation/gesture state anywhere in the file, and `location.href` assignment
(`location.cc:330-334`) only *tags* the resulting navigation request with the current
activation state as metadata — it never gates whether the navigation itself proceeds. This
means the entire "navigate away, then navigate back" step can be driven by the page's own
script from a timer, with no user interaction required beyond the original incidental
gesture. (Source proof: `evidence/2026-07-05-history-navigation-not-gesture-gated.txt`.)

# Attack Preconditions

Minimal and, deliberately, not exotic:

1. A saved Chrome password exists for the origin (the normal, default outcome of using Chrome
   password saving on any site).
2. **One** incidental user gesture occurs anywhere on the page, at any time (a click to
   dismiss a cookie banner, focus the tab, follow any link — practically universal for any
   page a real user actually looks at).
3. The page is later restored from BFCache — which, as shown, the page's own script can
   trigger itself (navigate away, then `history.back()` from a timer) with **no further
   victim interaction**.
4. Attacker-controlled script executes in that page's context at some point (stored XSS, a
   compromised/malicious third-party script included on the page, or a malicious browser
   extension content script) — this is the only "delivery" precondition, and it is the same
   precondition any script-based Autofill/PII-exposure bug requires.

No admin/privileged access, no non-default flags, no experimental features, no out-of-date
browser required.

# Step-by-Step Reproduction

**Setup** (see attached `poc/` files):

1. Add a test credential via `chrome://password-manager/passwords` → "Add" → Website
   `http://127.0.0.1:8901`, Username `pocuser`, Password `PocPassw0rd789` → Save. (Any browser
   session is fine for this step; it does not need to be BFCache-eligible.)
2. Ensure the profile used for the actual test (`$CHROME_PROFILE`) has this credential in its
   `Login Data` SQLite store (verify: `sqlite3 "$CHROME_PROFILE/Default/Login Data"
   "SELECT origin_url, username_value FROM logins;"`). Close whatever browser session
   performed step 1 before proceeding (SQLite locking).

**Reproduction** (fully automated variant, `poc/attack_auto.html` + `poc/neutral_auto.html`,
`poc/run_full_credential_poc.sh`):

```bash
cd poc/
CHROME_PROFILE=/path/to/profile-with-saved-credential ./run_full_credential_poc.sh
```

This: (a) starts a local static+report server; (b) launches Chromium with **no**
`--remote-debugging-*`/CDP flag (required — CDP attachment disables BFCache); (c) sends
**one** real OS-level trusted click (`xdotool key Return`) on a benign button unrelated to
any form; (d) the page's own script then, via `setTimeout`, sets `location.href` to a
neutral page, and that page's own script, via another `setTimeout`, calls `history.back()` —
zero interaction beyond step (c); (e) on restore, the page's `pageshow` handler (seeing
`event.persisted === true`) creates a brand-new `<input type=password
autocomplete=current-password>` via `document.createElement`, and polls its `.value`.

**Observed result** (`evidence/2026-07-05-fully-automated-one-click-reveal.log`):

```
GET /report?event=click&hasBeenActive=true&...
GET /report?event=pagehide&persisted=true&...
GET /report?event=pageshow&persisted=true&hasBeenActive=true&...
GET /report?event=injected-form&reason=auto-bfcache-restore-timer&hasBeenActive=true&...
GET /report?event=poll-injected-value&value=PocPassw0rd789&checks=1&hasBeenActive=true&...
```

The real saved password (`PocPassw0rd789`) is present in `value=`, on the first poll
(`checks=1`), from a field that did not exist until after the BFCache restore, with no
interaction on the restored page.
