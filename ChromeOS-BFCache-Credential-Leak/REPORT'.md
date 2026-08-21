# Title

Password Manager's "wait for a fresh user gesture" gate never resets across a Back/Forward Cache restore, letting a saved password reveal into script-readable `element.value` with no interaction on the restored page

# Summary

Chromium's password autofill deliberately withholds a saved password's real value from
`element.value` until it believes the user has freshly, intentionally interacted with the
page (`PasswordAutofillAgent::PasswordValueGatekeeper`). The flag this gate depends on is
reset in exactly one place, tied to a brand-new document being committed
(`ReadyToCommitNavigation`) — but a Back/Forward Cache (BFCache) restore resumes the same
frozen document instead of committing a new one, and notifies observers through a completely
separate channel (`DidSetPageLifecycleState`) that this component never listens to. The
result: once any single, unrelated gesture has ever occurred on a page, the gate stays open
forever across BFCache round trips. I built an end-to-end PoC that adds a real saved
password, gets one incidental click, then has the page navigate itself away and immediately
call `history.back()` — with **zero further interaction** — and confirmed the real password
lands in a freshly-created password field's `.value`, readable by any script on that origin,
on the very first check after the restore. Reproduced 7/7 times across three variants with
two different credentials.

# Affected Version(s)

- **Product:** Chromium / Google Chrome
- **Platform:** Linux (tested); the mechanism (renderer-side C++, no Linux-specific code
  path involved) is not platform-gated and is expected to reproduce on Windows/macOS/ChromeOS
  builds sharing the same `components/autofill` and `content/renderer` source — not
  independently verified on those platforms in this pass.
- **Binary tested:** `/usr/bin/chromium` **147.0.7727.101**, stock Debian/Kali package
  (`chromium` `147.0.7727.101-1`, maintainer: Debian Chromium Team). Confirmed via
  `dpkg -s`/`file` that this is the unmodified distro package launcher, not a custom build
  (see `evidence/2026-07-05-build-verification.txt`). **Note:** a newer packaged version
  (149.0.7827.114-1) is available in the Kali repo but was not independently re-tested —
  see Limits.
- **Source audited:** Chromium `main` commit **`d90fdef3ca61a075b5a36f413b61e75035ccc5a8`**
  (2026-07-05). Re-verified against a same-day-later `main` fetch
  (`28c79d915cc052f2034eb1df9d3896a58986b839`, ~2 hours later) — byte-identical diff on
  every file this report cites (see `evidence/2026-07-05-code-drift-check.txt`), i.e. not
  already patched as of that re-fetch.

# Vulnerability Class / Category

Logic flaw / broken security-state invalidation: a security control that withholds a stored
plaintext password from readable DOM state until a fresh user gesture is bypassed via a
Back/Forward Cache restore, resulting in disclosure of the saved credential to same-origin
page script with no fresh interaction. Not a memory-safety bug — a logic bug in
state-machine / lifecycle-hook wiring.

**Proposed severity: Medium** — "exposure of sensitive user information that an attacker can
exfiltrate," per Chromium's Severity Guidelines. This is deliberately *not* claimed as the
Low example "bypass requirement for a user gesture" (issue 256057): see the Impact Statement
for why the sensitive-data-exposure consequence places it in Medium, and the "Non-Qualifying
Categories" section for why it is not the bare-gesture-bypass Low bucket. It is also *not*
claimed as High/Critical — a two-angle escalation investigation (cross-origin read;
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

# Proof of Concept — Files to Attach

- `poc/run_poc.sh`, `poc/pageA.html`, `poc/pageB.html` — mechanism-only demo (public
  `navigator.userActivation.hasBeenActive` signal, no credential needed).
- `poc/run_full_credential_poc.sh`, `poc/attack.html`, `poc/neutral.html`,
  `poc/login.html`, `poc/server.py` — full end-to-end demo with a real saved credential,
  manual keyboard-driven navigation (clean, step-by-step reproduction).
- `poc/attack_auto.html`, `poc/neutral_auto.html` — fully-automated escalation: one click,
  everything else script-driven (`location.href` + `history.back()` from timers).

# Supporting Evidence — Files to Attach

- `evidence/2026-07-05-local-verification.txt` — mechanism-only proof (public activation
  signal survives BFCache restore).
- `evidence/2026-07-05-end-to-end-real-password-reveal.log` — full end-to-end proof, manual
  navigation, real credential `PocPassw0rd789`.
- `evidence/2026-07-05-fully-automated-one-click-reveal.log` — same, fully automated
  navigation, one click only.
- `evidence/2026-07-05-gatekeeper-reset-path-source-trace.txt` — exhaustive source trace:
  every reference to `was_user_gesture_seen_` and every call site touching it, cross-referenced
  against `render_frame_impl.cc`'s actual observer dispatch.
- `evidence/2026-07-05-history-navigation-not-gesture-gated.txt` — source proof that
  `history.back()`/`location.href` are not gesture-gated.
- `evidence/2026-07-05-code-drift-check.txt` — confirms the vulnerable code is unchanged
  between the pinned commit and a same-day-later re-fetch of `main`.
- `evidence/2026-07-05-build-verification.txt` — exact binary version, package provenance,
  exact flags used (none security-relevant) in every reproduction.
- `evidence/reproducibility-runs.log` — 7/7 successful runs across 3 variants (3× fully
  automated, 3× manual, 1× with a second, independently different credential
  `DifferentSecret_99Zz` on a second origin, ruling out a hardcoded-value artifact).
- `docs/dedup-check.md` — prior-art search log (8 queries, no matching public report found;
  direct Chromium issue-tracker content fetch was inconclusive due to its JS-rendered UI, not
  a confirmed negative — flagged honestly).
- `docs/research-inventory.md` — full audit trail of adjacent surfaces checked during this
  investigation (UAF hypothesis in `FormTracker`/`WebFormElementObserver`, ruled out;
  cross-frame gesture-credit propagation, real but lower-impact; credit-card/address
  autofill, not applicable — no equivalent gate exists; WebOTP, not reachable on Linux
  desktop; WebAuthn `create()`/`get({mediation:'immediate'})`, same root-cause class but
  time-windowed and defense-in-depth only, not dynamically reproduced). **Item #12** is the
  full Medium→High/Critical escalation investigation (cross-origin read and memory-corruption
  angles, both dead ends, every claim cited to `file:line`).

# Impact Statement

**Proposed severity: Medium** — exposure of sensitive user information (a stored plaintext
credential) that an attacker can exfiltrate.

Demonstrated, not speculative: a real saved password, added through Chrome's own password
manager UI, was extracted into a script-readable `element.value` with **zero** user
interaction beyond one incidental click that had nothing to do with the credential or the
form it later appeared in (and, in the fully-automated variant, with the navigation itself
script-driven, so one incidental click *anywhere ever* is the whole precondition). This is a
complete break of the specific security invariant the `PasswordValueGatekeeper` exists to
enforce (*"we do not fill in the DOM with a password until we believe the user is
intentionally interacting with the page"*), reachable from any script executing in the
credential's origin — stored XSS, a compromised or malicious first- or third-party script on
the page, or a malicious browser-extension content script. Combined with a trivial
`fetch()`/`sendBeacon()` (the same mechanism this PoC's own reporter uses, pointed at an
attacker endpoint), it is a silent, no-prompt, no-visible-UI-change credential-exfiltration
primitive against any site with a saved Chrome password. Reproduced 7/7 times with two
independently different credentials — deterministic, not a timing fluke or harness artifact.

**Why Medium and not the Low gesture-bypass bucket.** Chromium lists a bare *"bypass
requirement for a user gesture"* as a Low (S3) example (issue 256057). This is materially
different: its direct and *only* consequence is the exposure of a stored plaintext credential.
The gatekeeper exists precisely to keep the saved password out of readable DOM state against
*passive* same-origin script when the user never interacts with the login form; this bug
defeats exactly that protection, enabling harvest of the saved passwords of users who visit a
compromised page and leave without ever typing or touching the form. That sensitive-data
consequence is what places it in Medium. (Honest note for triage: one could argue Low on the
grounds that exfiltration presupposes same-origin script execution — but the protection this
bug removes is specifically the one guarding the password against *passive* same-origin
script, so removing it is a real, concrete weakening of the credential-protection model, not a
no-op given XSS.)

**Escalation investigated — genuinely does not reach High/Critical.** I specifically checked
whether this yields a *cross-origin* read (the High bar: "read cross-origin data") or a
memory-corruption chain (Critical). Both are dead ends, and I am reporting Medium rather than
inflating:

- *No cross-origin read.* Two independent, source-grounded barriers. (1) The password
  gate-open (`PasswordValueGatekeeper::OnUserGesture()` ← `AutofillAgent::UserGestureObserved()`
  ← `Client()->NotifyUserActivation()`) is fired only by the frame that *directly* received
  the gesture — `Client()->NotifyUserActivation()` has exactly one caller,
  `third_party/blink/renderer/core/frame/local_frame.cc:2896`; the cross-frame activation
  propagation (`Frame::NotifyUserActivationInFrame`, `frame.cc:971-986`) only sets the raw
  activation *bit* and never fires that callback, so an attacker cannot open a different
  (cross-origin) frame's gate by riding propagation. (2) Even a directly-opened victim gate
  reveals the password into the *victim* frame's DOM, which the same-origin policy blocks any
  cross-origin embedder from reading, and the plaintext is delivered by the browser only into
  the credential-owning frame's own renderer (`PasswordAutofillAgent` is per-`RenderFrame`
  with a per-frame associated mojo receiver, `password_autofill_agent.h:95,666`) — a
  cross-origin frame is a separate process under Site Isolation and never receives the bytes.
  The cross-tab variant fails identically at barrier (2).
- *No memory-corruption chain.* No autofill component subscribes to the BFCache lifecycle
  hooks; the gatekeeper holds `FieldRendererId`s, not raw pointers; `FormTracker` teardown is
  two-phase (independently ruled safe). A time-boxed look at `render_frame_impl.cc`'s
  freeze/resume + teardown surface found no source-grounded lead (only a generic,
  whole-observer-system `kAllowReentrancyUntriaged` TODO, `crbug.com/484371187`, which I will
  not inflate into a corruption claim).

Full escalation analysis, every claim cited to `file:line`, is in the attached
`docs/research-inventory.md` item #12.

# Why This Is Not Excluded Under Standard Non-Qualifying Categories

- **Not "exceedingly unlikely user interaction."** The interaction required is one incidental
  click, keypress, or tap anywhere on the page, ever — not a specific, unusual, or
  attacker-directed action. It is, if anything, *less* interaction than almost any other
  client-side bug class requires (most require the victim to click something the attacker
  chose; this requires the victim to have clicked anything, ever, unrelated to the attack).
- **Not dependent on an out-of-date or unpatched browser.** Reproduced on 147.0.7727.101, and
  the exact vulnerable source is confirmed unchanged in `main` as of a same-day re-fetch
  (`28c79d915cc052f2034eb1df9d3896a58986b839`) — this is current, not historical, behavior as
  far as this investigation could verify.
- **Not a documented/intended behavior.** The code's own comments (*"we do not fill in the
  DOM with a password until we believe the user is intentionally interacting with the
  page"*, *"this is a new navigation, so require a new user gesture"*) explicitly state the
  invariant this bug defeats — the developers' own stated intent is violated, not honored.

# What This Report Does NOT Claim (Limits)

- **Not claimed as High or Critical.** The impact is confined to the credential's own origin
  (readable only by same-origin script; no cross-origin read, per the two barriers in the
  Impact Statement) and involves no memory corruption. Reported as Medium. The escalation
  angles were genuinely investigated (`docs/research-inventory.md` item #12), not dismissed.
- Tested against one local, disposable Chromium profile and a local test harness — not
  against a hosted/production site. The mechanism traced is generic (default code path, no
  site-specific configuration), so this is not expected to change the result, but it was not
  independently confirmed against a real production origin.
- Not independently re-tested against the newer 149.0.7827.114 package available in the Kali
  repo (only 147.0.7727.101 was installed/tested) — the source-level code-drift check against
  upstream `main` is the more authoritative signal that this is not yet fixed, but the
  specific newer Debian/Kali build was not separately run.
- Direct Chromium issue-tracker search (issues.chromium.org) could not be performed
  exhaustively from this environment — its UI is a JS-rendered SPA that automated fetching
  could not render, so the tracker-search leg of the dedup check is inconclusive rather than
  a confirmed "no prior report." A triager with tracker access should still run an internal
  search for `PasswordValueGatekeeper`, `was_user_gesture_seen_`, and
  `component:UI>Browser>Autofill BFCache` before/during triage.
- Not tested on Windows, macOS, Android, or ChromeOS — the source path involved is
  cross-platform C++ with no `#if BUILDFLAG(IS_ANDROID)`/platform gate around it (unlike, for
  contrast, WebOTP, which is confirmed Android-only in this codebase), so the same result is
  expected on other desktop platforms, but this was not independently verified.
- Did not build a full ASan/instrumented Chromium or use a virtual-authenticator CDP session
  to dynamically confirm the adjacent WebAuthn finding described in
  `docs/research-inventory.md` item #11 (same root-cause class, `ConsumeTransientUserActivation`
  for cross-origin-iframe `create()` and `HasTransientUserActivation` for
  `mediation:'immediate'` `get()`) — that finding is source-confirmed only, flagged as lower
  severity (native authenticator ceremony still gates the actually-sensitive step), and not
  part of this report's core claim.
- The credential used throughout (`pocuser`/`PocPassw0rd789`, and the second confirmation
  credential `second_test_user_xyz`/`DifferentSecret_99Zz`) is a test credential I created
  myself, on my own locally-hosted test server (`http://127.0.0.1:8901` / `:8902`), in a
  disposable local Chromium profile under my own control. No real account, no other user's
  data, and no production/third-party service was touched at any point in this
  investigation.

# Suggested Fix Direction

- Reset `PasswordValueGatekeeper` (and any other frame-scoped "has this frame ever seen a
  gesture" state gating an Autofill/PII reveal) on BFCache restore, not only on
  `ReadyToCommitNavigation`. `RenderFrameObserver::DidSetPageLifecycleState` already exists
  as the correct hook for this — wire `PasswordAutofillAgent`'s reset into it.
- More generally: audit every security-relevant "has a gesture occurred" check in
  Autofill/Password Manager code for whether it is invalidated on BFCache restore
  specifically, not just on ordinary navigation. This investigation independently found the
  same architectural gap recurring in WebAuthn's transient-activation checks
  (`docs/research-inventory.md` item #11) — this suggests a reusable pattern check across the
  codebase, not a single one-off fix.

# Attached Files

See `ATTACHMENTS-MANIFEST.txt` for the exact list of relative paths to upload.
