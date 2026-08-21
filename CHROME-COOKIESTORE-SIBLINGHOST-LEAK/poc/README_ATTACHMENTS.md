# poc/ — which PoC to file for Bug 03

## ✅ FILE THIS (claimed vector — confirmed)
- `cookiestore_xport_poc.html`
  Single self-contained PoC for the CONFIRMED vector:
  `cookieStore.addEventListener('change')` fires CROSS-PORT. The listener is
  attached BEFORE the cookie is set, so it proves the push EVENT (not a read).
  Verified on Chromium + Firefox. Run: serve poc/ on two ports, open the lower one.
- `document_vector_repro.py`  — deterministic automated reproduction of the same vector.

## ❌ DO NOT FILE (non-novel getAll() read — NOT claimed)
- `DO_NOT_FILE_vectorA_exploit.html`
- `DO_NOT_FILE_vectorA_minimal_exploit.html`
  These demonstrate `cookieStore.getAll()` cross-port — which is the SAME as
  `document.cookie` (RFC 6265 port-agnostic) and is EXPLICITLY NOT CLAIMED in the
  reports. Kept for reference only. Attaching them contradicts the Medium reports.

## Server PoCs (support files, not primary attachments)
- `chain3_persistent_harvest.js`, `server.js`, `server_twoport.js` — broader test
  servers. The SW `cookiechange` persistent variant in chain3 is NOT claimed
  (background-SW delivery unverified).
