# FINDING-003: Typha TLS Certificate Verification OR Logic — Weaker Than Documented

**Status**: CONFIRMED (static analysis)
**Severity**: LOW-MEDIUM
**Component**: typha
**File**: `typha/pkg/tlsutils/tlsutils.go` lines 94-97
**CVE candidate**: Possible (defense-in-depth / documentation mismatch)

---

## Vulnerability Description

The `CertificateVerifier` function in Typha uses OR logic when **both** `requiredCN` and `requiredURISAN` are configured. A peer certificate matching EITHER the required Common Name OR the required URI SAN is accepted — even if it doesn't satisfy both constraints. Operators configuring both fields may expect AND semantics (the certificate must have both), but the implementation uses OR.

## Vulnerable Code

```go
// typha/pkg/tlsutils/tlsutils.go lines 94-106
if requiredCN != "" && requiredURISAN != "" {
    if !requiredCNFound && !requiredURIFound {
        return errors.New("peer certificate does not have required CN or URI SAN")
    }
    // ^^^ only fails if NEITHER matches — passes if EITHER matches
} else if requiredCN != "" {
    if !requiredCNFound {
        return errors.New("peer certificate does not have required CN")
    }
} else if requiredURISAN != "" {
    if !requiredURIFound {
        return errors.New("peer certificate does not have required URI SAN")
    }
}
```

When both `requiredCN` and `requiredURISAN` are non-empty, the logic is:
```
REJECT if (!requiredCNFound AND !requiredURIFound)
= ACCEPT if (requiredCNFound OR requiredURIFound)
```

Expected AND semantics would be:
```
ACCEPT only if (requiredCNFound AND requiredURIFound)
```

## How It's Configured

From `felix/config/config_params.go`:
```go
// "either TyphaCN or TyphaURISAN may be left unset"
TyphaCN     string `config:"string;;local"`
TyphaURISAN string `config:"string;;local"`
```

Felix validation requires at least one to be set. The documentation says "one of" (OR) which is consistent with the implementation. However, an operator who sets BOTH values expecting stronger AND guarantees would be surprised.

## Attack Scenario

1. Operator configures Felix with both `TyphaCN = "typha-server"` AND `TyphaURISAN = "spiffe://cluster.local/ns/calico/sa/typha"`
2. Operator's intent: Typha must have BOTH the correct CN and the correct SPIFFE identity
3. An attacker who has compromised a CA-signed certificate with:
   - CN = "typha-server" (matching TyphaCN) but wrong URI SAN, OR
   - URI SAN matching TyphaURISAN but wrong CN
4. The attacker's certificate PASSES validation even though it doesn't satisfy both constraints
5. Result: The attacker can establish an mTLS connection to Typha and receive all Kubernetes resource updates (ConfigMaps, NetworkPolicies, etc.) streamed to Felix

## Severity Notes
- The configuration documentation says "one of" which is consistent with OR behavior
- This is more of a "documentation is ambiguous leading to misconfiguration" issue
- Real exploitability requires: having a CA-signed cert with one-but-not-both matching fields
- This is a defense-in-depth gap rather than a direct authentication bypass

## Recommended Fix
Add documentation that explicitly states OR semantics when both are set. Alternatively, change to AND semantics with a deprecation path:
```go
if requiredCN != "" && requiredURISAN != "" {
    if !requiredCNFound || !requiredURIFound {  // AND semantics
        return errors.New("peer certificate does not have required CN and URI SAN")
    }
}
```
