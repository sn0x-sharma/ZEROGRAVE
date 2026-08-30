# FINDING-001: Goldmane gRPC Server Optional TLS — Unauthenticated Flow Injection / Data Exfiltration

**Status**: CONFIRMED (static analysis)
**Severity**: HIGH
**Component**: goldmane
**File**: `goldmane/pkg/daemon/daemon.go` lines 112-122, 214-224
**CVE candidate**: Yes

---

## Vulnerability Description

The Goldmane flow aggregation daemon starts its gRPC server (default port 443, TCP) with TLS/mTLS **conditionally** — only when both `SERVER_CERT_PATH` and `SERVER_KEY_PATH` environment variables are set. If either is empty (the zero-value for Go strings), the server starts **without any authentication or transport security**.

## Vulnerable Code

```go
// goldmane/pkg/daemon/daemon.go lines 112-122
func newGRPCServer(cfg *Config) (*grpc.Server, error) {
    opts := []grpc.ServerOption{}
    if cfg.ServerCertPath != "" && cfg.ServerKeyPath != "" {  // <-- TLS is OPTIONAL
        tlsCfg, err := calicotls.NewMutualTLSConfig(cfg.ServerCertPath, cfg.ServerKeyPath, cfg.CACertPath)
        if err != nil {
            return nil, err
        }
        creds := credentials.NewTLS(tlsCfg)
        opts = append(opts, grpc.Creds(creds))
    }
    return grpc.NewServer(opts...), nil  // <-- starts with NO TLS if paths unset
}

// lines 214-224 — listens on TCP port 443 (0.0.0.0)
lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Port))
```

Default config:
```go
Port           int    `envconfig:"PORT"            default:"443"`
ServerCertPath string `envconfig:"SERVER_CERT_PATH"`  // default: ""
ServerKeyPath  string `envconfig:"SERVER_KEY_PATH"`   // default: ""
```

## Attack Scenario

If Goldmane is deployed without configuring `SERVER_CERT_PATH`/`SERVER_KEY_PATH` (e.g. a misconfigured or stripped-down deployment, a dev/staging cluster, or an operator that forgets the env vars), any attacker who can reach port 443 on the Goldmane pod/service can:

### 1. Inject Fake Flow Data (FlowCollector gRPC service)
- Connect to `goldmane.FlowCollector/Connect` without any credentials
- Stream crafted `FlowResult` messages with forged source/destination IPs, ports, policies
- This corrupts the flow aggregation store, poisoning security dashboards, alerting, and threat detection in Calico Cloud/Enterprise

### 2. Exfiltrate Real Network Flow Data (Flows gRPC service)
- Call `goldmane.Flows/List` or `goldmane.Flows/Stream` without credentials
- Retrieve all historical and live flow data — which connections traversed the cluster, which were ALLOWED/DENIED, which pods/services communicated
- This is a full network observability bypass — all connections in the cluster are visible

### 3. Exfiltrate Statistics (Statistics gRPC service)
- Call `goldmane.Statistics/List` for packet-count time-series data

## Flow Data Sensitivity
Each `proto.Flow` message contains:
- Source IP, Destination IP
- Source port, destination port
- Protocol
- Policy name and action (ALLOW/DENY)
- Namespace, pod name, workload identity
- Byte and packet counts

This is highly sensitive in multi-tenant environments — flow data exposes the full network topology.

## Impact
- **Integrity**: Attacker injects fake flows → corrupts security analytics, generates false positives/negatives, invalidates audit logs
- **Confidentiality**: Attacker reads all flows → full network topology disclosure, reveals which pods communicate with which services
- **Availability**: Flood the FlowCollector with millions of fake flows → OOM the goldmane process

## Severity Justification
- CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = **9.8 Critical** (when TLS not configured)
- CVSS 3.1: AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H = **8.1 High** (configuration-dependent)

## Notes on Exploitability
- In standard Calico Enterprise/Cloud deployments, TLS IS configured via the operator
- In default OSS Calico deployments, Goldmane may not be deployed or may be deployed without certs
- The risk is highest in: dev/staging clusters, operator misconfiguration, manual deployments
- The fact that TLS is optional (not enforced) is the design flaw — a hardened default would reject startup if certs are not provided

## Proof of Concept (static)
```go
// With TLS not configured, any process can connect:
conn, err := grpc.Dial("goldmane:443", grpc.WithInsecure())
client := proto.NewFlowCollectorClient(conn)
stream, _ := client.Connect(context.Background())
stream.Send(&proto.FlowResult{
    Flow: &proto.Flow{
        SourceIp: "10.0.0.1",
        DestIp:   "10.0.0.2",
        // ... forged flow data
    },
})
```

## Recommended Fix
Enforce TLS configuration at startup. If cert paths are not set, fail fast:
```go
func newGRPCServer(cfg *Config) (*grpc.Server, error) {
    if cfg.ServerCertPath == "" || cfg.ServerKeyPath == "" {
        return nil, fmt.Errorf("SERVER_CERT_PATH and SERVER_KEY_PATH must be set")
    }
    tlsCfg, err := calicotls.NewMutualTLSConfig(...)
    ...
}
```
