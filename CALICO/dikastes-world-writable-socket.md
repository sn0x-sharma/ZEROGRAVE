## Dikastes World-Writable Unix Socket Unauthenticated Policy Authorization Server

**Status**: CONFIRMED (static analysis)
**Severity**: MEDIUM-HIGH (context-dependent)
**Component**: app-policy / dikastes
**File**: `app-policy/pkg/dikastes/dikastes.go` lines 43, 65-66, 72

---

## Vulnerability Description

The Dikastes authorization sidecar creates a Unix domain socket with `0777` permissions and starts a gRPC server with **no TLS and no authentication**. Any process that can access the socket can make unauthenticated calls to the Envoy external authorization server.

## Vulnerable Code

```go
// app-policy/pkg/dikastes/dikastes.go
DefaultListenPath = "/var/run/dikastes/dikastes.sock"

func RunServer(ctx context.Context, listenPath string, nodeAgentPath string) error {
    lis, err := net.Listen("unix", listenPath)
    ...
    if err := os.Chmod(listenPath, 0o777); err != nil {      // <-- WORLD WRITABLE
        logrus.WithError(err).Fatal("Unable to set write permission on socket.")
    }
    gs := grpc.NewServer()                                     // <-- NO TLS, NO AUTH
    storeManager := policystore.NewPolicyStoreManager()
    NewCheckServer(ctx, gs, storeManager)
    ...
}
```

## What the gRPC Server Exposes

Dikastes implements the Envoy external authorization protocol (`envoy.service.auth.v3.Authorization`). The `Check()` RPC:
- Reads WorkloadEndpoint and network policy rules from the PolicyStore
- Evaluates whether a given connection should be ALLOWED or DENIED
- Returns the verdict to Envoy

## Attack Scenario

Within a Kubernetes pod running Calico App Layer Policy (ALP):

1. A compromised process in a container that has the `/var/run/dikastes` volume mounted can connect to `dikastes.sock`
2. Because the socket is 0777 and there is no authentication, the connection is accepted immediately
3. The attacker can call `Check()` with crafted `CheckRequest` messages:
   - **Policy enumeration**: discover what network policy rules are in effect for this workload
   - **Authorization oracle**: test whether arbitrary connection tuples would be ALLOWED or DENIED

## Deployment Context

From `manifests/alp/istio-inject-configmap-1.3.2.yaml`, the `dikastes-sock` emptyDir volume is mounted in:
- `istio-proxy` (Envoy) — intended consumer
- `dikastes` sidecar — socket owner

The application container does NOT get the volume mounted by default in standard Istio injection templates.

**However**, the 0777 chmod is a security design smell that indicates:
1. The code assumes no filesystem-level access control is needed
2. Any future deployment that accidentally mounts the socket in an app container would be immediately exploitable
3. If `shareProcessNamespace: true` is set on the pod, processes in any container can access other containers' file descriptors

## Impact
- **Confidentiality**: Enumeration of Calico network policy rules for the workload
- **Integrity**: N/A — Check() is read-only from the perspective of policy decisions
- **Availability**: Flooding the socket could cause a DoS against the authorization server

## Severity Notes
- Lower severity than FINDING-001 because the socket is not directly network-reachable
- Impact is primarily information disclosure (policy enumeration)
- Upgrading to Critical if a container escape allows reaching the socket from a non-mounted container

## Recommended Fix
1. Remove `os.Chmod(listenPath, 0o777)` — use appropriate file permissions (0600 or 0660)
2. Add gRPC authentication (even a shared secret) on the Unix socket
3. Document which container is the intended authorized consumer
