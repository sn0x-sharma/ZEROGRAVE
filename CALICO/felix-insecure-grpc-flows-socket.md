# FINDING-004: Felix Collector Insecure gRPC Unix Socket

**Status**: CONFIRMED (static analysis)
**Severity**: LOW
**Component**: felix/collector
**File**: `felix/collector/local/server.go` line 93
**CVE candidate**: Low priority

---

## Vulnerability Description

The Felix flow collector server creates an insecure gRPC server (no TLS, no authentication) on a Unix domain socket at `/var/run/calico/flows/flows.sock`.

## Vulnerable Code

From semgrep scan output and `felix/collector/local/server.go:93`:
```go
grpcServer: grpc.NewServer(),   // NO TLS, NO AUTH
```

Socket path: `/var/run/calico/flows/flows.sock` (inferred from standard Felix socket locations)

## Notes
- Felix runs as root on each node
- The socket is on the host filesystem (not in a pod volume)
- Access requires either root access or being in a group with socket access
- Standard deployment: only the calico-node DaemonSet pod accesses this socket
- Lower impact than goldmane (host-local, not network-reachable)

## Recommended Fix
Use Unix socket file permissions (0600) to restrict access to root only.
