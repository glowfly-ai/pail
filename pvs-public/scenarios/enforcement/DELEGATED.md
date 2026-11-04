# Enforcement — delegated cases

## TC-ENF-03 — forged gRPC `ReportDecision(PERMIT)`

The scenario verb vocabulary (`core/model.py:V2_VERBS`) covers ROS-plane rogue
actors (`rogue_publish` / `rogue_subscribe`) but not a forged **gRPC control-plane**
call. A forged `ReportDecision(PERMIT)` is defeated at the transport layer (mTLS),
before any RPC method runs — so it is proven where it lives, in the SUT's own Go
package, not faked as a scenario PASS.

**Delegated to (already implemented + passing):**
`services/pail_services_go/internal/grpcauth/grpcauth_test.go`

- `TestMutualTLSRejectsClientWithoutCert` — a plaintext attacker (the as-built
  `InsecureChannelCredentials` forger) is rejected before `ReportDecision`.
- `TestMutualTLSRejectsForeignCA` — an attacker holding a cert from a different
  CA is rejected (mutual auth, not just server auth).
- `TestMutualTLSAcceptsAuthorizedClient` — positive control: the CA-signed
  client succeeds, so the reject cases prove enforcement, not a broken server.

Evidence (docker `golang:1.21`, `go test ./internal/grpcauth/ -run TestMutualTLS`):
all three PASS. The guarantee lives in `grpcauth.ServerTLS` (`ClientAuth:
tls.RequireAndVerifyClientCert`) with fail-secure default (`PAIL_GRPC_TLS`=on
unless explicitly "off").

This mirrors the TC-TI-05 (`ERR_CLOCK`) delegation to Go unit tests: cases that
cannot be expressed honestly in the timeline DSL are proven at the layer where
they actually live, never faked as a scenario PASS.
