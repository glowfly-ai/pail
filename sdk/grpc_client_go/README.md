# Go gRPC client — submit an ActionPlan

A minimal `SubmitActionPlan` client. Generated protobuf code is not shipped.
This is a **plaintext development example**, not the mTLS client used by the
public E2E. Do not disable production TLS to connect this example.

## Prerequisites and generation

Install Go, `protoc`, `protoc-gen-go` v1.33.0 and `protoc-gen-go-grpc` v1.3.0;
make both plugins available on PATH. Run **from this directory**:

```sh
# Public tree: sdk/grpc_client_go -> sdk/proto
PROTO_DIR=../proto
# Internal developer tree only: use PROTO_DIR=../../proto instead.
protoc -I "$PROTO_DIR" \
  --go_out=. --go_opt=module=github.com/glowfly/pail/services \
  --go-grpc_out=. --go-grpc_opt=module=github.com/glowfly/pail/services \
  "$PROTO_DIR/pail.proto"
go build -o /tmp/submit_plan ./cmd/submit_plan
```

The module options strip the proto's `go_package` prefix so files land under
`proto/pailv1/`. Omitting them creates a different directory/import layout.

## Run against an explicitly isolated development listener

```sh
/tmp/submit_plan --addr 127.0.0.1:50051 --robot robot-01 --plan demo --target 880123
```

The robot and target must match the prepared deployment. A reachable server may
correctly reject a plan because its identity, policy or context is not authorized.
The client prints the structured denial when one is returned.

This client uses `grpc.WithInsecure()` and cannot connect directly to an mTLS-only
listener (`PAIL_GRPC_TLS=on`). For an authenticated end-to-end run without creating
a plaintext listener, use the public repository's `e2e/run_e2e.sh` or
`examples/tb3/run.py`; those paths provision and use mTLS.
