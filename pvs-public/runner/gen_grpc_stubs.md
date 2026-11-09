# Generate the Python gRPC stubs for the PVS live runner

The six generated modules under `pvs/runner/live/` (`pail_pb2*.py`, `token_service_pb2*.py`,
`operator_service_pb2*.py`) are **bundled with the public tree** so a recipient can run the live runner without a protobuf toolchain. They are
regenerated from `proto/*.proto` with a pinned toolchain whenever a proto changes, and the
release gate proves that the bundled files
are byte-identical to a fresh generation, import, serve one RPC, and carry the same descriptor
(every message, field number, type, label, enum value, service and method) as the `.proto`
sources.

## Pinned toolchain

| package | version |
|---|---|
| grpcio | 1.83.0 |
| grpcio-tools | 1.83.0 |
| protobuf | 7.35.1 |

Install exactly these (for example into `pvs/.venv`):

```bash
python3 -m pip install "grpcio==1.83.0" "grpcio-tools==1.83.0" "protobuf==7.35.1"
```

## Generate (from the repository root)

```bash
python3 pvs/runner/gen_grpc_stubs.py
```

The script refuses a toolchain other than the pinned one, runs `grpc_tools.protoc -I ./proto --python_out
--grpc_python_out` over the three protos and prepends the license header every public file carries (the
generated code itself is not edited). `--out DIR` generates elsewhere; the release gate uses that to compare a
fresh generation byte for byte with the bundled files.

The generated modules import each other by bare module name (`import pail_pb2`); the live runner
adds `pvs/runner/live` to `sys.path` before importing them.

## When to regenerate

- any change under `proto/` (the contract test fails until the stubs match again);
- a toolchain bump (change the table above and regenerate in the same change).

Do not edit the generated files by hand.
