# submit_plan (Go)

This command submits an ActionPlan to a running `pail-services` gRPC server.

## Generate protos
```bash
cd PAIL/services/pail_services_go
make proto
```

## Run
```bash
go run ./cmd/submit_plan --addr 127.0.0.1:50051 --robot robot-1 --plan demo --target 880123
```
