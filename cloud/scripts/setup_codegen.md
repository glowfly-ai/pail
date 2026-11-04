# Proto codegen setup (Go)

Install protoc (macOS):
```bash
brew install protobuf
protoc --version
```

Install Go plugins:
```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# ensure in PATH:
export PATH="$PATH:$(go env GOPATH)/bin"
```

Generate:
```bash
cd PAIL/services/pail_services_go
make proto
```
