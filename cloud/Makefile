# ha_replication.proto 는 묶음 C(비공개) — 공개 트리에는 없으므로 wildcard 로 있을 때만 생성한다.
# .proto 의 위치는 트리마다 다르다 — 내부는 ../../proto, 공개 스냅숏은 ../sdk/proto.
# 기본값이 한쪽에서만 맞으므로 아래 proto 타깃이 존재를 먼저 검사한다.
PROTO_DIR?=../../proto
OUT_PROTO?=.
MODULE?=github.com/glowfly/pail/services
BUILD_TAGS?=pail_generated

.PHONY: proto
proto:
	@echo "Generate Go code from protos (requires protoc + protoc-gen-go + protoc-gen-go-grpc)"
	@test -d "$(PROTO_DIR)" || { \
	  echo "PROTO_DIR=$(PROTO_DIR) does not exist; select the directory containing the .proto files."; \
	  echo "  Public snapshot: make proto PROTO_DIR=../sdk/proto"; exit 1; }
	@command -v protoc >/dev/null || { \
	  echo "protoc is missing; install protoc, protoc-gen-go and protoc-gen-go-grpc first."; exit 1; }
	mkdir -p $(OUT_PROTO)
	protoc -I $(PROTO_DIR) \
		--go_out=$(OUT_PROTO) --go_opt=module=$(MODULE) \
		--go-grpc_out=$(OUT_PROTO) --go-grpc_opt=module=$(MODULE) \
		$(PROTO_DIR)/pail.proto $(PROTO_DIR)/token_service.proto $(PROTO_DIR)/operator_service.proto $(PROTO_DIR)/agent_relay.proto $(PROTO_DIR)/robot_ops_service.proto $(wildcard $(PROTO_DIR)/ha_replication.proto)

# EC-2 (EUC D2): the build identifies itself. Dockerfile.pail_services_go passes
# -X flags for internal/buildinfo (Version, GitSHA, SBOMSHA256); a bare `make
# build` leaves them empty and the binary says `-` in those slots — visibly.
BUILD_LDFLAGS ?=

.PHONY: build build-core build-issuer
build: build-core

build-issuer:
	@test -d issuer/cmd/pail_cloud || { echo "Issuer source is private. Use the evaluation image; see RELEASE.md."; exit 2; }
	# Force module mode so missing go.sum entries can be resolved during build.
	go build -mod=mod -tags "$(BUILD_TAGS)" -ldflags "$(BUILD_LDFLAGS)" -o bin/pail_services ./issuer/cmd/pail_services
	go build -mod=mod -tags "$(BUILD_TAGS)" -ldflags "$(BUILD_LDFLAGS)" -o bin/pail_cloud ./issuer/cmd/pail_cloud

build-core:
	go build -mod=readonly -tags "$(BUILD_TAGS)" -ldflags "$(BUILD_LDFLAGS)" -o bin/pail_robot_agent ./cmd/pail_robot_agent
	# process 1 of the single-host split profile (cloud + robot agent in one container); no dependency outside the standard library
	CGO_ENABLED=0 go build -mod=readonly -o bin/pail_split ./cmd/pail_split
	go build -mod=mod -tags "$(BUILD_TAGS)" -ldflags "$(BUILD_LDFLAGS)" -o bin/submit_plan ./cmd/submit_plan
	go build -mod=mod -tags "$(BUILD_TAGS)" -ldflags "$(BUILD_LDFLAGS)" -o bin/pail_telemetryd ./cmd/pail_telemetryd
