# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
# Context: public repository root. No ROS or private build image is required.
ARG RUST_IMAGE=rust:1-trixie@sha256:223cc32ddca8f3ee90c436dbc94b6b5f052ea7f9653c5201e9612f08ad7d21b8
ARG GO_IMAGE=golang:1.27.4-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d
FROM ${RUST_IMAGE} AS build-base
ENV CARGO_BUILD_JOBS=2 CMAKE_BUILD_PARALLEL_LEVEL=2
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake pkg-config libprotobuf-dev protobuf-compiler libsodium-dev libyaml-cpp-dev \
    libudev-dev ca-certificates git python3 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY examples/common/collect_cargo_licenses.py /collect_cargo_licenses.py
COPY examples/common/license-notices /license-notices
FROM build-base AS upstream-builder
ARG MICRODUCK_COMMIT=942e58e3aa6dbb28e7037203fff11866122c7567
RUN git init /upstream && cd /upstream && git remote add origin https://github.com/pollen-robotics/microduck.git \
    && git fetch --depth 1 origin ${MICRODUCK_COMMIT} && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "${MICRODUCK_COMMIT}"
WORKDIR /upstream
RUN cargo build --locked -p robotd -p robotctl
RUN cargo metadata --locked --filter-platform $(rustc -vV | sed -n 's/^host: //p') --format-version 1 > /metadata.json \
    && python3 /collect_cargo_licenses.py /metadata.json /licenses/cargo-upstream --packages robotd robotctl
FROM build-base AS adapter-builder
COPY sdk/proto /src/sdk/proto
COPY libpail_gate /src/libpail_gate
RUN cmake -S libpail_gate -B /build -DBUILD_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/opt/pail_gate \
    && cmake --build /build -j2 && cmake --install /build
# Build inputs by name: guides and deployment scripts in this directory are not image inputs. The install guide
# is one, because a unit test of the adapter opens it.
COPY adapters/microduck/Cargo.toml adapters/microduck/Cargo.lock adapters/microduck/build.rs \
     adapters/microduck/build_paths.rs /src/adapters/microduck/
COPY adapters/microduck/src /src/adapters/microduck/src
COPY adapters/microduck/deploy/INSTALL.md /src/adapters/microduck/deploy/INSTALL.md
ENV PAIL_GATE_LIB_DIR=/opt/pail_gate/lib LD_LIBRARY_PATH=/opt/pail_gate/lib
WORKDIR /src/adapters/microduck
RUN rustc --test build_paths.rs -o /tmp/test-build-paths && /tmp/test-build-paths \
    && cargo build --locked --features libgate && cargo test --locked --features libgate
RUN cargo metadata --locked --features libgate --filter-platform $(rustc -vV | sed -n 's/^host: //p') --format-version 1 > /metadata.json \
    && python3 /collect_cargo_licenses.py /metadata.json /licenses/cargo-adapter --packages pail-duckd
FROM ${GO_IMAGE} AS core-builder
ENV GOMAXPROCS=2 GOFLAGS=-p=2
WORKDIR /src/cloud
COPY cloud/go.mod cloud/go.sum ./
RUN go mod download
COPY cloud ./
RUN test ! -d issuer
ENV CGO_ENABLED=0
RUN go build -trimpath -buildvcs=false -mod=readonly -tags pail_generated -o /out/pail_robot_agent ./cmd/pail_robot_agent \
    && go build -trimpath -buildvcs=false -mod=readonly -tags pail_generated -o /out/blackbox_verify ./cmd/blackbox_verify \
    && go build -trimpath -buildvcs=false -mod=readonly -tags pail_generated -o /out/pail_telemetryd ./cmd/pail_telemetryd \
    && go build -trimpath -buildvcs=false -mod=readonly -tags pail_generated -o /out/submit_plan ./cmd/submit_plan \
    && go build -trimpath -buildvcs=false -mod=readonly -tags pail_generated -o /out/get_active_token ./cmd/get_active_token \
    && go build -trimpath -buildvcs=false -mod=readonly -o /out/pail-keyring-sign ./tools/pail-keyring-sign
COPY examples/tb3/probe.go /src/cloud/tb3-probe.go
RUN go build -trimpath -buildvcs=false -mod=readonly -o /out/tb3-probe /src/cloud/tb3-probe.go
RUN go mod download all && mkdir -p /licenses/go && go list -m -mod=readonly -f '{{if not .Main}}{{.Path}} {{.Dir}}{{end}}' all | \
    while read name dir; do test -z "$name" && continue; mkdir -p "/licenses/go/$name"; \
    find "$dir" -maxdepth 1 -type f \( -iname '*license*' -o -iname 'notice*' -o -iname 'copying*' \) \
    -exec cp {} "/licenses/go/$name/" \;; done
# Debian 13, the same release as the two build images above: the gate library is linked there and loaded here, and
# a recipient takes it and pail-duckd out of this image (adapters/microduck/deploy/INSTALL.md names these packages).
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS tooling
# zlib1g is named although the base holds it: the security repository publishes a fixed build (CVE-2026-85091) that
# the pinned base predates, and naming an installed package upgrades exactly that package. No general upgrade runs.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libprotobuf32t64 libsodium23 libyaml-cpp0.8 libudev1 ca-certificates python3 python3-venv \
    protobuf-compiler openssl zlib1g && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH PYTHONUNBUFFERED=1 LD_LIBRARY_PATH=/opt/pail/lib
RUN pip install --no-cache-dir grpcio==1.83.0 grpcio-tools==1.83.0 protobuf==7.35.1 pynacl==1.6.0 pyyaml==6.0.2
COPY --from=core-builder /out/ /usr/local/bin/
COPY --from=core-builder /licenses/ /opt/pail/licenses/
COPY --from=core-builder /usr/local/go/LICENSE /opt/pail/licenses/Go-LICENSE
COPY LICENSE NOTICE /opt/pail/licenses/core/
COPY sdk/proto /opt/pail/proto
COPY libpail_gate/abi/pail_gate_abi.proto /opt/pail/proto/pail_gate_abi.proto
RUN mkdir -p /opt/pail/python && python -m grpc_tools.protoc -I/opt/pail/proto \
    --python_out=/opt/pail/python --grpc_python_out=/opt/pail/python /opt/pail/proto/*.proto
ENV PYTHONPATH=/opt/pail/python:/opt/pail/pvs
COPY pvs-public /opt/pail/pvs
COPY scripts/gen_dev_keys.py /opt/pail/keygen.py
# Only what a container opens. Host-side runners, judges, guides and the demo scripts mounted at /reference are
# the bundle layer and stay outside; tests/contract/test_023_c2_explicit_copy.py holds this list to its users.
COPY examples/microduck/support.py /opt/pail/example/support.py
COPY examples/microduck/fixtures/robotd.toml examples/microduck/fixtures/policy.yaml \
     examples/microduck/fixtures/duck_skills.yaml examples/microduck/fixtures/skills.microduck.yaml \
     examples/microduck/fixtures/site.yaml /opt/pail/example/fixtures/
COPY examples/common/core_operation_wire.py examples/common/core_report_wire.py \
     examples/common/diagnostics.py /opt/pail/common/
COPY examples/adapter/minimal.py /opt/pail/adapter-reference/minimal.py
RUN find /opt/pail -type d -exec chmod 0755 {} + && find /opt/pail -type f -exec chmod 0644 {} +
RUN groupadd -g 10001 pail && useradd -u 10001 -g pail -M pail
WORKDIR /opt/pail
LABEL org.pail.component=core-tools
ARG PAIL_IMAGE_INPUT_SHA256=unknown
LABEL org.pail.image-input-sha256=$PAIL_IMAGE_INPUT_SHA256
CMD ["blackbox_verify", "--help"]

FROM tooling AS runtime
COPY --from=adapter-builder /licenses/ /opt/pail/licenses/
COPY --from=upstream-builder /licenses/ /opt/pail/licenses/
COPY --from=adapter-builder /opt/pail_gate/lib/ /opt/pail/lib/
COPY --from=adapter-builder /src/adapters/microduck/target/debug/pail-duckd /usr/local/bin/
COPY --from=upstream-builder /upstream/target/debug/robotd /upstream/target/debug/robotctl /usr/local/bin/
COPY --from=upstream-builder /upstream/LICENSE /opt/pail/licenses/microduck-LICENSE
COPY --from=upstream-builder /upstream/deploy/updater.toml /opt/pail/upstream/updater.toml
ARG PAIL_VERSION
LABEL org.pail.component=core-microduck org.pail.release=${PAIL_VERSION}
CMD ["pail-duckd", "--help"]
