// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// This file intentionally left minimal.
// Actual selection is performed in pep_gate_node.cpp via parameters.
//
// Build system selects either:
// - src/token_provider_grpc_stub.cpp   (default, no grpc deps)
// - src/grpc/token_provider_grpc.cpp   (when PAIL_ENABLE_GRPC=ON)
