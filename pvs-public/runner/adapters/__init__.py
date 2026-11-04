# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Adapter-conformance backends (spec/ADAPTER_CONTRACT.md §4). Each backend drives one
adapter through the same PVS scenario vocabulary the ROS gate node is driven with
(`runner.live.backend_live.LiveBackend`), so a conformance case is one YAML file for every
transport and the verdict logic (`runner.core.orchestrator`) is shared, not copied."""
