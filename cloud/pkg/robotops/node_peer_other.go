//go:build !linux

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package robotops

import (
	"fmt"
	"net"
)

type NodePeer struct {
	PID                                  int32
	UID                                  uint32
	StartTicks, BootID, ExecutableSHA256 string
}

func InspectNodePeer(net.Conn, uint32, string) (NodePeer, error) {
	return NodePeer{}, fmt.Errorf("RO_CAPABILITY: native node peer inspection requires Linux")
}
func InspectNodePeerIdentity(net.Conn, uint32) (NodePeer, error) {
	return NodePeer{}, fmt.Errorf("RO_CAPABILITY: native node peer inspection requires Linux")
}
func NodeExecutableSHA256(NodePeer) (string, error) {
	return "", fmt.Errorf("RO_CAPABILITY: native node peer inspection requires Linux")
}
func LocalMonotonicNS() (int64, error) {
	return 0, fmt.Errorf("RO_CAPABILITY: native node clock requires Linux")
}
