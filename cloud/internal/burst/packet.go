// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package burst

import (
	"crypto/sha256"
	"encoding/binary"
)

// BuildPacket creates the minimal UDP burst packet described in codex_spec/03_LOGGING_BLACKBOX.md.
// Layout (little-endian where applicable):
// magic(4)='PAIL' | ver(1)=1 | event(1) | token_id_hash16(16) | reason(2) | unix_ms(8)
func BuildPacket(eventCode byte, tokenID string, reasonCode uint16, unixMs uint64) []byte {
	pkt := make([]byte, 32)
	copy(pkt[0:4], []byte{'P', 'A', 'I', 'L'})
	pkt[4] = 1
	pkt[5] = eventCode
	h := sha256.Sum256([]byte(tokenID))
	copy(pkt[6:22], h[:16])
	binary.LittleEndian.PutUint16(pkt[22:24], reasonCode)
	binary.LittleEndian.PutUint64(pkt[24:32], unixMs)
	return pkt
}
