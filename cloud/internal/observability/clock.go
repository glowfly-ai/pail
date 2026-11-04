// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package observability

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math/big"
	"os"
	"regexp"
	"strings"
)

// ClockBindingShared is the only binding a source map may ask for. Asking is
// not binding: the collector compares every record with its own identity.
const ClockBindingShared = "shared_kernel_monotonic"

const bootIDPath = "/proc/sys/kernel/random/boot_id"
const timensOffsetsPath = "/proc/self/timens_offsets"

var bootID = regexp.MustCompile(`^[0-9a-f-]{1,64}$`)
var offsetPart = regexp.MustCompile(`^-?[0-9]{1,19}$`)

func readSmall(path string) (string, bool) {
	f, e := os.Open(path)
	if e != nil {
		return "", false
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 4097))
	if e != nil || len(b) > 4096 {
		return "", false
	}
	return string(b), true
}

// clockIdentityFrom names the monotonic clock this process reads: the boot
// and the monotonic offset of its time namespace, hashed exactly as the
// producer hashes its own. Two processes get the same name only when their
// CLOCK_MONOTONIC values are directly comparable. Anything unreadable or
// unexpected is "unavailable", never a guess.
func clockIdentityFrom(bootPath, offsetsPath string) (string, bool) {
	boot, ok := readSmall(bootPath)
	boot = strings.TrimSpace(boot)
	if !ok || !bootID.MatchString(boot) {
		return "", false
	}
	text, ok := readSmall(offsetsPath)
	if !ok {
		return "", false
	}
	var row []string
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == "monotonic" {
			if row != nil {
				return "", false
			}
			row = fields
		}
	}
	if len(row) != 3 || !offsetPart.MatchString(row[1]) || !offsetPart.MatchString(row[2]) {
		return "", false
	}
	seconds, _ := new(big.Int).SetString(row[1], 10)
	nanos, _ := new(big.Int).SetString(row[2], 10)
	offset := seconds.Mul(seconds, big.NewInt(1000000000)).Add(seconds, nanos)
	sum := sha256.Sum256([]byte(boot + ":monotonic-offset-ns=" + offset.String()))
	return "mono-" + hex.EncodeToString(sum[:]), true
}
