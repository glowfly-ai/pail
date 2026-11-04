// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/glowfly/pail/services/internal/blackbox"
)

// blackbox_verify checks the segment-based hash-chained blackbox (LLD-v2 §5.2/§5.3).
//
// Segment file: pail_blackbox.<seq:08d>.seg
//   header(56B): magic'PBSG' | ver(u32)=2 | segment_seq(u64) | prev_segment_tail_hash(32) | created_unix_ms(u64)
//   records: version(u32) | type(u32) | unix_ms(u64) | payload_len(u32) | payload | prev_hash(32) | this_hash(32)
//     this_hash = sha256(hdr | payload | prev_hash); first record's prev_hash = sha256(segment header)
// CHECKPOINT v1 (type=30) payload: head_hash(32) | record_count(u64 LE) | sig(64), sig = Sign(head_hash)
// CHECKPOINT v2 (type=31) payload: head_hash(32) | record_count(u64 BE) | segment_seq(u64 BE) | sig(64),
//
//	sig = Sign("pail-checkpoint:v2:" ‖ head ‖ record_count ‖ segment_seq)
//
// v1 stays readable forever (F8) but is no longer written. v1 checkpoints are
// reported as count-unattested: the signature does not cover record_count, so
// "signature valid" says nothing about the count sitting next to it (X13a).
//
// --check-chain verifies: per-record hashes, header-to-first-record chaining,
// segment-boundary tail inheritance, and CHECKPOINT signatures (needs -pubkey or -keyfile).
// --find searches TOKEN_ISSUED records across all segments.

const (
	segMagic      = "PBSG"
	segVersion    = 2
	segHeaderSize = 56
)

// The payload lengths and the v2 signed input come from the blackbox package —
// the same code the writer signs with. This tool carried its own copy for a day
// (E-C3 first draft), which let it agree with itself while disagreeing with the
// writer and report that as a verified chain.
const (
	ckptPayloadV1 = blackbox.CheckpointV1PayloadLen
	ckptPayloadV2 = blackbox.CheckpointV2PayloadLen
)

type record struct {
	segName  string
	idx      int
	offset   int64
	hdr      []byte // 16B: version|type|unix_ms
	recType  uint32
	payload  []byte
	prevHash [32]byte
	thisHash [32]byte
}

func main() {
	var (
		dir        = flag.String("dir", "/var/log/pail_blackbox", "blackbox segment directory")
		checkChain = flag.Bool("check-chain", false, "verify hash chain integrity across all segments")
		findToken  = flag.String("find", "", "find TOKEN_ISSUED record containing token_hash_hex (hex string)")
		pubkeyB64  = flag.String("pubkey", "", "issuer ed25519 public key (base64) for CHECKPOINT signature verification")
		keyfile    = flag.String("keyfile", "", "issuer key JSON file (reads ed25519_public_key_base64)")
		retention  = flag.Bool("retention", false, "report the sealed policy's retention: per segment (needs -policy); rc 4 mismatched, 5 unsealed, 6 sealed policy invalid")
		policyPath = flag.String("policy", "", "policy.yaml to compare against the newest CONFIG_SEALED policy_file_sha256")
	)
	flag.Parse()

	if !*checkChain && *findToken == "" && !*retention {
		fmt.Fprintln(os.Stderr, "need at least one action: --check-chain, --find <token_hash_hex> and/or --retention -policy <file>")
		os.Exit(2)
	}
	var policyBytes []byte
	if *retention {
		if *policyPath == "" {
			fmt.Fprintln(os.Stderr, "--retention needs -policy <policy.yaml>")
			os.Exit(2)
		}
		b, err := os.ReadFile(*policyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "policy: %v\n", err)
			os.Exit(2)
		}
		policyBytes = b
	}

	pub, err := loadPubkey(*pubkeyB64, *keyfile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pubkey: %v\n", err)
		os.Exit(2)
	}

	wantFind := strings.TrimPrefix(strings.ToLower(*findToken), "0x")
	if wantFind != "" {
		if _, err := hex.DecodeString(wantFind); err != nil {
			fmt.Fprintf(os.Stderr, "--find must be hex (got %q): %v\n", *findToken, err)
			os.Exit(2)
		}
	}

	segs, err := listSegments(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan %s: %v\n", *dir, err)
		os.Exit(1)
	}
	if len(segs) == 0 {
		fmt.Fprintf(os.Stderr, "no pail_blackbox.*.seg segments in %s\n", *dir)
		os.Exit(1)
	}

	var (
		prevSeq          uint64
		prevTail         [32]byte
		havePrev         bool
		totalRecords     int
		totalCkpts       int
		found            bool
		unverifiedCkpts  int
		unattestedCounts int
		segInfos         []segInfo
		sealedSHA        string
		sealSkipped      int
		allRecords       []record
	)

	for _, name := range segs {
		path := filepath.Join(*dir, name)
		seq, header, records, err := readSegment(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %s: %v\n", name, err)
			os.Exit(1)
		}

		var declaredTail [32]byte
		copy(declaredTail[:], header[16:48])
		if *checkChain {
			allRecords = append(allRecords, records...)
		}
		if *retention {
			segInfos = append(segInfos, segInfo{Seq: seq, CreatedMs: binary.LittleEndian.Uint64(header[48:56])})
			// Segments are walked in order, so the last hash seen is the newest.
			if sha, skipped := sealedPolicySHA(records); sha != "" || skipped > 0 {
				if sha != "" {
					sealedSHA = sha
				}
				sealSkipped += skipped
			}
		}

		if *checkChain {
			if havePrev {
				if seq != prevSeq+1 {
					fmt.Fprintf(os.Stderr, "FAIL: %s: segment_seq=%d not contiguous after %d\n", name, seq, prevSeq)
					os.Exit(1)
				}
				if declaredTail != prevTail {
					fmt.Fprintf(os.Stderr, "FAIL: %s: prev_segment_tail_hash mismatch\n  got : %s\n  want: %s\n",
						name, hex.EncodeToString(declaredTail[:]), hex.EncodeToString(prevTail[:]))
					os.Exit(1)
				}
			} else if declaredTail != ([32]byte{}) {
				fmt.Printf("NOTE: %s inherits tail %s but no prior segment is present (older segments removed?)\n",
					name, hex.EncodeToString(declaredTail[:]))
			}

			prevExpected := sha256.Sum256(header) // header participates in the chain
			ckpts := 0
			for _, r := range records {
				if r.prevHash != prevExpected {
					fmt.Fprintf(os.Stderr, "FAIL: %s record[%d] offset=%d: prev_hash mismatch\n  got : %s\n  want: %s\n",
						name, r.idx, r.offset, hex.EncodeToString(r.prevHash[:]), hex.EncodeToString(prevExpected[:]))
					os.Exit(1)
				}
				h := sha256.New()
				h.Write(r.hdr)
				h.Write(r.payload)
				h.Write(r.prevHash[:])
				var expected [32]byte
				copy(expected[:], h.Sum(nil))
				if r.thisHash != expected {
					fmt.Fprintf(os.Stderr, "FAIL: %s record[%d] offset=%d: this_hash mismatch\n  got : %s\n  want: %s\n",
						name, r.idx, r.offset, hex.EncodeToString(r.thisHash[:]), hex.EncodeToString(expected[:]))
					os.Exit(1)
				}

				if r.recType == blackbox.RecordCheckpoint || r.recType == blackbox.RecordCheckpointV2 {
					v2 := r.recType == blackbox.RecordCheckpointV2
					wantLen := ckptPayloadV1
					if v2 {
						wantLen = ckptPayloadV2
					}
					if len(r.payload) != wantLen {
						fmt.Fprintf(os.Stderr, "FAIL: %s record[%d]: CHECKPOINT payload len=%d, want %d\n", name, r.idx, len(r.payload), wantLen)
						os.Exit(1)
					}
					var head [32]byte
					copy(head[:], r.payload[0:32])
					if head != r.prevHash {
						fmt.Fprintf(os.Stderr, "FAIL: %s record[%d]: CHECKPOINT head_hash != preceding record this_hash\n", name, r.idx)
						os.Exit(1)
					}
					var count uint64
					var signed, sig []byte
					if v2 {
						count = binary.BigEndian.Uint64(r.payload[32:40])
						declSeq := binary.BigEndian.Uint64(r.payload[40:48])
						if declSeq != seq {
							fmt.Fprintf(os.Stderr, "FAIL: %s record[%d]: CHECKPOINT segment_seq=%d, but it sits in segment %d (checkpoint moved between segments)\n",
								name, r.idx, declSeq, seq)
							os.Exit(1)
						}
						signed, sig = blackbox.CheckpointV2SignedInput(head[:], count, declSeq), r.payload[48:112]
					} else {
						count = binary.LittleEndian.Uint64(r.payload[32:40])
						signed, sig = head[:], r.payload[40:104]
					}
					if count != uint64(r.idx) {
						fmt.Fprintf(os.Stderr, "FAIL: %s record[%d]: CHECKPOINT record_count=%d, want %d\n", name, r.idx, count, r.idx)
						os.Exit(1)
					}
					if pub != nil {
						if !ed25519.Verify(pub, signed, sig) {
							fmt.Fprintf(os.Stderr, "FAIL: %s record[%d]: CHECKPOINT ed25519 signature invalid\n", name, r.idx)
							os.Exit(1)
						}
						if !v2 {
							// The count above was compared against the reader's own
							// walk, not against anything the issuer signed. Saying
							// "signature valid" and stopping would let a v1 record
							// borrow v2's meaning.
							unattestedCounts++
						}
					} else {
						unverifiedCkpts++
					}
					ckpts++
				}

				prevExpected = r.thisHash
			}
			fmt.Printf("OK: %s seq=%d records=%d checkpoints=%d\n", name, seq, len(records), ckpts)
			totalCkpts += ckpts
		}

		if wantFind != "" {
			for _, r := range records {
				if r.recType != blackbox.RecordTokenIssued {
					continue
				}
				if th := tokenHashFromPayload(r.payload); th != "" && strings.EqualFold(strings.TrimPrefix(th, "0x"), wantFind) {
					fmt.Printf("FOUND: %s record[%d] offset=%d token_hash_hex=%s\n", name, r.idx, r.offset, th)
					found = true
				}
			}
		}

		// tail for the next segment: last record this_hash, or the inherited
		// prev tail when the segment has no records (empty segments are
		// transparent to chain inheritance — mirrors writer segmentTailHash).
		prevTail = declaredTail
		if len(records) > 0 {
			prevTail = records[len(records)-1].thisHash
		}
		prevSeq = seq
		havePrev = true
		totalRecords += len(records)
	}

	if *checkChain {
		if unverifiedCkpts > 0 {
			fmt.Fprintf(os.Stderr, "FAIL: %d CHECKPOINT record(s) present but no -pubkey/-keyfile given for signature verification\n", unverifiedCkpts)
			os.Exit(1)
		}
		if unattestedCounts > 0 {
			fmt.Printf("NOTE: %d CHECKPOINT v1 record(s): signature verified, record_count NOT attested by it (X13a)\n", unattestedCounts)
		}
		fmt.Printf("OK: chain verified (%d segments, %d records, %d checkpoints)\n", len(segs), totalRecords, totalCkpts)
		// EC-3: what the verified records are evidence of, by intervention class.
		printClassCounts(os.Stdout, classCounts(allRecords))
	}
	if wantFind != "" && !found {
		fmt.Printf("NOT_FOUND: token_hash_hex=%s\n", wantFind)
		os.Exit(3)
	}
	if *retention {
		rep, err := evaluateRetention(sealedSHA, policyBytes, segInfos, time.Now())
		if err != nil {
			fmt.Fprintf(os.Stderr, "RETENTION policy=%s but the sealed file's retention: is invalid: %v\n", rep.Policy, err)
			os.Exit(6)
		}
		if rc := printRetention(os.Stdout, rep, sealSkipped); rc != 0 {
			os.Exit(rc)
		}
	}
}

func loadPubkey(b64, keyfile string) (ed25519.PublicKey, error) {
	if b64 == "" && keyfile != "" {
		b, err := os.ReadFile(keyfile)
		if err != nil {
			return nil, err
		}
		var jf struct {
			PublicKeyB64 string `json:"ed25519_public_key_base64"`
		}
		if err := json.Unmarshal(b, &jf); err != nil {
			return nil, fmt.Errorf("keyfile parse: %w", err)
		}
		b64 = jf.PublicKeyB64
	}
	if b64 == "" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: %d", len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

func listSegments(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		var seq uint64
		if !e.IsDir() {
			if _, err := fmt.Sscanf(e.Name(), "pail_blackbox.%d.seg", &seq); err == nil {
				names = append(names, e.Name())
			}
		}
	}
	sort.Strings(names) // zero-padded seq sorts lexicographically
	return names, nil
}

func readSegment(path string) (seq uint64, header []byte, records []record, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, nil, nil, err
	}
	defer f.Close()
	r := bufio.NewReader(f)

	header = make([]byte, segHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, nil, fmt.Errorf("truncated segment header: %w", err)
	}
	if string(header[0:4]) != segMagic {
		return 0, nil, nil, fmt.Errorf("bad segment magic %q", header[0:4])
	}
	if v := binary.LittleEndian.Uint32(header[4:8]); v != segVersion {
		return 0, nil, nil, fmt.Errorf("unsupported segment version=%d", v)
	}
	seq = binary.LittleEndian.Uint64(header[8:16])

	var nameSeq uint64
	if _, err := fmt.Sscanf(filepath.Base(path), "pail_blackbox.%d.seg", &nameSeq); err != nil || nameSeq != seq {
		return 0, nil, nil, fmt.Errorf("filename seq mismatch (header seq=%d)", seq)
	}

	offset := int64(segHeaderSize)
	idx := 0
	for {
		hdr := make([]byte, 16)
		n, rerr := io.ReadFull(r, hdr)
		if (errors.Is(rerr, io.EOF) || errors.Is(rerr, io.ErrUnexpectedEOF)) && n == 0 {
			return seq, header, records, nil // clean end of segment
		}
		if rerr != nil {
			return 0, nil, nil, fmt.Errorf("record[%d] offset=%d: truncated header: %w", idx, offset, rerr)
		}
		if v := binary.LittleEndian.Uint32(hdr[0:4]); v != 1 {
			return 0, nil, nil, fmt.Errorf("record[%d] offset=%d: unsupported version=%d", idx, offset, v)
		}
		recType := binary.LittleEndian.Uint32(hdr[4:8])

		lenBuf := make([]byte, 4)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return 0, nil, nil, fmt.Errorf("record[%d] offset=%d: read payload_len: %w", idx, offset, err)
		}
		payload := make([]byte, binary.LittleEndian.Uint32(lenBuf))
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, nil, fmt.Errorf("record[%d] offset=%d: read payload(%d): %w", idx, offset, len(payload), err)
		}
		var prevHash, thisHash [32]byte
		if _, err := io.ReadFull(r, prevHash[:]); err != nil {
			return 0, nil, nil, fmt.Errorf("record[%d] offset=%d: read prev_hash: %w", idx, offset, err)
		}
		if _, err := io.ReadFull(r, thisHash[:]); err != nil {
			return 0, nil, nil, fmt.Errorf("record[%d] offset=%d: read this_hash: %w", idx, offset, err)
		}

		records = append(records, record{
			segName: filepath.Base(path), idx: idx, offset: offset,
			hdr: hdr, recType: recType, payload: payload, prevHash: prevHash, thisHash: thisHash,
		})
		offset += int64(16 + 4 + len(payload) + 32 + 32)
		idx++
	}
}

func tokenHashFromPayload(payload []byte) string {
	var obj map[string]any
	if err := json.Unmarshal(payload, &obj); err == nil {
		if s, ok := obj["token_hash_hex"].(string); ok {
			return s
		}
	}
	s := string(payload)
	needle := `"token_hash_hex":"`
	if i := strings.Index(s, needle); i >= 0 {
		j := i + len(needle)
		if k := strings.IndexByte(s[j:], '"'); k > 0 {
			return s[j : j+k]
		}
	}
	return ""
}
