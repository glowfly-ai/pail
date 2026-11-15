// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package ledgerq

// OBS-RET: the query index keeps a window of observation rows instead of
// growing until it refuses to ingest.
//
// No setting ever removed a row from the index, the size check looked at the
// file (which SQLite never shrinks), and at the 2 GiB default the observation
// ingest stopped for good — about a day of one robot at 20 lines a second.
// These tests drive the real ingest with synthetic lines and a clock they own.

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/blackbox"
	"github.com/glowfly/pail/services/internal/telemetry"
)

var orNow = time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)

const orDay = 24 * time.Hour

type orLine struct {
	at    time.Time
	robot string
}

// orLines writes one raw observation file: a burst per line, a liveness tick
// before every hundredth.
func orLines(t *testing.T, dir, name string, lines []orLine) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriter(f)
	dup := false
	for i, l := range lines {
		if i%100 == 0 {
			b, _ := json.Marshal(telemetry.Record{V: 1, Kind: telemetry.KindTick, Ms: uint64(l.at.UnixMilli())})
			w.Write(append(b, '\n'))
		}
		ev := "PERMIT"
		if i%50 == 49 {
			ev = "BLOCK"
		}
		b, _ := json.Marshal(telemetry.Record{V: 1, Kind: telemetry.KindBurst, Ms: uint64(l.at.UnixMilli()), Event: ev,
			Robot: RobotHash16(l.robot), Token: TokenHash16(fmt.Sprintf("tok-%d", i/200)), Sig: telemetry.SigOK, Dup: &dup, Raw: "00"})
		w.Write(append(b, '\n'))
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

func orSpread(n int, from, to time.Time) []orLine {
	out := make([]orLine, n)
	step := to.Sub(from) / time.Duration(n)
	for i := range out {
		out[i] = orLine{at: from.Add(time.Duration(i) * step), robot: "robot-1"}
	}
	return out
}

func orConfig(t *testing.T, doc string) telemetry.StorageConfig {
	t.Helper()
	c, err := telemetry.ParseStorageConfig([]byte(doc))
	if err != nil {
		t.Fatalf("storage config %s: %v", doc, err)
	}
	return c
}

func orOpen(t *testing.T, doc string) *DB {
	t.Helper()
	d, err := Open(filepath.Join(t.TempDir(), "ledger.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if doc != "" {
		if err := d.ConfigureStorage(orConfig(t, doc)); err != nil {
			t.Fatalf("ConfigureStorage: %v", err)
		}
	}
	return d
}

func orCount(t *testing.T, d *DB, query string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := d.sql.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

func orRecords(t *testing.T, d *DB) int64 {
	return orCount(t, d, `SELECT COUNT(*) FROM observation_records WHERE kind='burst'`)
}

func orHas(t *testing.T, d *DB, at time.Time) bool {
	return orCount(t, d, `SELECT COUNT(*) FROM observation_records WHERE kind='burst' AND received_ms=?`, at.UnixMilli()) > 0
}

// orIndex is the `window` object of the storage health, read through JSON so
// that this file compiles on a tree that does not have it yet.
func orIndex(t *testing.T, d *DB) map[string]any {
	t.Helper()
	b, err := json.Marshal(d.StorageHealth())
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	idx, ok := m["window"].(map[string]any)
	if !ok {
		t.Fatalf("storage health has no `window` object: %s", b)
	}
	return idx
}

func orNum(t *testing.T, m map[string]any, key string) float64 {
	t.Helper()
	v, ok := m[key].(float64)
	if !ok {
		t.Fatalf("index health has no number %q: %v", key, m)
	}
	return v
}

func orStatusNum(t *testing.T, st TelemetryStatus, key string) float64 {
	t.Helper()
	b, _ := json.Marshal(st)
	var m map[string]any
	json.Unmarshal(b, &m)
	v, ok := m[key].(float64)
	if !ok {
		t.Fatalf("ingest status has no number %q: %s", key, b)
	}
	return v
}

func orFileBytes(t *testing.T, d *DB) int64 {
	t.Helper()
	var n int64
	for _, s := range []string{"", "-wal"} {
		if st, err := os.Stat(d.Path() + s); err == nil {
			n += st.Size()
		}
	}
	return n
}

// The four ages every retention case uses: two outside a 7-day window, two inside.
func orAged() []orLine {
	return []orLine{
		{orNow.Add(-10 * orDay), "robot-1"}, {orNow.Add(-8 * orDay), "robot-1"},
		{orNow.Add(-6 * orDay), "robot-1"}, {orNow.Add(-1 * orDay), "robot-1"},
	}
}

func orJournal(t *testing.T, n int, at time.Time) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "bb")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	w, err := blackbox.OpenDir(dir, blackbox.Config{Signer: testSigner(t), IdleFlushAfter: -1})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		ms := uint64(at.UnixMilli()) + uint64(i)
		b, _ := json.Marshal(map[string]any{"kind": "plan_accepted", "unix_ms": ms, "robot_id": "robot-1",
			"plan_id": fmt.Sprintf("plan-%d", i), "chain_id": fmt.Sprintf("chain-%d", i), "policy_hash_hex": "ab", "key_id": "dev-key-1"})
		if err := w.Append(blackbox.RecordPlanAccepted, ms, b); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Abandon(); err != nil {
		t.Fatal(err)
	}
	return dir
}

// The floor is stated so that these cases do not depend on how full the disk
// of the machine running them is (the automatic floor is a tenth of it).
const orSevenDays = `{"schema_version":1,"index_retain_days":7,"disk_free_min_bytes":1048576}`

// ---- T01: a handle nobody configured keeps everything ------------------------

func TestORT01UnconfiguredIndexKeepsEverything(t *testing.T) {
	tel := filepath.Join(t.TempDir(), "tel")
	orLines(t, tel, "decisions-20261101.jsonl", orAged())
	d := orOpen(t, "")
	if _, err := d.IngestTelemetry(tel, orNow); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if n := orRecords(t, d); n != 4 {
		t.Fatalf("observation rows=%d, want all 4", n)
	}
}

// ---- T02/T10: rows outside the window go, journal rows stay -------------------

func TestORT02RowsOlderThanTheWindowAreRemoved(t *testing.T) {
	tel := filepath.Join(t.TempDir(), "tel")
	orLines(t, tel, "decisions-20261101.jsonl", orAged())
	bb := orJournal(t, 2, orNow.Add(-30*orDay))
	d := orOpen(t, orSevenDays)
	if _, _, err := d.Ingest(bb, tel, orNow); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	cut := orNow.Add(-7 * orDay).UnixMilli()
	for name, q := range map[string]string{
		"observation_records":      `SELECT COUNT(*) FROM observation_records WHERE kind='burst' AND received_ms < ?`,
		"events (telemetry)":       `SELECT COUNT(*) FROM events WHERE src='telemetry' AND ms < ?`,
		"observation_points":       `SELECT COUNT(*) FROM observation_points WHERE ms < ?`,
		"observation_burst_counts": `SELECT COUNT(*) FROM observation_burst_counts WHERE bucket_ms < ?`,
		"ticks":                    `SELECT COUNT(*) FROM ticks WHERE ms < ?`,
	} {
		if n := orCount(t, d, q, cut-int64(time.Hour/time.Millisecond)); n != 0 {
			t.Errorf("%s still holds %d row(s) older than the window", name, n)
		}
	}
	if n := orRecords(t, d); n != 2 {
		t.Errorf("observation rows=%d, want the 2 inside the window", n)
	}
	if n := orCount(t, d, `SELECT COUNT(*) FROM events WHERE src='telemetry'`); n != 2 {
		t.Errorf("telemetry events=%d, want 2", n)
	}
	if n := orCount(t, d, `SELECT COUNT(*) FROM events WHERE src='chain'`); n != 2 {
		t.Errorf("journal rows=%d, want 2 — retention is for observation rows only", n)
	}
	// T10: what the index no longer holds is said.
	if got := int64(orNum(t, orIndex(t, d), "pruned_through_ms")); got != cut {
		t.Errorf("pruned_through_ms=%d, want the window edge %d", got, cut)
	}
}

// ---- T03: old lines are not inserted, the file is read once and left alone -----

func TestORT03ExpiredLinesAreCountedNotInserted(t *testing.T) {
	tel := filepath.Join(t.TempDir(), "tel")
	p := orLines(t, tel, "decisions-20261101.jsonl", orAged())
	before, _ := os.ReadFile(p)
	d := orOpen(t, orSevenDays)
	st, err := d.IngestTelemetry(tel, orNow)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	// two bursts outside the window, and the tick written before the first line
	if got := orStatusNum(t, st, "ExpiredLines"); got != 3 {
		t.Errorf("ExpiredLines=%v, want 3", got)
	}
	if off := orCount(t, d, `SELECT durable_offset FROM observation_files`); off != int64(len(before)) {
		t.Errorf("durable_offset=%d, want the whole file (%d)", off, len(before))
	}
	st2, err := d.IngestTelemetry(tel, orNow)
	if err != nil {
		t.Fatalf("second ingest: %v", err)
	}
	if st2.Bursts != 0 || orRecords(t, d) != 2 {
		t.Errorf("second pass inserted bursts=%d rows=%d, want 0 and 2", st2.Bursts, orRecords(t, d))
	}
	after, _ := os.ReadFile(p)
	if sha256.Sum256(before) != sha256.Sum256(after) {
		t.Errorf("the raw observation file changed")
	}
}

// ---- T04: the budget shortens the window instead of stopping ingest -------------

func orBudgetCase(t *testing.T, doc string) (*DB, []orLine) {
	t.Helper()
	tel := filepath.Join(t.TempDir(), "tel")
	lines := orSpread(20000, orNow.Add(-6*time.Hour), orNow)
	orLines(t, tel, "decisions-20261113.jsonl", lines)
	d := orOpen(t, doc)
	if _, err := d.IngestTelemetry(tel, orNow); err != nil {
		t.Fatalf("ingest stopped: %v", err)
	}
	return d, lines
}

// The pre-existing shape of the setting: only a budget. On the unfixed tree
// this is where the collector stops for good.
func TestORT04pABudgetAloneNoLongerStopsIngest(t *testing.T) {
	d, lines := orBudgetCase(t, `{"schema_version":1,"db_max_bytes":6291456,"disk_free_min_bytes":1048576}`)
	if !orHas(t, d, lines[len(lines)-1].at) {
		t.Errorf("the newest line is not in the index")
	}
	if orHas(t, d, lines[0].at) {
		t.Errorf("the oldest line is still in the index although the budget is far smaller than the data")
	}
	if h := d.StorageHealth(); h.State != "READY" {
		t.Errorf("state=%s error=%s, want READY", h.State, h.Error)
	}
}

func TestORT04TheBudgetShortensTheWindowAndSaysSo(t *testing.T) {
	d, lines := orBudgetCase(t, `{"schema_version":1,"index_retain_days":7,"db_max_bytes":6291456,"disk_free_min_bytes":1048576}`)
	idx := orIndex(t, d)
	if used := orNum(t, idx, "used_bytes"); used > 6291456 {
		t.Errorf("used_bytes=%.0f exceeds the budget", used)
	}
	if g := idx["guidance"]; g != "WINDOW_CUT_BY_BUDGET" {
		t.Errorf("guidance=%v, want WINDOW_CUT_BY_BUDGET", g)
	}
	if from := int64(orNum(t, idx, "covers_from_ms")); from <= lines[0].at.UnixMilli() {
		t.Errorf("covers_from_ms=%d does not move past the first line %d", from, lines[0].at.UnixMilli())
	}
}

// The budget has cut the window, but the index covers less than an hour, so no
// daily growth can be stated. "Measuring" would hide that rows are already
// being dropped: what has happened outranks what cannot be estimated yet.
func TestORT04bACutIsReportedEvenBeforeARateIsKnown(t *testing.T) {
	tel := filepath.Join(t.TempDir(), "tel")
	lines := orSpread(20000, orNow.Add(-30*time.Minute), orNow)
	orLines(t, tel, "decisions-20261113.jsonl", lines)
	d := orOpen(t, `{"schema_version":1,"index_retain_days":7,"db_max_bytes":6291456,"disk_free_min_bytes":1048576}`)
	if _, err := d.IngestTelemetry(tel, orNow); err != nil {
		t.Fatalf("ingest stopped: %v", err)
	}
	idx := orIndex(t, d)
	if orNum(t, idx, "rate_bytes_per_day") != 0 {
		t.Fatalf("precondition: thirty minutes of data must not yield a daily rate, got %v", idx["rate_bytes_per_day"])
	}
	if orHas(t, d, lines[0].at) {
		t.Fatalf("precondition: the oldest line should have been dropped for space")
	}
	if g := idx["guidance"]; g != "WINDOW_CUT_BY_BUDGET" {
		t.Errorf("guidance=%v, want WINDOW_CUT_BY_BUDGET", g)
	}
}

// ---- T05/T13: nothing to prune -> the old refusal -------------------------------

func TestORT05NoObservationRowsAndNoBudgetIsStillPressure(t *testing.T) {
	d := orOpen(t, `{"schema_version":1,"db_max_bytes":1}`)
	if err := d.CheckStorage(); err == nil || !strings.Contains(err.Error(), "DB_DISK_PRESSURE") {
		t.Fatalf("CheckStorage=%v, want DB_DISK_PRESSURE", err)
	}
}

func TestORT13JournalRowsAreNeverPrunedForSpace(t *testing.T) {
	bb := orJournal(t, 300, orNow.Add(-30*orDay))
	d := orOpen(t, `{"schema_version":1,"db_max_bytes":4096}`)
	if _, err := d.IngestChain(bb, orNow); err != nil {
		t.Fatalf("IngestChain: %v", err)
	}
	if err := d.CheckStorage(); err == nil || !strings.Contains(err.Error(), "DB_DISK_PRESSURE") {
		t.Fatalf("CheckStorage=%v, want DB_DISK_PRESSURE", err)
	}
	if n := orCount(t, d, `SELECT COUNT(*) FROM events WHERE src='chain'`); n != 300 {
		t.Fatalf("journal rows=%d, want 300", n)
	}
}

// ---- T06: the file stops growing once rows leave as fast as they arrive ---------

func TestORT06TheFileDoesNotGrowInSteadyState(t *testing.T) {
	tel := filepath.Join(t.TempDir(), "tel")
	d := orOpen(t, `{"schema_version":1,"index_retain_days":1,"disk_free_min_bytes":1048576}`)
	var sizes []int64
	for day := 0; day < 3; day++ {
		end := orNow.Add(time.Duration(day) * orDay)
		orLines(t, tel, fmt.Sprintf("decisions-202611%02d.jsonl", 14+day), orSpread(5000, end.Add(-orDay+time.Minute), end))
		if _, err := d.IngestTelemetry(tel, end); err != nil {
			t.Fatalf("day %d: %v", day, err)
		}
		// a second pass lets the bounded pruning finish its work for this day
		if _, err := d.IngestTelemetry(tel, end); err != nil {
			t.Fatalf("day %d, second pass: %v", day, err)
		}
		d.sql.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
		sizes = append(sizes, orFileBytes(t, d))
		if n := orRecords(t, d); n < 4500 || n > 5500 {
			t.Errorf("day %d: observation rows=%d, want about one day's 5000", day, n)
		}
	}
	if float64(sizes[2]) > float64(sizes[1])*1.25 {
		t.Errorf("file grew from %d to %d bytes between two equal days", sizes[1], sizes[2])
	}
}

// ---- T07-T09: guidance in terms of the disk that is left ------------------------

// orDiskFree is the free space the index is told about: the measurement in effect (the tests' fake since 0.2.2 F4,
// so the guidance assertions below no longer depend on the host's free disk; statfsUsage itself is covered by
// TestF4T4ProductionMeasurementReadsTheFilesystem).
func orDiskFree(t *testing.T, path string) float64 {
	t.Helper()
	free, _, ok := diskUsage(path)
	if !ok {
		t.Fatal("disk measurement unavailable")
	}
	return float64(free)
}

func TestORT07GuidanceRelatesTheWindowToTheDiskThatIsLeft(t *testing.T) {
	tel := filepath.Join(t.TempDir(), "tel")
	orLines(t, tel, "decisions-20261112.jsonl", orSpread(4000, orNow.Add(-2*orDay), orNow))
	d := orOpen(t, orSevenDays)
	if _, err := d.IngestTelemetry(tel, orNow); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	idx := orIndex(t, d)
	if g := idx["guidance"]; g != "OK" {
		t.Errorf("guidance=%v, want OK on a disk with room", g)
	}
	rate, need := orNum(t, idx, "rate_bytes_per_day"), orNum(t, idx, "window_need_bytes")
	if rate <= 0 {
		t.Fatalf("rate_bytes_per_day=%v", rate)
	}
	if math.Abs(need-rate*7) > rate*7*0.01 {
		t.Errorf("window_need_bytes=%.0f, want rate x 7 days = %.0f", need, rate*7)
	}
	if int(orNum(t, idx, "retain_days")) != 7 {
		t.Errorf("retain_days=%v", idx["retain_days"])
	}
	free, want := orNum(t, idx, "disk_free_bytes"), orDiskFree(t, d.Path())
	if math.Abs(free-want) > want*0.10 {
		t.Errorf("disk_free_bytes=%.0f, the filesystem says %.0f", free, want)
	}
	if orNum(t, idx, "disk_total_bytes") < free || orNum(t, idx, "disk_floor_bytes") <= 0 {
		t.Errorf("disk_total_bytes=%v disk_floor_bytes=%v", idx["disk_total_bytes"], idx["disk_floor_bytes"])
	}
	if left := orNum(t, idx, "disk_days_left"); left <= 0 {
		t.Errorf("disk_days_left=%v, want a positive number of days", left)
	}
}

// A floor larger than the disk: from then on the index may not grow, so the
// oldest rows make room for the new ones and the health says why.
func TestORT08ALowDiskShortensTheWindowAndSaysSo(t *testing.T) {
	tel := filepath.Join(t.TempDir(), "tel")
	first := orSpread(10000, orNow.Add(-6*time.Hour), orNow.Add(-3*time.Hour))
	orLines(t, tel, "decisions-20261113.jsonl", first)
	d := orOpen(t, orSevenDays)
	if _, err := d.IngestTelemetry(tel, orNow.Add(-3*time.Hour)); err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	if err := d.ConfigureStorage(orConfig(t, `{"schema_version":1,"index_retain_days":7,"disk_free_min_bytes":1152921504606846976}`)); err != nil {
		t.Fatal(err)
	}
	second := orSpread(10000, orNow.Add(-3*time.Hour), orNow)
	orLines(t, tel, "decisions-20261114.jsonl", second)
	if _, err := d.IngestTelemetry(tel, orNow); err != nil {
		t.Fatalf("ingest with the disk below its floor stopped: %v", err)
	}
	if !orHas(t, d, second[len(second)-1].at) {
		t.Errorf("the newest line is not in the index")
	}
	if orHas(t, d, first[0].at) {
		t.Errorf("the oldest line is still in the index")
	}
	if g := orIndex(t, d)["guidance"]; g != "WINDOW_CUT_BY_DISK" {
		t.Errorf("guidance=%v, want WINDOW_CUT_BY_DISK", g)
	}
}

func TestORT09GuidanceWhenThereIsNothingToSayYet(t *testing.T) {
	tel := filepath.Join(t.TempDir(), "tel")
	orLines(t, tel, "decisions-20261113.jsonl", orSpread(100, orNow.Add(-10*time.Minute), orNow))
	d := orOpen(t, orSevenDays)
	if _, err := d.IngestTelemetry(tel, orNow); err != nil {
		t.Fatal(err)
	}
	idx := orIndex(t, d)
	if idx["guidance"] != "MEASURING" || orNum(t, idx, "rate_bytes_per_day") != 0 {
		t.Errorf("guidance=%v rate=%v, want MEASURING and 0 for ten minutes of data", idx["guidance"], idx["rate_bytes_per_day"])
	}
	all := orOpen(t, `{"schema_version":1,"index_retain_days":0,"disk_free_min_bytes":1048576}`)
	if _, err := all.IngestTelemetry(tel, orNow); err != nil {
		t.Fatal(err)
	}
	if g := orIndex(t, all)["guidance"]; g != "KEEP_ALL" {
		t.Errorf("guidance=%v with retention 0, want KEEP_ALL", g)
	}
}

// ---- T12: a rebuild follows the same window --------------------------------------

// orRebuild is where this test meets the product: a rebuild that knows the
// storage configuration.
func orRebuild(path, bb, tel string, now time.Time, c telemetry.StorageConfig) (*DB, error) {
	d, _, _, err := RebuildWithStorage(path, bb, tel, now, c)
	return d, err
}

func TestORT12ARebuildDoesNotBringExpiredRowsBack(t *testing.T) {
	tel := filepath.Join(t.TempDir(), "tel")
	orLines(t, tel, "decisions-20261101.jsonl", orAged())
	bb := orJournal(t, 2, orNow.Add(-30*orDay))
	d, err := orRebuild(filepath.Join(t.TempDir(), "ledger.sqlite"), bb, tel, orNow, orConfig(t, orSevenDays))
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	defer d.Close()
	if n := orRecords(t, d); n != 2 {
		t.Fatalf("observation rows after a rebuild=%d, want the 2 inside the window", n)
	}
}
