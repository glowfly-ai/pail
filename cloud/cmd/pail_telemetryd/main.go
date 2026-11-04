// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/glowfly/pail/services/internal/crypto"
	"github.com/glowfly/pail/services/internal/deploysec"
	"github.com/glowfly/pail/services/internal/graph"
	"github.com/glowfly/pail/services/internal/identity"
	"github.com/glowfly/pail/services/internal/ledgerq"
	"github.com/glowfly/pail/services/internal/observability"
	"github.com/glowfly/pail/services/internal/telemetry"
)

// pail_telemetryd is the dashboard's collector (implementation contract D1/D2): it
// listens for burst packets beside the gate receiver, appends tick/burst
// records to a bounded UTC/size JSONL roll, and serves the loopback query API whose
// answers carry their own coverage. It is observation material only — the
// verdict canon stays in the blackbox/anchor chain, and nothing served here
// may feed an authorization decision.

const component = "pail_telemetryd"

// The dashboard page ships inside the binary (consoleui precedent): markup and
// display modules only — every judgment value it renders arrives from the query
// API at runtime, so serving the static shell unauthenticated leaks nothing.
//
//go:embed dashboard/index.html dashboard/i18n.js dashboard/shared.js dashboard/adapters.js dashboard/reason_dict.js dashboard/robotops.js dashboard/fleet.js dashboard/status_ledger.js
var dashboardFS embed.FS

func main() {
	var (
		observationConfig = flag.String("observability-config", "", "strict schema_version=1 raw retention and DB/WAL budget JSON; default retain_no_delete")
		pushListen        = flag.String("push-listen", "", "TLS bind addr for observation uploads of robots on other machines (design 15); client certificates are required and bound to robots by the registry")
		pushCA            = flag.String("push-ca", "", "CA that issued the robots' client certificates (with -push-listen)")
		pushCert          = flag.String("push-cert", "", "server certificate of the push listener (with -push-listen)")
		pushKey           = flag.String("push-key", "", "server key of the push listener (with -push-listen)")
		listen            = flag.String("listen", "127.0.0.1:46010", "UDP listen addr for burst packets")
		httpAddr          = flag.String("http", "127.0.0.1:8090", "query API bind addr (non-loopback requires PAIL_TELEMETRY_TOKEN)")
		dir               = flag.String("dir", "/var/lib/pail/telemetry", "JSONL directory (new decisions-YYYYMMDD-NNNNNN.jsonl; legacy daily files readable)")
		check             = flag.String("check", "", "check a decisions JSONL file for liveness gaps and exit")
		maxGap            = flag.Duration("max-gap", 30*time.Second, "gap threshold for -check and query coverage")
		tick              = flag.Duration("tick", 10*time.Second, "liveness tick period")
		registry          = flag.String("registry", "", "robot registry YAML for hash→name resolution (default $PAIL_ROBOT_REGISTRY, else "+identity.DefaultRegistryPath+")")
		sbomDir           = flag.String("sbom-dir", "", "directory holding <component>.cdx.json SBOMs for /v1/telemetry/software (default $PAIL_SBOM_DIR, else /usr/share/pail/sbom)")
		// AL-1 (implementation contract D6): ledger index. The blackbox directory is read only —
		// this process never appends to the chain, and the index is derived.
		blackboxDir = flag.String("blackbox-dir", "", "blackbox segment directory, read-only (default $PAIL_BLACKBOX_DIR, else /var/log/pail_blackbox)")
		indexPath   = flag.String("index", "", "ledger index sqlite path (default $PAIL_LEDGER_INDEX, else <dir>/ledger.sqlite)")
		reindex     = flag.Bool("reindex", false, "build and validate a side-by-side ledger index, preserve the old index, then publish from segments + JSONL, print counts, exit 0/1")
		indexCheck  = flag.Bool("index-check", false, "re-derive every chain row from its origin and compare; exit 0 = all reproduce, 1 = mismatch")
		snapshotDir = flag.String("snapshot-dir", "", "site-model snapshot dir for after-the-fact zone resolution (default $PAIL_SNAPSHOT_DIR, else <blackbox-dir>/snapshots)")
	)
	flag.Parse()
	registryPath = resolveRegistryPath(*registry, os.Getenv("PAIL_ROBOT_REGISTRY"))
	sbomDirPath = firstNonEmpty(*sbomDir, os.Getenv("PAIL_SBOM_DIR"), "/usr/share/pail/sbom")
	ledgerBlackboxDir = firstNonEmpty(*blackboxDir, os.Getenv("PAIL_BLACKBOX_DIR"), "/var/log/pail_blackbox")
	ledgerIndexPath = firstNonEmpty(*indexPath, os.Getenv("PAIL_LEDGER_INDEX"), ledgerq.DefaultIndexPath(*dir))
	ledgerSnapshotDir = firstNonEmpty(*snapshotDir, os.Getenv("PAIL_SNAPSHOT_DIR"), filepath.Join(ledgerBlackboxDir, "snapshots"))
	if flag.NArg() > 0 {
		// an argument nobody parses must not be silently ignored — it is a
		// command the caller believed was in effect
		fmt.Fprintf(os.Stderr, "unexpected arguments: %v\n", flag.Args())
		os.Exit(2)
	}
	if *tick <= 0 || *maxGap <= 0 {
		fmt.Fprintf(os.Stderr, "tick and max-gap must be positive (tick=%v max-gap=%v)\n", *tick, *maxGap)
		os.Exit(2)
	}

	if *check != "" {
		os.Exit(runCheck(*check, *maxGap))
	}
	if *reindex {
		os.Exit(runReindex(ledgerIndexPath, ledgerBlackboxDir, *dir))
	}
	if *indexCheck {
		os.Exit(runIndexCheck(ledgerIndexPath, ledgerBlackboxDir))
	}

	// The keyring path comes from PAIL_KEYRING, not a flag of this binary's
	// own: S8 scans that env var, and a flag the scanner cannot see would let
	// the process trust one file while the check cleared another (burst_recv
	// precedent).
	keyringPath := os.Getenv("PAIL_KEYRING")
	if keyringPath == "" {
		keyringPath = deploysec.DefaultKeyringPath
	}
	deploysec.Preflight(component)
	deploysec.EnforceKeyModes(component)

	keys, keyRole, mode, err := verifyKeys(keyringPath)
	if err != nil {
		deploysec.RefuseConfig(component,
			fmt.Errorf("keyring trust path (mode=%s): %w", mode, err))
	}

	// 미러 신뢰근은 **기동을 막지 않는다**. `split_config.sh` 가 mirror 개인키를
	// 로봇 트리에만 두므로 클라우드 수집기의 키링에는 mirror 역할이 없는 것이
	// 정상이고, 여기서 거부하면 그 배치가 통째로 서지 않는다.
	//
	// 대신 **없다는 사실이 값으로 남는다**: 키가 없으면 도착한 PMIR 은
	// `sig=unverifiable` 로 적히고(H-B2 — "검증 못 했다"이지 "검증했고 틀렸다"가
	// 아니다), 아래 배너가 그 상태를 기동 로그에 인쇄한다. 인쇄하지 않으면
	// "미러를 못 믿는다"와 "미러가 안 온다"가 화면에서 같은 회색이 된다.
	mirrorKeys, mirrorRole, mirrorErr := verifyMirrorKeys(keyringPath)
	if mirrorErr != nil {
		mirrorRole = "none"
		fmt.Fprintf(os.Stderr,
			"%s: mirror trust anchor absent — permit packets will be recorded sig=unverifiable: %v\n",
			component, mirrorErr)
	}

	token := os.Getenv("PAIL_TELEMETRY_TOKEN")
	if !loopbackAddr(*httpAddr) && token == "" {
		// fail-closed like the anchor admin plane: an open bind without a
		// token is refused at startup, not discovered in an audit
		fmt.Fprintf(os.Stderr, "non-loopback -http %s requires PAIL_TELEMETRY_TOKEN\n", *httpAddr)
		os.Exit(1)
	}

	storageConfig := telemetry.DefaultStorageConfig()
	if *observationConfig != "" {
		b, e := os.ReadFile(*observationConfig)
		if e == nil {
			storageConfig, observationCollector, e = parseObservationConfig(b)
		}
		if e != nil {
			fmt.Fprintf(os.Stderr, "observability-config: %v\n", e)
			os.Exit(2)
		}
	}
	if observationCollector != nil {
		go observationCollector.RunFiles(context.Background())
	}
	if *pushListen != "" {
		if observationCollector == nil || *pushCA == "" || *pushCert == "" || *pushKey == "" {
			fmt.Fprintf(os.Stderr, "push-listen needs an observability-config with a source map and push-ca, push-cert, push-key\n")
			os.Exit(2)
		}
		pushRegistry, e := identity.Load(registryPath)
		if e != nil {
			fmt.Fprintf(os.Stderr, "push-listen: %v\n", e)
			os.Exit(2)
		}
		if _, e = pushTLS(*pushCA, *pushCert, *pushKey); e != nil {
			fmt.Fprintf(os.Stderr, "push-listen: %v\n", e)
			os.Exit(2)
		}
		go func() {
			if e := servePush(*pushListen, *pushCA, *pushCert, *pushKey, pushRegistry, observationCollector); e != nil {
				fmt.Fprintf(os.Stderr, "push-listen: %v\n", e)
				os.Exit(1)
			}
		}()
	}
	store, err := telemetry.OpenStoreWithConfig(*dir, storageConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "store: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()
	observationStore = store

	udpAddr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve: %v\n", err)
		os.Exit(1)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Fprintf(os.Stderr, "%s listening udp=%s http=%s dir=%s (keyring mode=%s %s-role keys: %d, %s-role mirror keys: %d tick=%v max-gap=%v)\n",
		component, *listen, *httpAddr, *dir, mode, keyRole, len(keys), mirrorRole, len(mirrorKeys), *tick, *maxGap)

	ingress := telemetry.NewIngress(store, func(err error) { fmt.Fprintf(os.Stderr, "observation writer: %v\n", err) })
	defer ingress.Close()
	observationIngress = ingress
	appendLine := func(line []byte, now time.Time) {
		if err := ingress.AppendLine(line, now); err != nil {
			fmt.Fprintf(os.Stderr, "observation ingress: %v\n", err)
		}
	}

	go func() {
		t := time.NewTicker(*tick)
		defer t.Stop()
		for now := range t.C {
			line, err := telemetry.MarshalTick(uint64(now.UnixMilli()))
			if err != nil {
				fmt.Fprintf(os.Stderr, "tick marshal: %v\n", err)
				os.Exit(1)
			}
			appendLine(line, now)
		}
	}()

	// AL-1: 원장 인덱스. 열지 못하면 조회 표면이 503 으로 그 사실을 말한다 —
	// 기동을 막지는 않는다(수집은 인덱스와 다른 실패 도메인이다).
	if idx, err := ledgerq.Open(ledgerIndexPath); err != nil {
		fmt.Fprintf(os.Stderr, "ledger index: %v (GET /v1/ledger/events will answer 503)\n", err)
		connectLedger(nil, observationCollector)
	} else {
		ledgerIndex = idx
		connectLedger(idx, observationCollector)
		if err := idx.ConfigureStorage(storageConfig); err != nil {
			fmt.Fprintf(os.Stderr, "storage config: %v\n", err)
			os.Exit(2)
		}
		idx.ZoneResolver = snapshotZoneResolver(ledgerSnapshotDir)
		// Independent serial workers: a full journal copy/verification must
		// not prevent observation catch-up from being scheduled. SQLite still
		// serializes publication writes; reader snapshots remain independent.
		repeat := func(work func(time.Time)) {
			work(time.Now())
			t := time.NewTicker(*tick)
			defer t.Stop()
			for range t.C {
				work(time.Now())
			}
		}
		go repeat(func(now time.Time) {
			first := true
			cs, passes, err := verifyLedger(idx, ledgerBlackboxDir, func() time.Time {
				if first {
					first = false
					return now
				}
				return time.Now()
			}, time.Sleep)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ledger verification: %v\n", err)
			} else if cs.Inserted > 0 || cs.State != "ok" || passes > 1 {
				fmt.Fprintf(os.Stderr, "ledger verification: state=%s records=%d new=%d passes=%d\n", cs.State, cs.Records, cs.Inserted, passes)
			}
		})
		go repeat(func(now time.Time) {
			ts, err := idx.IngestTelemetry(*dir, now)
			if err != nil {
				fmt.Fprintf(os.Stderr, "observation ingest: %v\n", err)
				return
			}
			if err = store.Maintain(now, idx.IndexedRaw); err != nil {
				fmt.Fprintf(os.Stderr, "retention: %v\n", err)
			}
			if ts.BadLines > 0 {
				fmt.Fprintf(os.Stderr, "observation bad lines: %d\n", ts.BadLines)
			}
		})
		// Do not wait on the writer for startup statistics: HTTP must expose
		// BUILDING as 503 while UDP collection and the bounded backfill run.
		fmt.Fprintf(os.Stderr, "ledger index %s: background catch-up started; blackbox=%s\n", ledgerIndexPath, ledgerBlackboxDir)
	}

	liveSignals := telemetry.NewLiveSignals(keyRole, mirrorRole)
	go serveHTTP(*httpAddr, token, *dir, *maxGap, liveSignals)

	// 한 소켓에 두 형식이 도착한다(D11). 매직으로 갈라 각자의 신뢰근으로 재고
	// 각자의 줄로 적는 판단은 Dispatcher 안에 한 벌만 산다 — 여기서 다시
	// 분기하면 "매직은 permit 인데 burst 로 적히는" 조합이 조용히 생긴다.
	disp := telemetry.NewDispatcher(keys, mirrorKeys)
	buf := make([]byte, 2048)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read: %v\n", err)
			os.Exit(1)
		}
		now := time.Now()
		line, observation, err := disp.Observe(buf[:n], now)
		if err != nil {
			fmt.Fprintf(os.Stderr, "malformed packet: %v\n", err)
			continue
		}
		appendLine(line, now)
		liveSignals.Observe(observation, now)
		if observationCollector != nil {
			kind, seq, dup := "", observation.Seq, false
			if observation.Kind == telemetry.KindBurst {
				kind = "legacy_burst"
				dup = observation.Dup != nil && *observation.Dup
			}
			if observation.Kind == telemetry.KindPermit {
				kind = "legacy_permit"
				seq = observation.MirrorSeq
			}
			if kind != "" {
				observationCollector.ObserveLegacy(kind, observation.Robot, seq, observation.Sig == telemetry.SigOK, dup)
			}
		}
	}
}

// verifyKeys loads the burst trust anchors through the one keyring path every
// PAIL process uses (`B6-6`) and the shared role-selection rule
// (telemetry.VerifyKeys): burst-role keys first, issuer only as the pre-split
// fallback. A local issuer-only parser was the DB-1 defect — genuine bursts
// recorded as `sig=bad` (`S15`, H-B2 역상).
func verifyKeys(legacyPath string) ([]ed25519.PublicKey, string, string, error) {
	kr, mode, err := crypto.LoadTrustedKeyringFromEnv(legacyPath)
	if err != nil {
		return nil, "", mode, err
	}
	keys, role, err := telemetry.VerifyKeys(kr)
	return keys, role, mode, err
}

// verifyMirrorKeys loads the permit-mirror trust anchors through the same
// keyring path. 폴백은 `telemetry.VerifyMirrorKeys` 가 의도적으로 갖지 않는다 —
// 아무 신뢰 키나 permit 생존을 증언할 수 있으면 화면의 초록은 누구의 증언인지를
// 잃는다.
func verifyMirrorKeys(legacyPath string) ([]ed25519.PublicKey, string, error) {
	kr, _, err := crypto.LoadTrustedKeyringFromEnv(legacyPath)
	if err != nil {
		return nil, "", err
	}
	return telemetry.VerifyMirrorKeys(kr)
}

func runCheck(path string, maxGap time.Duration) int {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "check: %v\n", err)
		return 2
	}
	defer f.Close()
	rep, err := telemetry.Check(f, maxGap)
	if err != nil {
		fmt.Fprintf(os.Stderr, "check: %v\n", err)
		return 2
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		fmt.Fprintf(os.Stderr, "check: %v\n", err)
		return 2
	}
	// zero records is not a clean file — it is a file that proves nothing
	if rep.Records == 0 || len(rep.Gaps) > 0 || len(rep.BadLines) > 0 {
		return 1
	}
	return 0
}

func loopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func serveHTTP(addr, token, dir string, maxGap time.Duration, live ...*telemetry.LiveSignals) {
	srv := &http.Server{Addr: addr, Handler: newMux(token, dir, maxGap, live...), ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "http: %v\n", err)
		os.Exit(1)
	}
}

// newMux builds the routing table apart from the listener so a test can drive
// the real handlers instead of a re-implementation. 라우팅을 테스트가 다시
// 짜면 그 테스트는 자기가 짠 것을 재고, 배포되는 표는 아무도 안 잰다.
func newMux(token, dir string, maxGap time.Duration, live ...*telemetry.LiveSignals) *http.ServeMux {
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		if token == "" {
			return h // loopback-only bind, enforced at startup
		}
		return func(w http.ResponseWriter, r *http.Request) {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			h(w, r)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/dashboard/", serveDashboardWith(os.Getenv("PAIL_ROBOTOPS_PROJECTION") != "")) // same switch as projectionSourceFromEnv
	observationAPI := observability.NewAPI(observationCollector)
	mux.HandleFunc("/v2/observation/capabilities", auth(observationAPI.Capabilities))
	mux.HandleFunc("/v2/observation/robots", auth(observationAPI.Robots))
	mux.HandleFunc(observability.DecisionsEndpoint, auth(observationAPI.Decisions))
	mux.HandleFunc("/v1/telemetry/storage", auth(func(w http.ResponseWriter, r *http.Request) {
		h := ledgerIndex.StorageHealth()
		var raw telemetry.StorageHealth
		if observationStore != nil {
			raw = currentStorageHealth()
		} else {
			raw = h.Raw
		}
		if h.State != "READY" || raw.State == "OBSERVATION_LOSS" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		writeJSON(w, struct {
			Index  ledgerq.IndexStorageHealth `json:"index"`
			Writer telemetry.StorageHealth    `json:"writer"`
		}{h, raw})
	}))
	mux.HandleFunc("/v1/telemetry/decisions", auth(func(w http.ResponseWriter, r *http.Request) {
		f, ok := parseFilter(w, r)
		if !ok {
			return
		}
		if observationStore != nil && currentStorageHealth().State == "OBSERVATION_LOSS" {
			http.Error(w, "OBSERVATION_LOSS", http.StatusServiceUnavailable)
			return
		}
		storageHeaders(w)
		res, err := ledgerIndex.ObservationDecisions(r.Context(), f, maxGap)
		if err != nil {
			http.Error(w, "INDEX_UNAVAILABLE", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, res)
	}))
	mux.HandleFunc("/v1/telemetry/liveness", auth(func(w http.ResponseWriter, r *http.Request) {
		f, ok := parseFilter(w, r)
		if !ok {
			return
		}
		if observationStore != nil && currentStorageHealth().State == "OBSERVATION_LOSS" {
			http.Error(w, "OBSERVATION_LOSS", http.StatusServiceUnavailable)
			return
		}
		storageHeaders(w)
		res, err := ledgerIndex.ObservationLiveness(r.Context(), f, maxGap)
		if err != nil {
			http.Error(w, "INDEX_UNAVAILABLE", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, res)
	}))
	// 운영자 뷰의 로봇별 행. 판정은 여기서 서고 페이지는 표시만 한다(H5) —
	// 나이 비교를 브라우저에 두면 사용자 시계가 판정 재료가 되고, 시계가 어긋난
	// 자리에서 초록과 회색이 뒤집힌다.
	//
	// `now` 는 요청 시각이다. 마지막 레코드의 시각으로 재면 수집기가 멈춘 순간
	// 표가 그 순간에 얼어붙어 **영원히 초록**이 된다 — DB-2 가 막으려는 바로 그
	// 형태다.
	// AL-0 (implementation contract D7): 로봇 해시→이름 해소 재료. 원장·decisions·permits 계약은
	// 손대지 않는다 — 화면이 이 표로 이름을 붙이고, 해시는 그대로 남긴다.
	mux.HandleFunc("/v1/telemetry/registry", auth(registryHandler(registryPath)))
	mux.HandleFunc("/v1/telemetry/robotops/probe", auth(collectorProbeHandler(registryPath)))
	var signalSource *telemetry.LiveSignals
	if len(live) == 1 {
		signalSource = live[0]
	}
	mux.HandleFunc("/v1/telemetry/robotops/signals", auth(collectorSignalsHandler(registryPath, signalSource)))
	// LLD §13: sanitized executor projection. Unset = 404 (feature absent).
	projection := projectionSourceFromEnv()
	observationAPI.SetManagementProjection(projection != nil)
	mux.HandleFunc("/v1/telemetry/robotops", auth(projectionHandler(projection)))
	// EC-2 (EUC D2): 설치 SW 식별. 체인이 말하는 각 컴포넌트의 빌드와 디스크의 SBOM 대조.
	mux.HandleFunc("/v1/telemetry/software", auth(softwareHandler(ledgerBlackboxDir, sbomDirPath)))
	// AL-1 (implementation contract D6): 원장 조회. 인덱스에서 답하고, 응답이 자기 결측(커버리지·
	// 검증 상태·해소 상태·인덱스 신선도)을 함께 싣는다.
	mux.HandleFunc("/v1/ledger/events", auth(ledgerEventsHandler(maxGap)))
	mux.HandleFunc("/v1/ledger/plans", auth(ledgerPlansHandler()))
	mux.HandleFunc("/v1/telemetry/permits", auth(func(w http.ResponseWriter, r *http.Request) {
		if observationStore != nil && currentStorageHealth().State == "OBSERVATION_LOSS" {
			http.Error(w, "OBSERVATION_LOSS", http.StatusServiceUnavailable)
			return
		}
		storageHeaders(w)
		res, err := ledgerIndex.ObservationPermits(r.Context(), time.Now())
		if err != nil {
			http.Error(w, "INDEX_UNAVAILABLE", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, res)
	}))

	return mux
}

// ---- AL-0 (implementation contract D7): robot hash → name -----------------------------------
//
// The burst v2 robot field is sha256(robot_id)[:16] (internal/burst/packet_v2.go)
// — a one-way value the operator cannot read. This view hands the dashboard the
// declared robot_ids of config/robot_registry.yaml with the same hash beside
// each, so the page can label rows without ever touching the ledger. Three
// outcomes are distinguishable on purpose (H-B2): "registry" (loaded),
// "absent" (file not there), "invalid" (there but refused by RG-1..RG-4). An
// empty robots list with source=registry cannot happen — Parse refuses it.
type registryResponse struct {
	Digest  string          `json:"-"`
	Version int             `json:"version"`
	Source  string          `json:"source"`
	Path    string          `json:"path"`
	Error   string          `json:"error,omitempty"`
	Robots  []registryRobot `json:"robots"`
}

type registryRobot struct {
	RobotID   string `json:"robot_id"`
	RobotHash string `json:"robot_hash"`
}

// registryPath is fixed once in main after flag parsing; tests set it through
// registryHandler's argument instead.
var registryPath string

// sbomDirPath (EC-2) — same convention as registryPath.
var sbomDirPath string

func resolveRegistryPath(flagValue, envValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if envValue != "" {
		return envValue
	}
	return identity.DefaultRegistryPath
}

func registryView(path string) registryResponse {
	out := registryResponse{Version: 1, Path: path, Robots: []registryRobot{}}
	if _, err := os.Stat(path); err != nil {
		out.Source = "absent"
		out.Error = err.Error()
		return out
	}
	reg, err := identity.Load(path)
	if err != nil {
		out.Source = "invalid"
		out.Error = err.Error()
		return out
	}
	out.Source = "registry"
	out.Digest = reg.LoadedDigest()
	for _, id := range reg.RobotIDs() {
		// one derivation for the whole process (ledgerq.RobotHash16): the index and the
		// registry view must never disagree about what a robot's hash is
		out.Robots = append(out.Robots, registryRobot{RobotID: id, RobotHash: ledgerq.RobotHash16(id)})
	}
	return out
}

func registryHandler(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, registryView(path))
	}
}

// ---- AL-1 (implementation contract D6): ledger query surface ---------------------------------

var (
	ledgerIndex       *ledgerq.DB
	ledgerBlackboxDir string
	ledgerIndexPath   string
	ledgerSnapshotDir string
)

// snapshotZoneResolver (AL-4) answers zone questions from the kept
// site-model snapshots (<sha256>.yaml). Each snapshot is compiled once through
// the same graph.Compile the issuer used — no second YAML reader — and cached
// by hash. A missing or uncompilable snapshot is "cannot resolve", never a
// guess from today's model.
func snapshotZoneResolver(dir string) ledgerq.ZoneResolver {
	var mu sync.Mutex
	cache := map[string]map[string]string{} // hash → object → zone (nil = unreadable)
	return func(hash, target string) (string, bool) {
		if hash == "" || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(hash) {
			return "", false
		}
		mu.Lock()
		zones, seen := cache[hash]
		mu.Unlock()
		if !seen {
			raw, err := os.ReadFile(filepath.Join(dir, hash+".yaml"))
			if err == nil {
				// The name is the content (review item 17): a file whose bytes do not
				// hash to its name is not the model of that day — it is a file somebody
				// put there — and is "cannot resolve", cached as such, said once.
				if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != hash {
					log.Printf("AL-4 snapshot %s: content does not hash to its name — not used", hash)
				} else if _, sm, cerr := graph.Compile(raw); cerr == nil {
					zones = sm.ObjectZone
				}
			}
			mu.Lock()
			cache[hash] = zones
			mu.Unlock()
		}
		if zones == nil {
			return "", false
		}
		z, ok := zones[target]
		return z, ok && z != ""
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

var robotHashRe = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)

// parseLedgerFilter reads the AL-1 axes. `robot` accepts a plain robot_id or
// the 32-hex hash; a name is resolved through the registry view, and a name
// the registry does not know is NOT silently dropped — it yields an empty row
// set with resolution.robot=unresolved (the filter the operator asked for is
// answered, not replaced by "all robots").
func parseLedgerFilter(w http.ResponseWriter, r *http.Request) (ledgerq.Filter, string, bool) {
	q := r.URL.Query()
	var f ledgerq.Filter
	u64 := func(key string) (uint64, bool) {
		s := q.Get(key)
		if s == "" {
			return 0, true
		}
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			http.Error(w, key+": "+err.Error(), http.StatusBadRequest)
			return 0, false
		}
		return v, true
	}
	var ok bool
	if f.FromMs, ok = u64("from_ms"); !ok {
		return f, "", false
	}
	if f.ToMs, ok = u64("to_ms"); !ok {
		return f, "", false
	}
	around, ok := u64("around_ms")
	if !ok {
		return f, "", false
	}
	span, ok := u64("span_ms")
	if !ok {
		return f, "", false
	}
	if around != 0 {
		if span == 0 {
			span = 60_000
		}
		if around > span {
			f.FromMs = around - span
		} else {
			f.FromMs = 0
		}
		f.ToMs = around + span
	}
	lim, ok := u64("limit")
	if !ok {
		return f, "", false
	}
	f.Limit = int(lim)
	f.Cursor = q.Get("cursor")
	f.PlanID = q.Get("plan_id")
	f.StepID = q.Get("step_id")
	f.TokenID = q.Get("token_id")
	f.Target = q.Get("target")
	f.Outcome = q.Get("outcome")
	f.Src = q.Get("src")
	// AL-3 axes
	ac, ok := u64("action_class")
	if !ok {
		return f, "", false
	}
	f.ActionClass = uint32(ac)
	f.ActionName = q.Get("action_name")
	f.Zone = q.Get("zone")
	f.Requester = q.Get("requester")
	switch q.Get("registered") {
	case "":
	case "true", "false":
		b := q.Get("registered") == "true"
		f.Registered = &b
	default:
		http.Error(w, "registered: want true|false", http.StatusBadRequest)
		return f, "", false
	}
	resolution := "none"
	if robot := q.Get("robot"); robot != "" {
		if robotHashRe.MatchString(robot) {
			f.RobotHash = strings.ToLower(robot)
			resolution = "hash_only"
		} else {
			resolution = "unresolved"
			for _, rr := range registryView(registryPath).Robots {
				if rr.RobotID == robot {
					f.RobotHash = rr.RobotHash
					resolution = "registry"
				}
			}
		}
	}
	return f, resolution, true
}

func ledgerEventsHandler(maxGap time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if ledgerIndex == nil {
			http.Error(w, "ledger index unavailable (open failed at start — see stderr)", http.StatusServiceUnavailable)
			return
		}
		f, resolution, ok := parseLedgerFilter(w, r)
		if !ok {
			return
		}
		var res ledgerq.Result
		if resolution == "unresolved" {
			// 답은 "그 로봇의 사건 0건"이 아니라 "그 이름을 모른다"다 — 행을 비우고
			// 해소 상태로 말한다. 전체 조회로 바꿔치기하지 않는다.
			res = ledgerq.Result{Rows: []ledgerq.OutRow{}}
			st, err := ledgerIndex.Stats()
			if err != nil {
				ledgerQueryError(w, err)
				return
			}
			res.Index = st
			res.Verify = ledgerq.Verify{State: "unverified", CheckedToSeq: st.CheckedToSeq, CheckedToMs: st.CheckedToMs, WalkMs: st.ChainWalkMs}
		} else {
			var err error
			res, err = ledgerIndex.Query(f, maxGap, time.Now())
			if err != nil {
				ledgerQueryError(w, err)
				return
			}
		}
		res.Resolution.Robot = resolution
		// zone: computed by the index (recorded → snapshot → unresolved); the
		// handler adds nothing — AL-1's constant "unresolved" here once hid
		// AL-4's answer behind the honest-looking default (2026-09-04 실측).
		// 텔레메트리 행의 robot_id 는 저장하지 않고 응답 시 레지스트리로 붙인다 —
		// 레지스트리가 바뀌어도 인덱스가 낡은 이름을 물고 있지 않도록.
		names := map[string]string{}
		for _, rr := range registryView(registryPath).Robots {
			names[rr.RobotHash] = rr.RobotID
		}
		for i := range res.Rows {
			if res.Rows[i].RobotID == "" && res.Rows[i].RobotHash != "" {
				if id, ok := names[res.Rows[i].RobotHash]; ok {
					res.Rows[i].RobotID = id
					res.Rows[i].Resolved = true
				}
			}
		}
		writeJSON(w, res)
	}
}

// ledgerPlansHandler keeps the same authentication and axis parser as events.
func ledgerPlansHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", 405)
			return
		}
		if ledgerIndex == nil {
			http.Error(w, "ledger index unavailable", 503)
			return
		}
		f, resolution, ok := parseLedgerFilter(w, r)
		if !ok {
			return
		}
		if resolution == "unresolved" {
			writeJSON(w, ledgerq.PlansResult{Plans: []ledgerq.PlanSummary{}, Resolution: resolution, Verify: ledgerq.Verify{State: "unverified"}})
			return
		}
		result, err := ledgerIndex.QueryPlans(f, time.Now())
		if err != nil {
			ledgerQueryError(w, err)
			return
		}
		result.Resolution = resolution
		writeJSON(w, result)
	}
}

func ledgerQueryError(w http.ResponseWriter, err error) {
	if strings.HasPrefix(err.Error(), "cursor:") {
		http.Error(w, "invalid ledger cursor", http.StatusBadRequest)
		return
	}
	http.Error(w, "ledger query unavailable", http.StatusServiceUnavailable)
}

// runReindex rebuilds the index from scratch and prints what it found.
func runReindex(indexPath, blackboxDir, telemetryDir string) int {
	d, cs, ts, err := ledgerq.Rebuild(indexPath, blackboxDir, telemetryDir, time.Now())
	if err != nil {
		fmt.Fprintf(os.Stderr, "reindex: %v\n", err)
		return 1
	}
	defer d.Close()
	st, _ := d.StatsAsRecorded()
	out, _ := json.Marshal(map[string]any{
		"index": indexPath, "blackbox_dir": blackboxDir, "chain": cs, "telemetry": ts, "stats": st,
	})
	fmt.Println(string(out))
	if cs.State == "chain_error" {
		return 1
	}
	return 0
}

// runIndexCheck re-derives every chain row from its origin (G-LED-02).
func runIndexCheck(indexPath, blackboxDir string) int {
	d, err := ledgerq.Open(indexPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "index-check: %v\n", err)
		return 1
	}
	defer d.Close()
	rep, err := d.CheckOrigins(blackboxDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "index-check: %v\n", err)
		return 1
	}
	out, _ := json.Marshal(rep)
	fmt.Println(string(out))
	if !rep.OK() {
		return 1
	}
	return 0
}

// serveDashboard hands out the embedded page and its three script files by
// exact name — no directory listing, no path walking, anything else is 404
// (consoleui discipline). GET/HEAD only; no-store so a rebuilt binary is never
// masked by a stale cached shell.
// serveDashboardWith serves the page with a capability meta tag for the robot
// operations projection: when PAIL_ROBOTOPS_PROJECTION is unset the page carries
// content="off" and robotops.js never requests the endpoint, so a demo
// collector shows no 404 in the browser console (P22-N4).
func serveDashboardWith(robotops bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		serveDashboardPage(w, r, robotops)
	}
}

func serveDashboard(w http.ResponseWriter, r *http.Request) { serveDashboardPage(w, r, false) }

const robotopsMetaPlaceholder = `<meta name="pail-robotops" content="unknown">`

func serveDashboardPage(w http.ResponseWriter, r *http.Request, robotops bool) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/dashboard/")
	ctype := ""
	switch name {
	case "", "index.html":
		name, ctype = "index.html", "text/html; charset=utf-8"
	case "shared.js", "adapters.js", "reason_dict.js", "i18n.js", "robotops.js", "fleet.js", "status_ledger.js":
		ctype = "text/javascript; charset=utf-8"
	default:
		http.NotFound(w, r)
		return
	}
	body, err := dashboardFS.ReadFile("dashboard/" + name)
	if err != nil {
		http.Error(w, "embed read: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if name == "index.html" {
		flag := "off"
		if robotops {
			flag = "on"
		}
		body = []byte(strings.Replace(string(body), robotopsMetaPlaceholder, `<meta name="pail-robotops" content="`+flag+`">`, 1))
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Cache-Control", "no-store")
	w.Write(body)
}

func parseFilter(w http.ResponseWriter, r *http.Request) (telemetry.Filter, bool) {
	q := r.URL.Query()
	var f telemetry.Filter
	u64 := func(key string) (uint64, bool) {
		s := q.Get(key)
		if s == "" {
			return 0, true
		}
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			http.Error(w, key+": "+err.Error(), http.StatusBadRequest)
			return 0, false
		}
		return v, true
	}
	var ok bool
	if f.FromMs, ok = u64("from_ms"); !ok {
		return f, false
	}
	if f.ToMs, ok = u64("to_ms"); !ok {
		return f, false
	}
	if f.ToMs == 0 {
		// an open-ended window ends now: coverage must judge the span up to
		// the present, or "no gap" quietly stops meaning "listening currently"
		f.ToMs = uint64(time.Now().UnixMilli())
	}
	f.Event = q.Get("event")
	f.Robot = q.Get("robot")
	if s := q.Get("reason"); s != "" {
		v, err := strconv.ParseUint(s, 0, 16)
		if err != nil {
			http.Error(w, "reason: "+err.Error(), http.StatusBadRequest)
			return f, false
		}
		rv := uint16(v)
		f.Reason = &rv
	}
	if s := q.Get("limit"); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil || v < 0 {
			http.Error(w, "limit: invalid", http.StatusBadRequest)
			return f, false
		}
		f.Limit = v
	}
	return f, true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		fmt.Fprintf(os.Stderr, "encode: %v\n", err)
	}
}

// projectionSourceFromEnv reads PAIL_ROBOTOPS_PROJECTION (absolute file path;
// unset disables the endpoint) and PAIL_ROBOTOPS_PROJECTION_MAX_AGE_S (default
// 300) after which the snapshot is served with stale=true.
func projectionSourceFromEnv() *projectionSource {
	path := os.Getenv("PAIL_ROBOTOPS_PROJECTION")
	if path == "" {
		return nil
	}
	maxAge := 300 * time.Second
	if v := os.Getenv("PAIL_ROBOTOPS_PROJECTION_MAX_AGE_S"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 86400 {
			maxAge = time.Duration(n) * time.Second
		} else {
			fmt.Fprintf(os.Stderr, "PAIL_ROBOTOPS_PROJECTION_MAX_AGE_S invalid (%q); using 300\n", v)
		}
	}
	return newProjectionSource(path, maxAge)
}

// observationStore is assigned once, before HTTP starts.
var observationStore *telemetry.Store

var observationIngress *telemetry.Ingress

func currentStorageHealth() telemetry.StorageHealth {
	if observationIngress != nil {
		return observationIngress.Health()
	}
	if observationStore != nil {
		return observationStore.Health()
	}
	return telemetry.StorageHealth{State: "UNAVAILABLE"}
}

func storageHeaders(w http.ResponseWriter) {
	w.Header().Set("X-PAIL-Storage-Status", "/v1/telemetry/storage")
	raw := ledgerIndex.StorageHealth().Raw
	if observationStore != nil {
		raw = currentStorageHealth()
	}
	w.Header().Set("X-PAIL-Raw-Complete", strconv.FormatBool(!raw.RawIncomplete))
}
