// adapters.js — 데이터 어댑터 2종 (observation UI contract). 표시는 shared.js 한 벌이고
// 여기서는 재료(materials)·이력 행·커버리지만 나른다. 두 어댑터의 출력 형상은
// 같다: onUpdate({ materials, rows, coverage, status }).
"use strict";

// ---- OpsAdapter: telemetryd 조회 API 폴링 (D2 — 응답이 커버리지를 품는다) ----
// windowMs 조회 창을 매 pollMs 마다 다시 묻는다. 0건 응답도 커버리지와 함께
// 오므로 "없었음"과 "못 들었음"이 갈린다.
function OpsAdapter(opts) {
  const base = (opts && opts.base) || "";
  const windowMs = (opts && opts.windowMs) || 15 * 60 * 1000;
  const pollMs = (opts && opts.pollMs) || 3000;
  const onUpdate = opts.onUpdate;
  let timer = null;
  // Filters (observation UI contract): 필터는 페이지가 URL 에서 풀어 넘긴다. 없으면 종전 창
  // (now-windowMs .. now) 과 같다 — 필터 바가 없던 화면과 동일한 조회.
  let filter = (opts && opts.filter) || null;

  function mapRow(r) {
    return {
      ms: r.ms,
      event: r.event,
      reason: r.reason_value, // 수치 — reasonText 가 사전으로 푼다
      robot: r.robot,
      token: r.token,
      sig: r.sig,
      dup: r.dup === true,
    };
  }

  // DB-2: permit 생존 미러 조회. 실패는 **빈 목록이 아니라 null** 이다 —
  // 0건("물었고 아무 로봇도 말하지 않았다")과 미조회("못 물었다")가 같은 값이
  // 되면 조회 배선 사고가 현장 상태로 도착한다.
  async function fetchPermits() {
    try {
      const resp = await fetch(base + "/v1/telemetry/permits");
      if (!resp.ok) throw new Error("permits HTTP " + resp.status);
      const body = await resp.json();
      return Array.isArray(body) ? body : null;
    } catch (e) {
      return null;
    }
  }

  // 조회 창·로봇 조건을 URL 쿼리로 만든다. robot 은 해시(16바이트 hex)로만
  // 보낸다 — 이름→해시 해소는 페이지의 resolver 몫이고 서버 계약(v1)은 불변.
  function queryString() {
    let fromMs = Date.now() - windowMs, toMs = null, robot = null;
    if (filter) {
      const w = filterWindow(filter, Date.now());
      fromMs = w.fromMs; toMs = w.toMs; robot = filter.robotHash || null;
    }
    // 행 상한. 서버는 넘치면 **최신** N행을 남기고 truncated/matched 로 말한다
    // (G-DSH-07). 200 이던 때 6시간 창(525건)이 오래된 200건으로 잘려 최근 차단
    // 165건이 화면에 오지 않았다(2026-09-04 실측). 상한은 튜닝값이고 정직성은
    // 서버 답 + computeTile 의 잘림 분기가 맡는다 — 값을 키운 것이 고침이 아니다.
    let qs = "from_ms=" + fromMs + "&limit=1000";
    if (toMs !== null && toMs !== undefined) qs += "&to_ms=" + toMs;
    if (robot) qs += "&robot=" + encodeURIComponent(robot);
    return qs;
  }

  async function poll() {
    const qs = queryString();
    // DB-2: permit 생존 미러를 **먼저** 묻는다. decisions 와 다른 실패
    // 도메인이므로 이력이 안 와도 로봇별 행은 그려져야 한다.
    const permitRows = await fetchPermits();
    const permitMat = {
      permit: foldPermit(permitRows),
      permitQueried: permitRows !== null,
      permitAlive: null,
      gatePermit: null,
    };
    try {
      const resp = await fetch(base + "/v1/telemetry/decisions?" + qs);
      if (!resp.ok) throw new Error("decisions HTTP " + resp.status);
      const body = await resp.json();
      const rows = (body.rows || []).map(mapRow);
      const coverage = body.coverage || null;
      // G-DSH-07: 잘림은 서버가 말하고 화면은 그대로 나른다. 여기서 떨어뜨리면
      // 타일이 창 전체를 봤다고 주장한다.
      const truncated = body.truncated === true;
      const matched = typeof body.matched === "number" ? body.matched : rows.length;
      onUpdate({
        materials: Object.assign({
          mode: "ops",
          recentBursts: rows,
          coverage: coverage,
          truncated: truncated,
          matched: matched,
        }, permitMat),
        rows: rows,
        permitRows: permitRows || [],
        coverage: coverage,
        status: pailT("폴링 중 (") + (pollMs / 1000) + "s)" +
          (truncated ? pailT(" · 조회 상한에 잘림: 창 ") + matched + pailT("건 중 최신 ") + rows.length + pailT("건") : "") +
          (permitRows === null ? pailT(" · permit 조회 실패") : ""),
      });
    } catch (e) {
      // 조회 실패는 회색 재료다 — 마지막 성공 화면을 조용히 유지하면
      // "수집기가 죽었다"가 "정상"으로 읽힌다 (H-B2).
      onUpdate({
        materials: Object.assign({ mode: "ops", recentBursts: [],
                                   coverage: null }, permitMat),
        rows: [],
        permitRows: permitRows || [],
        coverage: null,
        status: pailT("조회 실패: ") + e.message,
      });
    }
  }

  return {
    start: function () { poll(); timer = setInterval(poll, pollMs); },
    stop: function () { if (timer) clearInterval(timer); timer = null; },
    // 필터 교체는 즉시 한 번 다시 묻는다 — 다음 폴까지 옛 창이 서 있으면
    // "적용했는데 안 바뀐다"가 3초 동안 참이다.
    setFilter: function (f) { filter = f || null; poll(); },
    query: queryString,
  };
}

// burst v2 raw hex → 로봇 해시 32자. 배치는 packet_v2.go 의 것이고 여기서는
// 자리만 읽는다 — 서명 검증은 하지 않는다(허브의 ok 가 그 사실을 따로 싣는다).
function robotHashFromRawHex(rawHex) {
  const h = String(rawHex || "").toLowerCase();
  if (h.length !== 240 || h.slice(0, 8) !== "5041494c" || h.slice(8, 10) !== "02") return "";
  return h.slice(32, 64);
}


// ---- LedgerAdapter (Timeline, observation UI contract): /v1/ledger/events 폴링 — 타임라인 탭 전용 ----
// 응답을 그대로 나른다: rows · verify · resolution · coverage · index. 판정은 서버가 서고
// 화면은 묶어 보일 뿐이다. 조회 실패는 null 재료다(마지막 성공 화면을 남기지 않는다).
function LedgerAdapter(opts) {
  const base = (opts && opts.base) || "";
  const pollMs = (opts && opts.pollMs) || 5000;
  const onUpdate = opts.onUpdate;
  let filter = (opts && opts.filter) || null;
  let timer = null, generation = 0, controller = null;
  let cursor = "", nextCursor = "", page = 1, frozenQuery = null, mode = "events";

  function queryString() {
    let qs = "limit=2000";
    if (filter && filter.aroundMs) {
      qs += "&around_ms=" + filter.aroundMs + "&span_ms=" + (filter.spanMs || 60000);
    } else {
      const w = filter ? filterWindow(filter, Date.now()) : { fromMs: Date.now() - 15 * 60 * 1000, toMs: null };
      qs += "&from_ms=" + w.fromMs + "&to_ms=" + (w.toMs == null ? Date.now() : w.toMs);
    }
    if (filter && filter.robotHash) qs += "&robot=" + encodeURIComponent(filter.robotHash);
    if (filter && filter.outcome) qs += "&outcome=" + encodeURIComponent(filter.outcome);
    if (filter && filter.planID) qs += "&plan_id=" + encodeURIComponent(filter.planID);
    return qs;
  }

  async function poll() {
    const mine = ++generation;
    if (controller) controller.abort();
    controller = new AbortController();
    if (!cursor) frozenQuery = queryString();
    const qs = frozenQuery + (cursor ? "&cursor=" + encodeURIComponent(cursor) : "");
    try {
      const resp = await fetch(base + "/v1/ledger/" + mode + "?" + qs, {signal: controller.signal});
      if (!resp.ok) throw new Error("ledger HTTP " + resp.status);
      const body = await resp.json();
      if (mine !== generation) return;
      nextCursor = body.next_cursor || "";
      onUpdate({rows: body.rows || [], plans: body.plans || [], mode: mode, page: page,
        verify: body.verify, resolution: body.resolution, coverage: body.coverage, index: body.index,
        next_cursor: nextCursor, query: qs, status: "Page " + page + " · " + (mode === "plans" ? (body.plans || []).length + " plan summaries" : (body.rows || []).length + " events") + (nextCursor ? " · More pages in selected range" : " · End of selected range")});
    } catch (e) {
      if (mine !== generation) return;
      nextCursor = "";
      onUpdate({rows: null, next_cursor: "", verify: null, query: qs, status: pailT("원장 조회 실패: ") + e.message});
    }
  }
  function reset() {cursor = ""; nextCursor = ""; page = 1; frozenQuery = null; return poll();}
  return {
    start: function () { poll(); timer = setInterval(function () { if (!cursor) poll(); }, pollMs); },
    stop: function () { ++generation; if (controller) controller.abort(); if (timer) clearInterval(timer); timer = null; },
    setFilter: function (f) { filter = f || null; return reset(); },
    setMode: function (m) { mode = m === "plans" ? "plans" : "events"; filter = Object.assign({}, filter, {planID:null}); return reset(); },
    next: function () { if (!nextCursor) return Promise.resolve(); cursor = nextCursor; nextCursor = ""; page++; return poll(); },
    first: reset,
    drill: function (id) { filter = Object.assign({}, filter, {planID:id}); mode = "events"; return reset(); },
    query: queryString,
  };
}

// ---- DemoAdapter: 데모 허브 웹소켓 패널 소비 (D5 — 같은 화면 + 데모 재료) ----
// 허브(demo-web :8600)는 수집기 발신 원문을 그대로 중계한다. 봉투는 평면
// `{"type": ...}` (demo/collector/panels.py 실형상, 2026-09-02 대조):
//   {"type":"burst","bursts":[{seq,event,reason(이름),ok,unix_ms,raw_hex}],"rejected":n}
//   {"type":"gate","state":"PERMIT"|...,"reason"}
//   {"type":"permit","alive":bool,"seq","age_ms"}
// burst 패널은 델타가 아니라 **꼬리 12건 스냅샷**이 주기 재송신된다
// (agent.slow_tick) — 덧붙이면 스냅샷마다 중복 누적이므로 통째 교체한다.
// permit.alive 는 신선도가 있다 — 마지막 수신에서 staleMs 지나면 재료를
// null(모름)로 되돌린다: 수집기가 죽으면 alive:false 조차 오지 않는다.
function DemoAdapter(opts) {
  const hub = opts.hub; // 예: "ws://127.0.0.1:8600/ui"
  const onUpdate = opts.onUpdate;
  const staleMs = (opts && opts.staleMs) || 5000;
  let ws = null, sweep = null;
  let rows = [];
  let permitAlive = null, permitSeenMs = 0;
  let gatePermit = null;

  function emit(status) {
    onUpdate({
      materials: {
        mode: "demo",
        recentBursts: rows,
        coverage: null, // 데모 재료에 커버리지는 없다 — 화면은 "미조회"로 그린다
        permitAlive: permitAlive,
        gatePermit: gatePermit,
      },
      rows: rows,
      coverage: null,
      status: status,
    });
  }

  function onMessage(ev) {
    let msg;
    try { msg = JSON.parse(ev.data); } catch (e) { return; }
    if (msg.type === "burst" && Array.isArray(msg.bursts)) {
      // 스냅샷 통째 교체 (위 주석 — 덧붙이면 재송신마다 중복 누적)
      rows = msg.bursts.map(function (b) {
        return {
          ms: b.unix_ms,
          event: b.event,
          reason: b.reason, // 이름 문자열 — reasonText 가 그대로/해설 붙여 그린다
          // Filters: 허브 봉투에는 robot 칸이 없다 — raw_hex(120B v2 패킷)의
          // [16:32] 가 sha256(robot_id)[:16] 이므로 거기서 꺼낸다(burst v2 배치,
          // internal/burst/packet_v2.go). v2 가 아니면 빈 값 = 「해시 없음」.
          robot: b.robot || robotHashFromRawHex(b.raw_hex),
          token: b.token || "",
          sig: b.ok === true ? "ok" : b.ok === false ? "bad" : "?",
          dup: false,
        };
      });
    } else if (msg.type === "gate") {
      gatePermit = msg.state === "PERMIT" ? true
        : msg.state ? false : null;
    } else if (msg.type === "permit") {
      permitAlive = msg.alive === true ? true
        : msg.alive === false ? false : null;
      permitSeenMs = Date.now();
    } else {
      return; // 다른 패널(pose/chain/token/...)은 이 화면의 재료가 아니다
    }
    emit(pailT("허브 연결됨"));
  }

  function sweepStale() {
    if (permitAlive === true && Date.now() - permitSeenMs > staleMs) {
      permitAlive = null; // 낡은 생존 신호는 초록 재료가 아니다
      emit(pailT("허브 연결됨 (permit 신호 낡음)"));
    }
  }

  return {
    setFilter: function () {},  // 데모 허브는 조회가 아니라 중계다 — 필터 없음
    start: function () {
      ws = new WebSocket(hub);
      ws.onmessage = onMessage;
      ws.onopen = function () { emit(pailT("허브 연결됨")); };
      ws.onclose = function () {
        permitAlive = null; gatePermit = null;
        emit(pailT("허브 연결 끊김 — 초록 재료 소멸"));
      };
      ws.onerror = function () { emit(pailT("허브 연결 오류")); };
      sweep = setInterval(sweepStale, 1000);
      emit(pailT("허브 연결 시도: ") + hub);
    },
    stop: function () {
      if (ws) ws.close();
      if (sweep) clearInterval(sweep);
    },
  };
}

// node 테스트용 export (브라우저에서는 무해하게 건너뛴다)
if (typeof module !== "undefined" && module.exports) {
  module.exports = { OpsAdapter: OpsAdapter, DemoAdapter: DemoAdapter };
}
