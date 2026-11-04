// shared.js — 판정 타일·사유 해설·이력·커버리지 표시 모듈 한 벌 (observation UI contract).
// 표시는 여기 한 벌뿐이고 데이터는 adapters.js 의 어댑터 2종이 나른다.
// 판정 값은 전부 API/스트림 원문이다 — 이 파일은 그리기만 한다 (H5).
"use strict";

// D4: 초록은 "차단 없음"이 아니다. 붉음=차단 실증, 초록=허용 실증(수신된
// 신호만), 회색=모름. 허용 실증 재료 없이 "최근 차단 없음"을 초록으로 그리면
// 결측을 정상으로 적는 것이다 (H-B2). 운영 모드의 그 재료는 permit 생존
// 미러다 (D11) — 미러가 말을 멈추면 초록도 꺼진다.
// AUTHORITY_WITHHELD (OI-04): the issuer stopped serving this robot because its
// gate's attestation is invalid or expired; the chain itself is not revoked.
const RED_EVENTS = { BLOCK: true, ESTOP: true, CHAIN_REVOKED: true, AUTHORITY_WITHHELD: true };

// materials: {
//   mode: "demo"|"ops",
//   recentBursts: [{event, sig|ok, ...}]  — 표시 창 안의 버스트,
//   coverage: {gaps:[...], listened_ratio} | null  — ops 조회 창의 커버리지,
//   permit: {state:"alive"|"absent"|"unknown", robot, key_role} | null
//                                 — ops 조회 API 가 판정한 permit 미러 재료,
//   permitAlive: true|false|null  — 허용 실증 신호 (demo: permit 패널),
//   gatePermit: true|false|null   — demo 백엔드의 명시 게이트 통지
// }
// 반환: { color: "red"|"green"|"gray", label, why }
function computeTile(m) {
  const verified = (m.recentBursts || []).filter(function (b) {
    return b.sig === "ok" || b.ok === true;
  });
  const red = verified.filter(function (b) { return RED_EVENTS[b.event]; });
  if (red.length > 0) {
    return { color: "red", label: pailT("차단 (DENY)"),
             why: pailT("서명 검증된 차단 버스트 ") + red.length + pailT("건 수신") };
  }
  if (m.mode === "demo") {
    if (m.permitAlive === true) {
      return { color: "green", label: pailT("허용 (ALLOW)"),
               why: pailT("permit 생존 신호 수신 중") };
    }
    if (m.gatePermit === true) {
      return { color: "green", label: pailT("허용 (ALLOW)"),
               why: pailT("데모 백엔드 게이트 통지 = PERMIT") };
    }
    return { color: "gray", label: pailT("모름 (UNKNOWN)"),
             why: pailT("허용 실증 신호 부재") };
  }
  // ops (D11): 초록 재료는 permit 생존 미러다. 커버리지 갭이 먼저다 — 타일은
  // 창 전체의 진술이고, 못 들은 구간 위의 초록은 평온을 사칭한다.
  const cov = m.coverage;
  if (!cov) {
    return { color: "gray", label: pailT("모름 (UNKNOWN)"), why: pailT("커버리지 미조회") };
  }
  if ((cov.gaps || []).length > 0) {
    return { color: "gray", label: pailT("모름 (UNKNOWN)"),
             why: pailT("수집기 갭 ") + cov.gaps.length + pailT("구간 — 못 들은 시간이 있다") };
  }
  // G-DSH-07: 조회 상한에 잘린 페이지는 창 전체가 아니다. 서버는 최신을 남기고
  // 잘렸다고 말하는데(matched·truncated), 화면이 그 위에 초록을 그리면 못 본
  // 오래된 구간의 차단이 평온으로 도착한다 — 갭 위의 초록과 같은 사칭이다
  // (2026-09-04 실측: 6시간 창 525건 중 200건만 받고 평온으로 그렸다).
  if (m.truncated === true) {
    return { color: "gray", label: pailT("모름 (UNKNOWN)"),
             why: pailT("조회 상한에 잘림 — 창의 ") + (m.matched || "?") + pailT("건 중 최신 ") +
                  (m.recentBursts || []).length + pailT("건만 봤다. 창을 좁혀라") };
  }
  const p = m.permit;
  if (!p) {
    // 회색 셋째 갈래. 「물었는데 0건」과 「안 물어봤다」가 같은 문장으로 접히면
    // 조회 배선이 끊긴 날 화면이 "미러가 하나도 없다"고 말한다 — 배선 사고가
    // 현장 상태로 도착하는 형태다.
    if (m.permitQueried) {
      return { color: "gray", label: pailT("모름 (UNKNOWN)"),
               why: pailT("미러 진술 0건 — 물었고, 아무 로봇도 말하지 않았다") };
    }
    return { color: "gray", label: pailT("모름 (UNKNOWN)"),
             why: pailT("permit 미러 미조회 — 안 물어본 것은 답이 아니다") };
  }
  // 서명 신원 없는 진술은 재료가 아니다. 있으면 아무 UDP 발신자나 초록을 켠다.
  if (!p.key_role) {
    return { color: "gray", label: pailT("모름 (UNKNOWN)"),
             why: pailT("미러 진술에 서명 신원 없음 — 누구의 증언인지 모른다") };
  }
  if (p.state === "alive") {
    return { color: "green", label: pailT("허용 (ALLOW)"),
             why: pailT("미러가 서명으로 증언한 permit 생존") };
  }
  // 회색 둘을 가른다. 접히면 미러 사망이 "정지 중"으로 읽힌다 (H-B2 의 회색판).
  //
  // 해설의 앞은 화면이 접어서 얻은 사실(어느 행이 이겼고 어느 갈래인가)이고,
  // 뒤는 **서버가 그 행에 적은 사유**다. 화면이 뒤까지 지어내면 서버가
  // 「미러 침묵」(왔는데 늦었다)이라 한 것을 「신호 없음」(오지 않았다)으로
  // 바꿔 말하게 되고, 로봇이 여럿일 때 어느 로봇이 왜인지가 통째로 사라진다.
  // 판정도 사유도 서버 몫이다(H5).
  if (p.state === "absent") {
    return { color: "gray", label: pailT("허용 아님 (NO PERMIT)"),
             why: permitWho(p) + pailT("미러는 말했고, 그 말이 허용 아님 — ") +
                  permitWhy(p) };
  }
  return { color: "gray", label: pailT("모름 (UNKNOWN)"),
           why: permitWho(p) + pailT("미러의 말로 허용 여부를 세우지 못했다 — ") +
                permitWhy(p) };
}

// 접힌 행의 이름. 없으면 비우지 않고 **없다고 적는다** — 로봇이 여럿일 때
// 이름 없는 사유는 어느 로봇의 것인지 모르는 채로 창 전체를 대표한다.
function permitWho(p) {
  return p.robot ? pailT("로봇 ") + p.robot + ": " : pailT("로봇 미상: ");
}

// 서버가 사유를 안 줬으면 화면이 채우지 않는다. 채우는 순간 그 문장은
// 서버의 판정처럼 읽히고, 사유 배선이 끊긴 날 아무도 그것을 못 본다.
function permitWhy(p) {
  return p.why ? pailT(p.why) : pailT("(서버 사유 없음)");
}

// ---- DB-2 운영자 뷰: 로봇별 행 ----------------------------------------
//
// 행의 판정은 조회 API 가 세운다(H5) — 여기서는 접고 그린다.

// 부팅 후 permit 무수신. 나이가 아니라 **진술**이다(mirror.go PermitAgeNever).
// 숫자로 그리면 49일짜리 나이로 읽히고, 그 순간 "한 번도 못 받았다"가
// "아주 오래됐다"로 도착한다.
const PERMIT_AGE_NEVER = 4294967295;

// 로봇 N행을 타일 재료 1개로 접는다. **가장 덜 확실한 행이 이긴다**:
// 모름 > 허용 아님 > 생존. 초록으로 접으면 말 없는 로봇이 말하는 로봇의 초록
// 뒤에 숨는다 — 타일은 창 전체의 진술이므로 한 로봇이라도 모르면 모름이다.
const PERMIT_RANK = { unknown: 3, absent: 2, alive: 1 };

function foldPermit(rows) {
  if (!rows || rows.length === 0) return null;
  let worst = rows[0];
  for (const r of rows) {
    const a = PERMIT_RANK[r.state] || 3; // 모르는 state 는 모름 취급 (기본 통과 금지)
    const b = PERMIT_RANK[worst.state] || 3;
    if (a > b) { worst = r; continue; }
    // 같은 등급에서는 신원 없는 진술이 앞선다 — 초록 재료가 될 수 없는 쪽이다.
    if (a === b && !r.key_role && worst.key_role) worst = r;
  }
  return worst;
}

function permitAgeText(ms) {
  if (ms === PERMIT_AGE_NEVER) return pailT("무수신");
  if (typeof ms !== "number") return "";
  return String(ms) + "ms";
}

// 0 은 값이 아니라 미관찰이다(record.go 가 omitempty 를 두지 않은 이유와 같다).
function observedMs(ms) {
  return ms ? String(ms) + "ms" : pailT("미관찰");
}

// 상태 셀. `alive` 라도 **신원이 없으면 초록이 아니다** — 서버가 그 조합을
// 내지 않는다는 것은 서버의 불변조건이지 화면의 것이 아니고, 화면이 그것을
// 믿으면 서버가 바뀐 날 아무도 안 붉는다.
function permitStateCell(r) {
  if (r.state === "alive" && r.key_role) {
    return pailT('<span class="ok">허용 실증</span>');
  }
  if (r.state === "absent") return pailT('<span class="unv">허용 아님</span>');
  if (r.state === "alive") return pailT('<span class="unv">모름 (신원 없음)</span>');
  return pailT('<span class="unv">모름</span>');
}

function renderPermitRows(rows, resolver) {
  if (!rows || rows.length === 0) {
    return pailT('<tr><td colspan="8" class="unv">미러 진술 없음</td></tr>');
  }
  return rows.map(function (r) {
    return "<tr>" +
      "<td>" + renderRobotCell(r.robot || "", resolver) + "</td>" +
      "<td>" + permitStateCell(r) + "</td>" +
      '<td class="note">' + esc(pailT(r.why || "")) + "</td>" +
      "<td>" + esc(observedMs(r.mirror_age_ms)) + "</td>" +
      "<td>" + esc(permitAgeText(r.permit_age_ms)) + "</td>" +
      "<td>" + esc(observedMs(r.deadman_window_ms)) + "</td>" +
      "<td>" + esc(r.mode || pailT("미관찰")) + "</td>" +
      '<td><button class="unlock-btn" data-robot="' + esc(r.robot || "") +
        pailT('">잠금 해제 요청</button></td>') +
      "</tr>";
  }).join("");
}

// unlock 요청 (상위설계 §2.1: "서명은 운영자 키 — 화면은 요청 UI 만").
//
// **화면도 telemetryd 도 서명하지 않는다.** 서명하려면 운영자 개인키를 수집
// 프로세스나 브라우저에 들여놔야 하고, 그것은 D11 실측 1 이 게이트에 대해
// 기각한 것과 같은 변경이다(안전·수집 계통에 개인키 도입). 그래서 이 함수가
// 내는 것은 결과가 아니라 **사람이 자기 키로 실행할 명령문**이다.
//
// 표의 로봇 열은 `sha256(robot_id)[:16]` 이지 평문이 아니다. 해시를 그대로
// `-robot` 에 끼우면 조용히 다른 로봇을 가리키는 명령이 만들어지므로, 평문은
// 사람이 적고 화면은 **그 평문의 해시가 이 행과 같을 때만** 명령을 낸다.
// 대조할 수 없으면 명령을 내지 않는다 — 확인 못 한 것을 확인된 것처럼
// 내주는 것이 H-B2 다.
async function unlockCommand(robotId, rowHash, addr) {
  if (!robotId) return { ok: false, reason: pailT("robot_id 미입력") };
  const subtle = (typeof globalThis !== "undefined" && globalThis.crypto &&
                  globalThis.crypto.subtle) || null;
  if (!subtle) {
    return { ok: false, reason:
      pailT("이 컨텍스트에서 SHA-256 을 계산할 수 없다 — 행과 대조하지 못한 명령은 내지 않는다") };
  }
  const digest = await subtle.digest("SHA-256",
    new TextEncoder().encode(robotId));
  const hex = Array.prototype.map.call(
    new Uint8Array(digest).slice(0, 16),
    function (b) { return b.toString(16).padStart(2, "0"); }).join("");
  if (hex !== String(rowHash || "").toLowerCase()) {
    return { ok: false, reason:
      pailT("입력한 robot_id 의 해시가 이 행과 다르다 (") + hex + " ≠ " + rowHash + ")" };
  }
  return { ok: true, robot: robotId, command:
    "operator_cli -mode unlock -robot " + robotId +
    " -addr " + (addr || "127.0.0.1:50051") };
}

// 사유 표시: 값 → {code, desc} (reason_dict.js 파생물). 미등재는 UNMAPPED
// 원값 노출 (D6). reasonLike 는 수치(ops JSONL reason_value) 또는 데모
// 패널의 이름 문자열을 받는다.
function reasonText(reasonLike) {
  if (typeof reasonLike === "number") {
    const e = pailReasonInfo(reasonLike);
    return e.desc ? e.code + " — " + PAIL_I18N.reason(e.code, e.desc) : e.code;
  }
  if (typeof reasonLike === "string" && reasonLike) {
    for (const k in PAIL_REASON_DICT) {
      if (PAIL_REASON_DICT[k].code === reasonLike) {
        const d = PAIL_REASON_DICT[k].desc;
        return d ? reasonLike + " — " + PAIL_I18N.reason(reasonLike, d) : reasonLike;
      }
    }
    return reasonLike; // 이름은 있는데 사전 밖 — 원문 그대로 (숨기지 않는다)
  }
  return "";
}

function fmtMs(ms) {
  if (!ms) return "";
  const d = new Date(Number(ms));
  return d.toLocaleTimeString("ko-KR", { hour12: false }) + "." +
         String(Number(ms) % 1000).padStart(3, "0");
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
}

// 이력 행 렌더링. row: {ms, event, reason(수치|이름), robot, token, sig, dup}
// 증거 하강(D7): token_hash+unix_ms 근방 탐색은 근사다 — 배지로 명시하고
// 확정 증거는 체인 검증으로 내려간다 (텔레메트리≠정본).
// 사유 칸. CHECKPOINT 버스트의 reason 0 은 「허용」이 아니라 「판정이 아니다」 —
// 사전의 0x00 은 판정면의 OK 인데 체크포인트는 판정을 싣지 않는다. 그대로 찍으면
// 「OK — 허용 — 거부 아님」이 체인 체크포인트 행마다 서서, 아무 판정도 없던 창이
// 「허용됐다」로 읽힌다(2026-09-04 Yang 실측: 1-1 무단 발행 뒤 「허용」이 떴다고 물었다).
function historyReasonCell(r) {
  if (r.event === "CHECKPOINT") {
    return pailT('<span class="unv">판정 아님 — 체인 체크포인트</span>') +
      (r.reason ? " (reason " + esc(String(r.reason)) + ")" : "");
  }
  return esc(reasonText(r.reason));
}

function renderHistoryRows(rows, resolver) {
  return rows.map(function (r) {
    const sig = r.sig === "ok" ? '<span class="ok">ok</span>'
      : r.sig === "bad" ? '<span class="bad">bad</span>'
      : '<span class="unv">' + esc(r.sig || "?") + "</span>";
    const badge = r.token
      ? pailT('<span class="approx" title="token_hash+시각 근방 탐색 — 확정 증거는 ') +
        pailT('블랙박스 체인 검증으로 확인">근사 매칭</span>')
      : "";
    return "<tr>" +
      "<td>" + esc(fmtMs(r.ms)) + "</td>" +
      "<td class=\"ev-" + esc(String(r.event || "").toLowerCase()) + "\">" + esc(r.event || "") + "</td>" +
      "<td>" + historyReasonCell(r) + "</td>" +
      "<td>" + renderRobotCell(r.robot || "", resolver) + "</td>" +
      "<td class=\"mono\">" + esc((r.token || "").slice(0, 16)) + " " + badge + "</td>" +
      "<td>" + sig + "</td>" +
      "<td>" + (r.dup ? "dup" : "") + "</td>" +
      "</tr>";
  }).join("");
}

// 커버리지 표시 (D2): 0건 응답이 "없었음"인지 "못 들었음"인지를 응답이
// 스스로 가른다 — 그 분리를 화면에서도 유지한다.
function renderCoverage(cov) {
  if (!cov) return pailT('<span class="unv">커버리지 미조회</span>');
  const ratio = (cov.listened_ratio * 100).toFixed(1) + "%";
  if (!cov.gaps || cov.gaps.length === 0) {
    return pailT('<span class="ok">청취율 ') + ratio + pailT(" · 갭 없음</span>") +
           pailT('<span class="note"> (UDP 유실은 재지 못한다 — 살아 있었다는 뜻일 뿐)</span>');
  }
  const g = cov.gaps.map(function (x) {
    return fmtMs(x.from_ms) + "~" + fmtMs(x.to_ms);
  }).join(", ");
  return pailT('<span class="bad">청취율 ') + ratio + pailT(" · 갭 ") + cov.gaps.length +
         pailT("구간: ") + esc(g) + "</span>";
}


// ---- Filters (observation UI contract): 로봇 해시 → 이름 해소 ----------------------------
//
// 화면의 로봇 열은 burst 가 싣는 sha256(robot_id)[:16] 이다. 이름은 수집기가
// robot_registry.yaml 에서 읽어 /v1/telemetry/registry 로 실어 보낸 것으로만
// 푼다 — 화면이 파일을 따로 읽지 않는다(한 벌). 레지스트리에 없는 해시는
// **비우지 않고 「미해소」로 적는다**: 빈 칸은 "이름이 없다"와 "안 물어봤다"를
// 같은 바이트로 만든다(H-B2). registry 응답이 없으면 source="absent" 로 남긴다.
function buildRobotResolver(body) {
  const map = {};
  const robots = (body && Array.isArray(body.robots)) ? body.robots : [];
  for (const r of robots) {
    if (r && r.robot_hash && r.robot_id) map[String(r.robot_hash).toLowerCase()] = String(r.robot_id);
  }
  return {
    source: (body && body.source) ? String(body.source) : "absent",
    resolve: function (hash) {
      const h = String(hash || "").toLowerCase();
      if (!h) return { hash: "", robot_id: null, resolved: false };
      if (Object.prototype.hasOwnProperty.call(map, h)) return { hash: h, robot_id: map[h], resolved: true };
      return { hash: h, robot_id: null, resolved: false };
    },
    hashOf: function (name) {
      for (const h in map) if (map[h] === name) return h;
      return null;
    },
    names: function () {
      return Object.keys(map).sort().map(function (h) { return { robot_hash: h, robot_id: map[h] }; });
    },
  };
}

const NO_RESOLVER = buildRobotResolver(null);

// 로봇 셀: 이름이 풀리면 `robot-1` + 해시(작게), 안 풀리면 「미해소」 표식 + 해시.
// 해시는 어느 쪽에서도 사라지지 않는다 — 잠금 해제 대조가 해시로 이뤄진다.
function renderRobotCell(hash, resolver) {
  const r = (resolver || NO_RESOLVER).resolve(hash);
  // 해시 자체가 없는 행(허브가 안 실었거나 v2 가 아님)은 「미해소」가 아니다 —
  // 미해소는 "해시는 있는데 이름을 못 붙였다"이고 이것은 "붙일 재료가 없다"다.
  if (!r.hash) return pailT('<span class="unv">해시 없음</span>');
  if (r.resolved) {
    return '<span class="rname">' + esc(r.robot_id) + '</span> ' +
           '<span class="mono rhash" title="' + esc(r.hash) + '">' + esc(r.hash.slice(0, 8)) + '…</span>';
  }
  return pailT('<span class="unv">미해소</span> <span class="mono rhash">') + esc(r.hash) + '</span>';
}

// ---- Filters: 필터 (시간 창 · 로봇). URL 쿼리와 왕복한다 — 공유 가능한 링크 ----
// preset 이 있으면 굴러가는 창(now-N .. now), 없으면 고정 창.
const FILTER_PRESETS = { "15m": 15 * 60 * 1000, "1h": 60 * 60 * 1000, "6h": 6 * 60 * 60 * 1000 };

function parseFilterQuery(search, resolver) {
  const q = new URLSearchParams(search || "");
  const f = { preset: null, fromMs: null, toMs: null, robotHash: null, robotName: null, unresolvedRobot: null,
              outcome: q.get("outcome") || null, aroundMs: q.get("around_ms") ? Number(q.get("around_ms")) : null,
              spanMs: q.get("span_ms") ? Number(q.get("span_ms")) : null };
  const preset = q.get("preset");
  if (preset && FILTER_PRESETS[preset]) f.preset = preset;
  if (q.get("from_ms")) f.fromMs = Number(q.get("from_ms"));
  if (q.get("to_ms")) f.toMs = Number(q.get("to_ms"));
  if (!f.preset && f.fromMs === null && f.toMs === null && !f.aroundMs) f.preset = "15m";
  const robot = q.get("robot");
  if (robot) {
    const res = resolver || NO_RESOLVER;
    if (/^[0-9a-f]{32}$/i.test(robot)) {
      f.robotHash = robot.toLowerCase();
      const r = res.resolve(f.robotHash); f.robotName = r.resolved ? r.robot_id : null;
    } else {
      const h = res.hashOf(robot);
      if (h) { f.robotHash = h; f.robotName = robot; }
      else { f.unresolvedRobot = robot; }   // 이름을 못 풀었다 — 필터를 조용히 버리지 않고 표식으로 남긴다
    }
  }
  return f;
}

function filterToQuery(f) {
  const q = new URLSearchParams();
  if (f.preset) q.set("preset", f.preset);
  else { if (f.fromMs !== null && f.fromMs !== undefined) q.set("from_ms", String(f.fromMs));
         if (f.toMs !== null && f.toMs !== undefined) q.set("to_ms", String(f.toMs)); }
  if (f.robotName) q.set("robot", f.robotName);
  else if (f.robotHash) q.set("robot", f.robotHash);
  else if (f.unresolvedRobot) q.set("robot", f.unresolvedRobot);
  if (f.outcome) q.set("outcome", f.outcome);
  if (f.aroundMs) { q.set("around_ms", String(f.aroundMs)); if (f.spanMs) q.set("span_ms", String(f.spanMs)); }
  return q.toString();
}

// 시작·끝 입력칸에 보일 창. 프리셋이 켜져 있어도 칸은 비지 않는다 — 그 프리셋이
// **지금** 뜻하는 창(now-N .. now)을 보인다. 빈 칸은 「창이 없다」로 읽혔다
// (2026-09-04 Yang 실측: 「6시간」을 눌러도 시작·끝이 전혀 변하지 않는다).
function filterInputs(f, now) {
  if (f.preset) return { fromMs: now - FILTER_PRESETS[f.preset], toMs: now };
  return { fromMs: f.fromMs, toMs: f.toMs };
}

// 「적용」의 판정: 칸이 비면 프리셋(없으면 15분) · 칸의 값이 화면이 채워 준 값
// 그대로면 프리셋 유지(굴러가는 창) · 사람이 바꿨으면 고정 창. filled 는 화면이
// 마지막으로 칸에 쓴 값(입력칸 왕복 뒤의 ms — 초 해상도).
function resolveApply(f, filled, fromMs, toMs) {
  if (fromMs === null && toMs === null) return { preset: f.preset || "15m", fromMs: null, toMs: null };
  if (f.preset && filled && fromMs === filled.fromMs && toMs === filled.toMs) {
    return { preset: f.preset, fromMs: null, toMs: null };
  }
  return { preset: null, fromMs: fromMs, toMs: toMs };
}

// 방송을 둘로 가른다: 게이트 판정(BLOCK·ESTOP·CHAIN_REVOKED)과 체인 봉인 알림(CHECKPOINT).
// 「결정 이력」 표에는 판정만 싣고, 봉인 알림은 커버리지 줄에 건수로 적는다 —
// 판정이 아닌 행이 판정 표에 앉으면 「판정 지점」으로 읽힌다(2026-09-04 Yang 질문).
function splitBursts(rows) {
  const decisions = [], checkpoints = [];
  (rows || []).forEach(function (r) { (r.event === "CHECKPOINT" ? checkpoints : decisions).push(r); });
  return { decisions: decisions, checkpoints: checkpoints };
}

// 커버리지 줄 꼬리: 체인 봉인 수신 건수. 청취 증거이지 판정이 아니다.
function renderCheckpointNote(n) {
  return pailT('<span class="note"> · 체인 봉인(CHECKPOINT) 수신 ') + n + pailT("건</span>");
}

// 이력 표 머리의 계수. 표는 창의 행을 **전부** 싣는다 — 「최신 50건」으로 조용히
// 자르던 것이 2026-09-04 실측(6시간에 40여 건)의 화면 쪽 절반이었다. 잘림은
// 서버가 말한 것(truncated/matched)만 적는다.
function historySummary(rows, truncated, matched) {
  const n = (rows || []).length;
  if (n === 0) return pailT("창 0건");
  const byEvent = {};
  rows.forEach(function (r) { byEvent[r.event || "?"] = (byEvent[r.event || "?"] || 0) + 1; });
  const parts = Object.keys(byEvent).sort().map(function (k) { return k + " " + byEvent[k]; });
  const head = truncated ? pailT("창 ") + matched + pailT("건 중 최신 ") + n + pailT("건(조회 상한에 잘림)") : pailT("창 ") + n + pailT("건");
  return head + " · " + parts.join(" · ");
}

// 실제 조회 창. preset 은 호출 시각 기준으로 푼다.
function filterWindow(f, nowMs) {
  const now = nowMs || Date.now();
  if (f.preset) return { fromMs: now - FILTER_PRESETS[f.preset], toMs: null };
  return { fromMs: f.fromMs !== null ? f.fromMs : 0, toMs: f.toMs };
}


// ---- Timeline (observation UI contract): 로봇 타임라인 — 계획 단위로 묶고 스텝·집행·체크포인트를 잇는다 ----
//
// 재료는 /v1/ledger/events 의 행뿐이다. 체인 행(PLAN_ACCEPTED·PLAN_REJECTED·TOKEN_ISSUED·CHECKPOINT)은
// plan_id 로 묶이고, 텔레메트리 burst 행은 token_hash 로 그 계획의 토큰에 붙는다(정확 링크 —
// 근사 매칭은 token_hash 가 없는 행에만 「근사」표식). 표식 넷은 각각 다른 글자다:
// 미등록 이름 · 미검증 대상 · 구역 미해소 · 창 미검증 — 접으면 H-B2.
function buildTimeline(rows) {
  const plans = {}; const order = [];
  const byTokenHash = {};
  const loose = [];
  let checkpoints = 0;
  const other = {}; // 계획 없는 체인 사건(ATTESTATION·LEASE_*·SAFE_STOP…) — 버리지 않고 종류별로 센다
  // 두 번 지난다: 체인 행(계획·토큰)을 먼저 전부 세우고, 그 다음 텔레메트리를 붙인다.
  // 응답은 새 것부터라 한 번에 지나면 burst 가 자기 토큰보다 먼저 와서 전부 「근사」가
  // 된다(2026-09-04 라이브 실측: 550행 전부 loose).
  const chain = (rows || []).filter(function (r) { return r.src === "chain"; });
  const tel = (rows || []).filter(function (r) { return r.src !== "chain"; });
  for (const r of chain.concat(tel)) {
    if (r.src === "chain" && r.plan_id) {
      if (!plans[r.plan_id]) { plans[r.plan_id] = { plan_id: r.plan_id, robot_hash: r.robot_hash || "", robot_id: r.robot_id || "",
        accepted: null, rejected: null, tokens: [], bursts: [], first_ms: r.ms, last_ms: r.ms }; order.push(r.plan_id); }
      const p = plans[r.plan_id];
      if (r.ms < p.first_ms) p.first_ms = r.ms;
      if (r.ms > p.last_ms) p.last_ms = r.ms;
      if (r.outcome === "PLAN_ACCEPTED") p.accepted = r;
      else if (r.outcome === "PLAN_REJECTED") p.rejected = r;
      else if (r.outcome === "TOKEN_ISSUED") { p.tokens.push(r); if (r.token_hash) byTokenHash[r.token_hash] = p; }
      else if (r.outcome !== "CONTEXT_SEALED") p.tokens.push(r); // 기타 체인 사건은 스텝 줄로 보인다
    } else if (r.src === "chain") {
      other[r.outcome] = (other[r.outcome] || 0) + 1;
    } else if (r.src === "telemetry") {
      // CHECKPOINT 버스트의 32:48 은 토큰 해시가 아니라 체인 head 해시다(packet_v2) —
      // 토큰에 붙을 수 없으므로 「근사」가 아니라 체크포인트로 따로 센다.
      if (r.outcome === "CHECKPOINT") { checkpoints++; continue; }
      const p = r.token_hash ? byTokenHash[r.token_hash] : null;
      if (p) { p.bursts.push(r); if (r.ms > p.last_ms) p.last_ms = r.ms; } else loose.push(r);
    }
  }
  // 토큰은 시각순, 버스트는 (event, reason) 로 집계 — 40건의 같은 차단은 한 줄 ×40 이다
  const out = order.map(function (id) {
    const p = plans[id];
    p.tokens.sort(function (a, b) { return a.ms - b.ms || a.seq - b.seq; });
    const agg = {};
    for (const b of p.bursts) { const k = b.outcome + "/" + b.reason_value; if (!agg[k]) agg[k] = { event: b.outcome, reason: b.reason_value, n: 0, first_ms: b.ms, last_ms: b.ms, sig_bad: 0 };
      agg[k].n++; if (b.ms < agg[k].first_ms) agg[k].first_ms = b.ms; if (b.ms > agg[k].last_ms) agg[k].last_ms = b.ms; if (b.sig !== "ok") agg[k].sig_bad++; }
    p.burst_groups = Object.keys(agg).map(function (k) { return agg[k]; }).sort(function (a, b) { return a.first_ms - b.first_ms; });
    return p;
  });
  out.sort(function (a, b) { return b.first_ms - a.first_ms; });
  return { plans: out, loose: loose, checkpoints: checkpoints, other: other };
}

// 표식: 토큰 한 줄의 결측을 각각의 글자로. 값이 아닌 것(null)은 「모름」이지 「없음」이 아니다.
function tokenMarks(tok) {
  const m = [];
  if (tok.registered === false) m.push({ cls: "mk-unreg", text: pailT("미등록 이름") });
  if (tok.registered === null || tok.registered === undefined) m.push({ cls: "mk-old", text: pailT("등록 여부 모름(구판)") });
  if (tok.target_unverified === true) m.push({ cls: "mk-unver", text: pailT("미검증 대상") });
  if (tok.target && tok.zone_resolution === "unresolved") m.push({ cls: "mk-zone", text: pailT("구역 미해소") });
  if (tok.target && tok.zone_resolution === "snapshot") m.push({ cls: "mk-snap", text: pailT("구역=스냅샷 재해소") });
  return m;
}

function fmtMs(ms) {
  if (!ms) return "";
  const d = new Date(ms); const p = function (n) { return String(n).padStart(2, "0"); };
  return p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
}

function classNames(mask) {
  const names = []; if (mask & 1) names.push("MOVE"); if (mask & 2) names.push("MANIPULATE"); if (mask & 4) names.push("ACTUATE"); if (mask & 8) names.push("NONE");
  return names.length ? names.join("|") : "-";
}

function otherLine(tl) {
  if (!tl || !tl.other) return "";
  const ks = Object.keys(tl.other).sort();
  if (!ks.length) return "";
  return pailT(" · 계획 없는 체인 사건 ") + ks.map(function (k) { return k + " " + tl.other[k] + pailT("건"); }).join(", ");
}

// 계획 블록 렌더. verify 는 응답 전체의 검증 상태 — 창 표식은 블록마다 같은 글자로 붙는다(숨기지 않는다).
function renderTimeline(tl, resolver, verify) {
  if (!tl || !tl.plans.length) {
    // 계획이 없어도 창이 비었던 것은 아니다 — 무엇이 있었는지 센다(체크포인트·붙지 않은 집행).
    return pailT('<div class="unv">이 창에 계획(PLAN_ACCEPTED·TOKEN_ISSUED·PLAN_REJECTED)이 없다') +
      (tl && tl.checkpoints ? pailT(' · 체크포인트 버스트 ') + tl.checkpoints + pailT('건(체인 head 상관 — 토큰 사건 아님)') : '') +
      otherLine(tl) +
      (tl && tl.loose.length ? pailT(' · 토큰에 붙지 않은 집행 ') + tl.loose.length + pailT('건') : '') +
      pailT(' — 로봇이 새 계획을 받지 않았거나 창이 그 시각을 비켜 갔다</div>');
  }
  const vstate = verify ? verify.state : "unverified";
  const vmark = vstate === "chain_ok" ? pailT('<span class="mk-ok">체인 검증됨</span>') :
                vstate === "chain_error" ? pailT('<span class="mk-err">체인 오류: ') + esc(verify.error || "") + "</span>" :
                pailT('<span class="mk-unver">창 미검증</span>');
  return tl.plans.map(function (p) {
    const head = p.accepted || p.rejected || p.tokens[0] || {};
    const rq = (p.accepted && p.accepted.requester) || (p.rejected && p.rejected.requester) || null;
    const rqText = rq ? esc(rq.kind + "/" + rq.id) : pailT('<span class="mk-old">요청자 없음(구판)</span>');
    let h = '<div class="tl-plan' + (p.rejected ? " tl-rejected" : "") + '" data-plan="' + esc(p.plan_id) + '">';
    h += '<div class="tl-head">' + esc(fmtMs(p.first_ms)) + " · " + renderRobotCell(head.robot_hash || p.robot_hash, resolver) +
         pailT(" · 계획 <span class=\"mono\">") + esc(p.plan_id) + pailT("</span> · 요청자 ") + rqText +
         (p.rejected ? pailT(' · <span class="mk-err">거부 ') + esc(p.rejected.reject_code) + "</span>" : (p.accepted ? pailT(" · 수락") : "")) +
         " · " + vmark + "</div>";
    for (const t of p.tokens) {
      const marks = tokenMarks(t).map(function (m) { return '<span class="' + m.cls + '">' + esc(m.text) + "</span>"; }).join(" ");
      h += '<div class="tl-step">' + esc(fmtMs(t.ms)) + " · " + esc(t.outcome) +
           (t.outcome === "TOKEN_ISSUED" ? " · " + esc(t.action_name || "?") + " (" + classNames(t.action_class || 0) + ")" +
             (t.target ? pailT(" · 대상 ") + esc(t.target) : "") + (t.zone ? pailT(pailT(" · 구역 ")) + esc(t.zone) : "") : "") +
           (marks ? " " + marks : "") +
           (t.token_hash ? pailT(' <span class="tl-ev mono" title="증거 하강: 정본에서 이 토큰을 찾는 명령(실행하지 않는다)">blackbox_verify -find ') + esc(t.token_hash) + "</span>" : "") +
           "</div>";
    }
    for (const g of p.burst_groups) {
      h += '<div class="tl-burst ' + (g.event === "BLOCK" || g.event === "ESTOP" || g.event === "AUTHORITY_WITHHELD" ? "tl-red" : "") + '">' + esc(fmtMs(g.first_ms)) +
           (g.n > 1 ? "~" + esc(fmtMs(g.last_ms)) : "") + pailT(" · 집행 ") + esc(g.event) + " " + esc(reasonText(g.reason)) +
           (g.n > 1 ? " ×" + g.n : "") + (g.sig_bad ? pailT(' <span class="mk-unver">서명 미검증 ') + g.sig_bad + "</span>" : "") + "</div>";
    }
    h += "</div>";
    return h;
  }).join("") + (tl.loose.length ? pailT('<div class="unv">토큰에 붙지 않은 집행 사건 ') + tl.loose.length + pailT('건 <span class="mk-old">근사</span></div>') : "") +
    (tl.checkpoints ? pailT('<div class="unv">체크포인트 버스트 ') + tl.checkpoints + pailT('건(체인 head 상관 — 토큰 사건 아님)</div>') : "") +
    (otherLine(tl) ? '<div class="unv">' + otherLine(tl).replace(/^ · /, "") + '</div>' : "");
}

// ---- Timeline (observation UI contract): 자연어 → 구조화 필터. 규칙 기반, 브라우저 안에서만. ----
// 결과는 필터 바에 **채워 보일 뿐** 조회를 시작하지 않는다 — 번역기가 틀리면 그 자리에서 보인다(G-LED-08).
// 못 읽은 낱말은 explain 에 「무시」로 적는다: 조용히 버려진 조건은 「전체」로 도착한다.
function parseNaturalQuery(text, resolver, nowMs) {
  const now = nowMs || Date.now();
  const f = { preset: null, fromMs: null, toMs: null, robotHash: null, robotName: null, unresolvedRobot: null, outcome: null };
  const explain = [];
  let t = String(text || "").trim();
  t = t.replace(/\byesterday\b/gi, "어제").replace(/\btoday\b/gi, "오늘")
       .replace(/\blast\b/gi, "최근").replace(/\bhours?\b/gi, "시간").replace(/\bminutes?\b/gi, "분")
       .replace(/\brobot\s+(\d+)\b/gi, "로봇 $1").replace(/\brejected?\b/gi, "거부")
       .replace(/\ball\b/gi, "전체").replace(/\bfrom\b/gi, " ").replace(/\bto\b/gi, "~")
       .replace(/\b(show|history|events|actions)\b/gi, " ");
  if (!t) return { filter: null, explain: [pailT("빈 문장")] };
  const base = new Date(now); base.setSeconds(0, 0);
  let day = new Date(base.getFullYear(), base.getMonth(), base.getDate());
  if (/어제/.test(t)) { day = new Date(day.getTime() - 86400000); explain.push(pailT("어제 → ") + day.toLocaleDateString()); t = t.replace(/어제/, " "); }
  else if (/오늘/.test(t)) { explain.push(pailT("오늘")); t = t.replace(/오늘/, " "); }
  const hm = function (h, m) { return new Date(day.getFullYear(), day.getMonth(), day.getDate(), Number(h), Number(m || 0)).getTime(); };
  const p2 = function (n) { return String(n).padStart(2, "0"); };
  // 시각 한 개: "16시", "16시 40분", "16:40", "16시40" 을 다 받는다
  const T = "(\\d{1,2})\\s*(?:시\\s*(?:(\\d{1,2})\\s*분?)?|:\\s*(\\d{2}))";
  const recent = t.match(/최근\s*(\d+)\s*(분|시간)/);
  if (recent) {
    const mins = recent[2] === "분" ? Number(recent[1]) : Number(recent[1]) * 60;
    const key = mins === 15 ? "15m" : mins === 60 ? "1h" : mins === 360 ? "6h" : null;
    if (key) { f.preset = key; explain.push(pailT("최근 ") + recent[1] + pailT(recent[2]) + pailT(" → 프리셋 ") + key + pailT("(굴러가는 창)")); }
    else { f.toMs = now; f.fromMs = now - mins * 60000; explain.push(pailT("최근 ") + recent[1] + pailT(recent[2]) + pailT(" → 고정 창 ") + new Date(f.fromMs).toLocaleTimeString() + pailT("~지금")); }
    t = t.replace(recent[0], " ");
  }
  const range = t.match(new RegExp(T + "\\s*(?:~|부터|-|에서)\\s*" + T + "\\s*(?:까지)?"));
  if (range && !f.preset && f.fromMs === null) {
    const h1 = range[1], m1 = range[2] || range[3] || 0, h2 = range[4], m2 = range[5] || range[6] || 0;
    f.fromMs = hm(h1, m1); f.toMs = hm(h2, m2);
    explain.push(pailT("시간 ") + p2(h1) + ":" + p2(m1) + "~" + p2(h2) + ":" + p2(m2));
    t = t.replace(range[0], " ");
  } else if (!f.preset && f.fromMs === null) {
    const one = t.match(new RegExp(T));
    if (one) { const h = one[1], m = one[2] || one[3] || 0; f.fromMs = hm(h, m); f.toMs = f.fromMs + 3600000;
      explain.push(pailT("시간 ") + p2(h) + ":" + p2(m) + pailT(" 부터 1시간(끝 시각이 없어서)")); t = t.replace(one[0], " "); }
  }
  const robot = t.match(/로봇\s*(\d+)/);
  if (robot) {
    const name = "robot-" + robot[1]; const h = (resolver || NO_RESOLVER).hashOf(name);
    if (h) { f.robotHash = h; f.robotName = name; explain.push(pailT("로봇 → ") + name); }
    else { f.unresolvedRobot = name; explain.push(pailT("로봇 ") + name + pailT(" — 레지스트리에 없음(필터 미적용 표식)")); }
    t = t.replace(robot[0], " ");
  }
  if (/차단|블록|BLOCK/i.test(t)) { f.outcome = "BLOCK"; explain.push(pailT("결과 → BLOCK")); t = t.replace(/차단|블록|BLOCK/i, " "); }
  else if (/비상\s*정지|ESTOP/i.test(t)) { f.outcome = "ESTOP"; explain.push(pailT("결과 → ESTOP")); t = t.replace(/비상\s*정지|ESTOP/i, " "); }
  else if (/거부/.test(t)) { f.outcome = "PLAN_REJECTED"; explain.push(pailT("결과 → PLAN_REJECTED")); t = t.replace(/거부/, " "); }
  else if (/모든|전체|전부|다\b/.test(t)) { explain.push(pailT("결과 조건 없음(모든 행동)")); t = t.replace(/모든|전체|전부/g, " "); }
  // 조건이 아닌 말(동안·내역·보여줘…)은 조용히 넘기되, 남은 낱말은 「무시」로 적는다 —
  // 조용히 버려진 조건은 「전체」로 도착한다.
  const filler = /동안|내역|이력|기록|사건|행동|조회|보여\s*줘|알려\s*줘|해\s*줘|줘|좀|의|를|을|에서|에|은|는|이|가/g;
  const rest = t.replace(filler, " ").replace(/[\s,.·~\-:]+/g, " ").trim();
  if (rest) explain.push(pailT("무시: 「") + rest + pailT("」"));
  if (f.fromMs === null && f.toMs === null && !f.preset) { f.preset = "15m"; explain.push(pailT("시간 없음 → 최근 15분")); }
  return { filter: f, explain: explain };
}

// node 테스트용 export (브라우저에서는 무해하게 건너뛴다)
if (typeof module !== "undefined" && module.exports) {
  module.exports = { computeTile: computeTile, reasonText: reasonText,
                     foldPermit: foldPermit, renderPermitRows: renderPermitRows,
                     renderHistoryRows: renderHistoryRows, unlockCommand: unlockCommand,
                     buildRobotResolver: buildRobotResolver, renderRobotCell: renderRobotCell,
                     parseFilterQuery: parseFilterQuery, filterToQuery: filterToQuery,
                     filterWindow: filterWindow, FILTER_PRESETS: FILTER_PRESETS,
                     buildTimeline: buildTimeline, tokenMarks: tokenMarks, renderTimeline: renderTimeline,
                     parseNaturalQuery: parseNaturalQuery, classNames: classNames };
}
