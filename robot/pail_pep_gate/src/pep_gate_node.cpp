#include "pail_deploy_guard/core_comm_io.hpp"
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

#include <algorithm>
#include <atomic>
#include "pail_pep_gate/attestation_worker.hpp"
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#if defined(PAIL_ENABLE_GRPC) && (PAIL_ENABLE_GRPC == 1)
#include <sodium.h>
#endif

#include "rclcpp/rclcpp.hpp"
#include "rcl_interfaces/msg/set_parameters_result.hpp"
#include "geometry_msgs/msg/twist.hpp"
#include "pail_msgs/msg/bridge_state.hpp"
#include "pail_msgs/msg/evidence.hpp"
#include "pail_msgs/msg/gate_state.hpp"
#include "pail_msgs/msg/permit.hpp"
#include "pail_msgs/msg/safety_state.hpp"
#include "pail_msgs/msg/stop_request.hpp"

#include "yaml-cpp/yaml.h"

#include "pail_deploy_guard/deploy_guard.hpp"
#include "pail_deploy_guard/config_seal.hpp"
#include "pail_deploy_guard/robotops_status.hpp"
#include "pail_pep_gate/fatal_report_worker.hpp"
#include "rmw/rmw.h"
#include "pail_deploy_guard/thresholds.hpp"
#if defined(PAIL_ENABLE_GRPC) && (PAIL_ENABLE_GRPC == 1)
#include <sodium.h>
#include "pail_deploy_guard/key_fingerprint.hpp"
#endif
#include "pail_pep_gate/config_seal_client.hpp"
#include "pail_pep_gate/control_transport.hpp"
#include "pail_pep_gate/clock_warning_summary.hpp"
#include "pail_pep_gate/core_contract.hpp"
#include "pail_pep_gate/deploy_profile.hpp"
#include "pail_gate/gate_core.hpp"
#include "pail_gate/gate_session.hpp"
#include "pail_gate/skills_load.hpp"
#include "pail_gate/safety_level.hpp"
#include "pail_gate/token_provider.hpp"
#include "pail_pep_gate/token_provider_grpc.hpp"
#include "pail_pep_gate/token_provider_static.hpp"
#include "pail_gate/keyring_bundle.hpp"
#include "pail_gate/strict_verify.hpp"
#include "pail_gate/wall_clock.hpp"

using namespace std::chrono_literals;

// SD4: the S0~S3 inputs depend on argv (--enclave) and on the keystore layout,
// which the node object never sees. main() resolves them once, from the same
// call the SD3 preflight already makes, so the seal reports the configuration
// that was actually judged rather than a second reading of it.
namespace {
pail_deploy_guard::GuardInput g_deploy_input;

// implementation contract (D-L4): 정책 파일 키 접근의 **유일한** 형태.
//
// 같은 파일을 파서 둘이 읽고 틀리는 방향이 반대다: Go 는 모르는 키에 `S16b` 로
// 죽고(시끄럽다), C++ 은 키 지목식 접근이라 모르는 키를 **조용히 무시**한다.
// `min_trust_class` 를 적었는데 게이트가 그 키를 모르면 파일은 강화를 말하고
// 게이트는 예전대로 돈다 — `E-W5` 의 형태다. 그래서 게이트가 읽는 키 집합을
// 기계가 셀 수 있어야 하고, 세려면 접근이 한 형태여야 한다.
//
// 경로는 **전체 점 경로**를 준다. 잎 이름만 적으면 검사기가
// `evidence.window_ms` 와 최상위 `window_ms` 를 구별하지 못한다.
//
// 시퀀스 원소는 `"rules[].mode"` 처럼 적고 원소 노드를 함께 넘긴다 — 조회에는
// 마지막 `[].` 뒤만 쓰고, 소스에 남는 리터럴은 검사기가 읽을 전체 경로다.
// 선언 경로와 조회 경로를 두 인자로 나누면 그 둘이 표류한다.
// 재귀로 내려간다. 반복문 + `reset()` 이 자연스러워 보이지만 yaml-cpp 에서
// 함정 셋을 한꺼번에 밟는다 (전부 실측):
//   - `cur = cur[seg]` 은 재지목이 아니라 **대입**이라 원본 트리를 바꾼다.
//   - `cur.reset(x)` 는 `x` 가 무효(없는 키의 좀비 노드)면 `InvalidNode` 를
//     던진다 — 즉 "키가 없다"가 예외로 도착한다.
//   - 좀비 노드에 `IsMap()` 을 부르면 `EnsureNodeExists()` 가 또 던진다.
//     `IsDefined()` 만 안전하므로 그것을 먼저 보고 단락시킨다.
// 반환하는 무효 노드는 `NodeType::Undefined` 다 — 기본 생성 `YAML::Node()` 는
// Null 이고 **참으로 평가된다**. 부재가 참이 되면 `H-B2` 그 자체다.
YAML::Node PolicyKeyWalk(const YAML::Node &cur, const std::string &path, std::size_t pos) {
  if (!cur.IsDefined() || !cur.IsMap()) return YAML::Node(YAML::NodeType::Undefined);
  const std::size_t dot = path.find('.', pos);
  const std::string seg =
      path.substr(pos, dot == std::string::npos ? std::string::npos : dot - pos);
  // const 오버로드를 강제한다: 비-const `operator[]` 는 없는 키를 조회하는 것
  // 만으로 트리에 노드를 만든다(프로브는 트리를 바꾸면 안 된다).
  const YAML::Node next = static_cast<const YAML::Node &>(cur)[seg];
  if (dot == std::string::npos) return next;
  return PolicyKeyWalk(next, path, dot + 1);
}

YAML::Node PolicyKey(const YAML::Node &node, const char *dotted) {
  std::string path(dotted);
  const std::size_t seq = path.rfind("[].");
  if (seq != std::string::npos) path = path.substr(seq + 3);
  return PolicyKeyWalk(node, path, 0);
}
}  // namespace

// NOTE: This is a skeleton. Business logic must follow codex_spec/20_PEP_GATE.md.

class PepGateNode final : public rclcpp::Node {
#ifdef PAIL_PEP_GATE_UNDER_TEST
  friend struct Preview12Probe;
#endif
public:
  // P15-H1: a fatal report still unconfirmed at shutdown is abandoned loudly
  // (worker hook), never silently; the worker joins before the provider goes.
  ~PepGateNode() override {
    attest_stopping_.store(true);
    if(attest_timer_)attest_timer_->cancel();
    if(attest_worker_)attest_worker_->Stop();
    if (fatal_worker_) fatal_worker_->Stop();
  }

  PepGateNode() : Node("pep_gate_node") {
    // Provider selection
    provider_mode_ = declare_parameter<std::string>("token_provider_mode", "notoken");
    use_token_service_ = declare_parameter<bool>("use_token_service", false);
    token_service_addr_ = declare_parameter<std::string>("token_service_addr", "127.0.0.1:50051");

    // Basic communication contract (spec/CORE_COMM.md): one contract since 0.2.0-preview.40, no selecting setting.
    // A PAIL_CORE_COMM_CONTRACT value of any kind refuses here, before any subscription or timer (RV11: the node
    // reads the environment once; the provider never does). The real gRPC provider always reports in the C1 form.
    {
      const auto verdict = pail_pep_gate::EvaluateCoreCommSetting(std::getenv("PAIL_CORE_COMM_CONTRACT"));
      if (verdict.refuse) {
        throw pail_deploy_guard::ConfigRefused(verdict.id + ": " + verdict.detail);
      }
      RCLCPP_INFO(get_logger(), "core_comm_contract=v1");
    }

    static_chain_id_ = declare_parameter<std::string>("static_chain_id", "static-chain");
    static_token_id_ = declare_parameter<std::string>("static_token_id", "static-token");
    static_target_object_id_ = declare_parameter<std::string>("static_target_object_id", "");
    static_sequence_index_ = declare_parameter<int>("static_sequence_index", 1);

    // SD1 §2.1: the mode decides whether authorization is verified at all, and
    // it can arrive by ROS parameter (launch file, -p, param file), which the
    // shell preflight cannot see. stderr is used directly so the "PAIL
    // PREFLIGHT" prefix is greppable regardless of logging configuration.
    {
      const char * profile_env = std::getenv("PAIL_PROFILE");
      const auto policy = pail_pep_gate::EvaluateDeployMode(
          profile_env ? profile_env : "", provider_mode_, use_token_service_,
#if defined(PAIL_ENABLE_GRPC) && (PAIL_ENABLE_GRPC == 1)
          true
#else
          false
#endif
      );
      const std::string profile_shown = profile_env ? profile_env : "(unset=production)";
      if (policy.verdict == pail_pep_gate::ModeVerdict::Fail) {
        std::fprintf(stderr, "PAIL PREFLIGHT FAIL: %s %s [profile=%s]\n",
                     policy.id.c_str(), policy.detail.c_str(), profile_shown.c_str());
        std::fprintf(stderr,
                     "PAIL PREFLIGHT FAIL: refusing to start. Set PAIL_PROFILE=dev to run "
                     "without authorization verification (DEV ONLY).\n");
        std::fflush(stderr);
        std::exit(78);
      }
      if (policy.verdict == pail_pep_gate::ModeVerdict::Warn) {
        std::fprintf(stderr, "PAIL PREFLIGHT WARN: %s %s [profile=%s]\n",
                     policy.id.c_str(), policy.detail.c_str(), profile_shown.c_str());
        std::fflush(stderr);
        RCLCPP_WARN(get_logger(), "PAIL PREFLIGHT WARN: %s %s [profile=%s]",
                    policy.id.c_str(), policy.detail.c_str(), profile_shown.c_str());
      }
    }

    // implementation contract (D-S3/D-S4/D-S7): the gate's operating mode, read once from
    // the sealed policy file (seal key 31 already carries its content hash —
    // H-B8 without touching canon), BEFORE the provider is constructed: the
    // provider stamps every ReportDecision with this value, and a refusal here
    // happens before any subscription exists.
    policy_file_ = declare_parameter<std::string>("policy_file", "/etc/pail/policy.yaml");
    gate_mode_ = load_gate_mode_or_refuse(policy_file_);
    RCLCPP_INFO(get_logger(), "gate_mode=%s (policy=%s)", gate_mode_.c_str(),
                policy_file_.c_str());

    if (provider_mode_ == "grpc" || use_token_service_) {
      auto grpc_provider =
          std::make_unique<pail_pep_gate::GrpcTokenProvider>(token_service_addr_, true);
      // implementation contract (D-S5): every decision report says which mode it was
      // decided under. Process-constant (D-S7) — set once, before the move.
      grpc_provider->SetEffectiveMode(gate_mode_);
      // C-B12 O-3 : every decision report says whether the
      // evidence plane's sender authentication was actually on. "enforced"
      // requires Enforce, not just enable — Permissive silently permits
      // unsecured participants (deploy guard S2), so an enabled-Permissive
      // deployment's evidence is still unauthenticated.
      grpc_provider->SetEvidenceProvenance(
          (g_deploy_input.security_enable == "true" &&
           g_deploy_input.security_strategy == "Enforce")
              ? "enforced" : "unenforced");
      token_provider_ = std::move(grpc_provider);
#if PAIL_ENABLE_GRPC == 1
      // KM2-1 trust path (KM LLD §6.3): signed bundle by default, unsigned
      // keyring.json only with explicit PAIL_KEYRING_MODE=unsigned-dev. Load
      // failure leaves the trust map empty — every token verification then
      // fails (fail-closed); a new bundle is applied by restarting this node.
      std::string kr_mode, kr_reason;
      keyring_ = pail_pep_gate::LoadTrustedKeyring(
          "/etc/pail/keys/keyring.json", &kr_mode, &kr_reason);
      keyring_mode_ = kr_mode;
      if (kr_reason == "ERR_BUNDLE_LIFETIME" || kr_reason == "ERR_BUNDLE_POLICY" || kr_reason == "ERR_BUNDLE_CLOCK") {
        std::fprintf(stderr, "PAIL PREFLIGHT FAIL: S20 %s PAIL_KEYRING_MAX_LIFETIME_SEC (remaining validity at load)\n", kr_reason.c_str());
        throw pail_deploy_guard::ConfigRefused("S20: keyring remaining-validity policy refused");
      }
      if (!kr_reason.empty()) {
        RCLCPP_WARN(get_logger(), "keyring load (mode=%s): %s — no trust anchor, all tokens will be rejected",
                    kr_mode.c_str(), kr_reason.c_str());
      } else {
        // `C16-C5`: 폐기 목록의 크기를 함께 찍는다. 0 과 미출력은 다른 값이다 —
        // 이 줄이 없으면 "폐기가 실리지 않았다"와 "폐기가 없다"가 같은 로그가
        // 되고, 폐기 목록을 통째로 떨어뜨린 배치가 조용히 정상으로 보인다.
        RCLCPP_INFO(get_logger(), "keyring trust path: mode=%s keys=%zu revoked=%zu",
                    kr_mode.c_str(), keyring_.pubkeys.size(), keyring_.revoked.size());
      }
      // S8 check (6) (PAIL-SD2-LLD-v1 §2.3): judge the anchors that were
      // actually loaded, not the path they came from — in bundle mode the path
      // says nothing about which keys ended up trusted. Before any subscription
      // exists, so a refused gate never verifies a single command.
      {
        std::vector<pail_deploy_guard::KeyMaterialItem> items;
        for (const auto & kv : keyring_.pubkeys) {
          unsigned char digest[crypto_hash_sha256_BYTES];
          crypto_hash_sha256(digest, kv.second.data(), kv.second.size());
          static const char * kHex = "0123456789abcdef";
          std::string fpr;
          fpr.reserve(sizeof(digest) * 2);
          for (unsigned char b : digest) {
            fpr.push_back(kHex[b >> 4]);
            fpr.push_back(kHex[b & 0x0f]);
          }
          items.push_back({"keyring entry [loaded key_id=" + kv.first + "]", fpr});
          // SD4: the seal reports the anchors this process actually trusts, for
          // the same reason S8 judges them — the path they came from is not the
          // question.
          keyring_fingerprints_.push_back(fpr);
        }
        const char * profile_env = std::getenv("PAIL_PROFILE");
        pail_deploy_guard::EnforceKeyMaterial(
          (profile_env && *profile_env) ? profile_env : "production", "pep_gate_node",
          pail_deploy_guard::EvaluateKeyMaterial(items));
      }
      // DC-10 / C3-C7 : cross-restart wall-clock rewind
      // floor. The monotonic baseline (clock_baseline_) dies with the process;
      // without this, "rewind the clock, restart the gate" resets the baseline
      // and every time judgment believes the rewound clock. Loaded-bundle only:
      // the floor lives in the bundle state file and rides the same lifecycle
      // as the version floor, which is also written only when a bundle loads
      // (unsigned-dev has neither). A failed bundle load leaves zero trust
      // anchors — every verification already fails closed, so no motion the
      // floor could protect is possible; refusing startup for a floor we could
      // never have written would kill every rig without /etc/pail. Before any
      // subscription exists — a refused gate never judges a command.
      if (kr_mode == "bundle" && kr_reason.empty()) {
        const std::string state_path =
            pail_pep_gate::KeyringStatePathFromEnv("/etc/pail/keys/keyring.json");
        switch (pail_pep_gate::CheckWallFloor(state_path, clock_baseline_.wall_ms0)) {
          case pail_pep_gate::WallFloor::Rewind:
            std::fprintf(stderr,
                         "PAIL PREFLIGHT FAIL: ERR_CLOCK_DRIFT boot wall clock is behind the "
                         "persisted floor (%s) — refusing to start on a rewound clock\n",
                         state_path.c_str());
            std::fflush(stderr);
            std::exit(78);
          case pail_pep_gate::WallFloor::StateError:
            std::fprintf(stderr,
                         "PAIL PREFLIGHT FAIL: ERR_BUNDLE_STATE wall floor unreadable (%s) — "
                         "a rewind cannot be ruled out\n",
                         state_path.c_str());
            std::fflush(stderr);
            std::exit(78);
          case pail_pep_gate::WallFloor::NoFloor:
          case pail_pep_gate::WallFloor::Ok:
            break;
        }
        if (!pail_pep_gate::PersistWallFloor(state_path, clock_baseline_.wall_ms0)) {
          std::fprintf(stderr,
                       "PAIL PREFLIGHT FAIL: ERR_BUNDLE_STATE wall floor not persisted (%s) — "
                       "the next boot would inherit an open rewind window\n",
                       state_path.c_str());
          std::fflush(stderr);
          std::exit(78);
        }
      }
#else
      RCLCPP_WARN(get_logger(), "grpc mode requested but PAIL_ENABLE_GRPC=0 build");
#endif
    } else if (provider_mode_ == "static") {
      token_provider_ = std::make_unique<pail_pep_gate::StaticTokenProvider>(static_chain_id_, static_token_id_, static_sequence_index_, static_target_object_id_);
    } else {
      token_provider_ = std::make_unique<pail_pep_gate::NoTokenProvider>();
    }
    cmd_sub_ = create_subscription<geometry_msgs::msg::Twist>(
        "/cmd_vel", 10,
        std::bind(&PepGateNode::on_cmd_vel, this, std::placeholders::_1));

    evidence_sub_ = create_subscription<pail_msgs::msg::Evidence>(
        "/pail/evidence", 10,
        std::bind(&PepGateNode::on_evidence, this, std::placeholders::_1));


    gate_state_pub_ = create_publisher<pail_msgs::msg::GateState>("/pail/gate_state", 10);

    robot_id_ = declare_parameter<std::string>("robot_id", "robot-1");

    // D-L1: 정책이 유일한 출처다. ROS 파라미터 기본값은 삭제됐다 — 남겨 두면
    // 정책을 안 읽어도 판정이 돌아 P-19 가 그대로 재발한다.
    load_evidence_limits_or_refuse(policy_file_);

    // D-L5 · D-L3: the trust-class floor, the two freshness windows, and the
    // safety-feed step exemption.
    load_policy_classes_or_refuse(policy_file_);
    // SK-2 (implementation contract, S33): the skill registry's envelope names must all be names
    // this adapter measures. Read once at start; the digest is kept for the seal (SK-4).
    robot_class_ = declare_parameter<std::string>("robot_class", "");
    skills_dir_ = declare_parameter<std::string>("skills_dir", "/etc/pail");
    adapter_measures_ = declare_parameter<std::string>(
        "adapter_measures", "sls.linear_mps,sls.angular_rps,step.max_duration_s");
    // SK-5 : the safe state this adapter executes on permit revocation
    // (the motion bridge's zero twist), and the vendor safety controller this gate
    // runs beside (S36 — production without one is degraded, not refused, first edition).
    adapter_safe_state_ = declare_parameter<std::string>("adapter_safe_state", "stop_zero_twist");
    safety_controller_ = declare_parameter<std::string>("safety_controller", "");
    preflight_s33_or_refuse();
    preflight_s36_warn();
    // 문구는 `evidence.window_ms=` 그대로 둔다 — 리그와 증거 파일이 이 이름으로
    // 노드의 실측 창을 읽는다. 달라진 것은 값의 **출처**이고, 그 출처는
    // 바로 아래 줄이 `preconditions` 로 말한다.
    RCLCPP_INFO(get_logger(),
                "evidence.window_ms=%d evidence.confidence_threshold=%.4f (policy=%s)",
                evidence_window_ms_, evidence_conf_threshold_, policy_file_.c_str());
    RCLCPP_INFO(get_logger(),
                "evidence.min_trust_class rank=%d over %zu graded sources; "
                "preconditions[safety_feed].exempt_in_progress_step=%s (policy=%s)",
                min_trust_rank_, trust_rank_by_source_.size(),
                safety_exempt_in_progress_step_ ? "true" : "false", policy_file_.c_str());

    // D-L7 §6.4: the evidence feed's "ever received" third value is NOT stamped
    // here. It used to be, and that one line made a gate that had never received
    // evidence report ERR_TARGET_MISMATCH instead of ERR_NO_EVIDENCE — absence
    // wearing the costume of a fresh reading about the wrong object. AD-4: the
    // feed lives in the session; ObserveEvidence is the only place it becomes true.

    // M3: report step completion (which consumes the token) once the step
    // deadline passes, even if the cmd_vel stream has already stopped.
    step_timer_ = create_wall_timer(50ms, std::bind(&PepGateNode::on_step_timer, this));

    // M4 (LLD-v2 §2.2): permit heartbeat. Absence of /pail/permit IS the stop
    // signal — the motion bridge holds when the deadline is missed.
    permit_rate_hz_ = declare_parameter<int>("permit_rate_hz", 20);
    permit_recheck_ms_ = declare_parameter<int>("permit_recheck_ms", 100);
    permit_deadline_ms_ = declare_parameter<int>("permit_deadline_ms", 100);


    // D §7.9: 범위 밖 값은 고치지 않고 기동을 거부한다 (C 의 EnvIntStrict 규율
    // 공유 — std::max(1, …) 클램프는 아무도 설정하지 않은 값으로 게이트를
    // 돌린다). 상한은 발명이 아니라 실측 유도값이다: 모션 브리지의 침묵 창이
    // 2×permit_deadline_ms 이므로 recheck 주기가 그보다 길면 재확인이 오기
    // 전에 브리지가 먼저 HOLD 로 떨어진다 — 그 설정은 동작이 아니라 오타다.
    if (permit_recheck_ms_ < 1 || permit_recheck_ms_ > 2 * permit_deadline_ms_) {
      RCLCPP_FATAL(get_logger(),
                   "permit_recheck_ms=%d out of range [1, 2 x permit_deadline_ms = %d] — refusing to start",
                   permit_recheck_ms_, 2 * permit_deadline_ms_);
      std::exit(pail_deploy_guard::kExitConfig);
    }

    // Expire queued velocity samples before the bridge can re-stamp an old
    // command after authority resumes. Reliable vendor-compatible transport.
    rclcpp::QoS safe_qos(rclcpp::KeepLast(1));
    safe_qos.reliable().durability_volatile();
    safe_qos.lifespan(std::chrono::milliseconds(permit_deadline_ms_));
    safe_pub_ = create_publisher<geometry_msgs::msg::Twist>("/safe_cmd_vel", safe_qos);

    // AV1 (AV LLD §1.2): how many CONSECUTIVE unanswered rechecks the gate
    // tolerates before stopping the heartbeat. A negative answer (REVOKED /
    // NO_TOKEN / ERROR) is never graced, and the token's own not_after is
    // checked independently, so grace can never outlive the authorization.
    // 0 restores the pre-AV1 behaviour (stop on the first failure).
    // S10 (PAIL-SD2-LLD-v1 §4.1) refuses a negative value below. Clamping it to
    // 0 here would run the gate on a number nobody configured.
    permit_grace_n_ = declare_parameter<int>("permit_grace_n", 3);
    RCLCPP_INFO(get_logger(), "permit_grace_n=%d (max hold %d ms)", permit_grace_n_,
                permit_grace_n_ * permit_recheck_ms_);

    // D4 (배치형상 §7): bounded cross-host clock-skew allowance for the token
    // time-window checks. The issuer stamps not_before/not_after on the cloud
    // clock; this gate verifies on the robot clock. Default 500ms tolerates
    // NTP-level jitter without materially widening the 30s token window.
    // Skew beyond the allowance stays fail-closed (ERR_NOT_YET_VALID/ERR_EXPIRED).
    clock_skew_ms_ = declare_parameter<int>("clock_skew_ms", 500);
    RCLCPP_INFO(get_logger(), "clock_skew_ms=%d", clock_skew_ms_);

    rclcpp::QoS permit_qos(rclcpp::KeepLast(1));
    permit_qos.best_effort();  // RELIABLE retransmits must not delay deadman detection
    permit_qos.deadline(std::chrono::milliseconds(permit_deadline_ms_));
    permit_qos.lifespan(std::chrono::milliseconds(permit_deadline_ms_));
    permit_pub_ = create_publisher<pail_msgs::msg::Permit>("/pail/permit", permit_qos);

    const auto hb_period = std::chrono::milliseconds(std::max(1, 1000 / std::max(1, permit_rate_hz_)));
    permit_hb_timer_ = create_wall_timer(hb_period, std::bind(&PepGateNode::on_permit_heartbeat, this));
    permit_recheck_timer_ = create_wall_timer(std::chrono::milliseconds(permit_recheck_ms_),
                                              std::bind(&PepGateNode::on_permit_recheck, this));

    // M8 (LLD-v2 §4): OEM safety-layer input + ESTOP path.
    //
    // `safety_stale_ms` 는 더 이상 ROS 파라미터가 아니다 (단계 6, §3.1). 값은
    // 위 `load_policy_classes_or_refuse` 가 `preconditions[safety_feed]
    // .freshness_ms` 에서 넣었다. 로그 문구는 **바꾸지 않는다** — 리그 넷이
    // `safety_stale_ms=<n>` 을 그레이프해 노드의 실측 창을 읽는다.
    // policy_file_ was declared above (gate_mode load, implementation contract).
    human_safety_enabled_ = load_human_safety_enabled(policy_file_);
    RCLCPP_INFO(get_logger(), "human_safety.enabled=%s (policy=%s) safety_stale_ms=%d",
                human_safety_enabled_ ? "true" : "false", policy_file_.c_str(), safety_stale_ms_);

    // S10 (PAIL-SD2-LLD-v1 §4.2): the node is the authoritative check because
    // thresholds also arrive by launch file, -p and parameter file, which the
    // entrypoint script never sees. All five are declared by now, and no
    // callback can run before spin(), so a refusal here stops the gate before
    // it acts on a value that would have disabled one of its checks.
    {
      pail_deploy_guard::ThresholdInput t;
      t.evidence_conf_threshold = evidence_conf_threshold_;
      t.evidence_window_ms = evidence_window_ms_;
      t.safety_stale_ms = safety_stale_ms_;
      t.clock_skew_ms = clock_skew_ms_;
      t.permit_grace_n = permit_grace_n_;
      t.permit_recheck_ms = permit_recheck_ms_;
      const char * profile_env = std::getenv("PAIL_PROFILE");
      pail_deploy_guard::EnforceThresholds(
        (profile_env && *profile_env) ? profile_env : "production", "pep_gate_node", t);
    }

    safety_sub_ = create_subscription<pail_msgs::msg::SafetyState>(
        "/pail/safety_state", 10,
        std::bind(&PepGateNode::on_safety_state, this, std::placeholders::_1));

    // D §7.6 (F-CPP-7, U-D1): observe the bridge's own report of the silence
    // window it holds motion to (seal v2 key 27). The gate's permit_deadline_ms
    // (key 26) is a different number with the same name and must not stand in
    // for it (RA-R4) — only the bridge knows what it enforces.
    bridge_state_sub_ = create_subscription<pail_msgs::msg::BridgeState>(
        "/pail/bridge_state", 10,
        std::bind(&PepGateNode::on_bridge_state, this, std::placeholders::_1));

    // Latched so a late-joining safety_adapter still receives the stop assertion.
    rclcpp::QoS stop_qos(rclcpp::KeepLast(1));
    stop_qos.reliable();
    stop_qos.transient_local();
    stop_req_pub_ = create_publisher<pail_msgs::msg::StopRequest>("/pail/stop_request", stop_qos);

    // AS-2 (HA/AT LLD §6): PEP self-attestation. The gate measures its own
    // running binary (sha256(/proc/self/exe)) and streams it to the issuer at
    // startup and every attest_interval_s, so the issuer can refuse to serve a
    // tampered gate (PAIL_ATTESTATION=required). Only meaningful against a real
    // issuer, so it runs in grpc mode only.
    attest_component_ = declare_parameter<std::string>("attest_component", "pep_gate");
    attest_interval_s_ = declare_parameter<int>("attest_interval_s", 300);
    attest_build_info_ = declare_parameter<std::string>("attest_build_info", "");
    const bool grpc_mode = (provider_mode_ == "grpc" || use_token_service_);
    if (grpc_mode) {
      do_attest();  // block-free startup attestation (verdict logged)
      if (attest_interval_s_ > 0) {
        attest_worker_=std::make_unique<pail_pep_gate::AttestationWorker>(
          [this]{if(!attest_stopping_.load())do_attest();},
          [this]{token_provider_->ShutdownAttestation();},
          [this](std::exception_ptr){RCLCPP_ERROR(get_logger(),"periodic attestation worker failed; outcome unknown");});
        attest_timer_ = create_wall_timer(std::chrono::seconds(attest_interval_s_),
                                          [this]{attest_worker_->Request();});
      }
    }

    // DC-11 / SD5 : rclcpp declares use_sim_time implicitly,
    // so the shell preflight cannot see it — the node reads it here and the
    // seal carries it (canon v2 key 4, RQ-1 접수분). true is degraded, not
    // refused: simulation is a legitimate use, and what C-B3 requires is that
    // the seal makes the run distinguishable afterwards. A failed read stays
    // "unknown" (H-B2 — not-read must not canonicalize as "off"), and the
    // seal's observation axis breaks the silence for that case.
    {
      if (has_parameter("use_sim_time")) {
        const rclcpp::Parameter p = get_parameter("use_sim_time");
        if (p.get_type() == rclcpp::ParameterType::PARAMETER_BOOL) {
          use_sim_time_seal_ = p.as_bool() ? "1" : "0";
        }
      }
      if (use_sim_time_seal_ != "0") {
        std::fprintf(stderr,
                     "PAIL PREFLIGHT WARN: SD5_SIM_TIME use_sim_time=%s — simulated time is "
                     "in effect (or unobserved); recorded in the config seal, not refused\n",
                     use_sim_time_seal_.c_str());
        std::fflush(stderr);
        RCLCPP_WARN(get_logger(),
                    "PAIL PREFLIGHT WARN: SD5_SIM_TIME use_sim_time=%s — recorded in the "
                    "config seal, not refused",
                    use_sim_time_seal_.c_str());
      }
    }

    // SD4 (설정봉인 LLD §3.4): last in the constructor, because the seal must
    // describe the configuration this gate RESOLVED, not the one it was asked
    // for — every parameter above has its final value by now. Unlike attest,
    // this runs in every provider mode: the run that verifies nothing is the
    // one worth recording.
    do_config_seal();

    // AD-4 (see spec/ARCHITECTURE.md): the permit state machine now lives in
    // libpail_gate's GateSession — the same class the Microduck adapter drives through the
    // C ABI. Constructed LAST, after every value it is fed has its final form (policy, keyring,
    // parameters, the seal digest). No callback can run before spin(), so nothing observed the
    // node without a session. The node keeps its S16* policy loaders: the library's
    // LoadSessionPolicy restates none of those refusals yet, so adopting it here would change
    // preflight semantics — that is a separate change with its own batteries.
    {
      pail_pep_gate::SessionConfig sc;
      sc.robot_id = robot_id_;
      sc.provider_mode = provider_mode_;
      sc.use_token_service = use_token_service_;
#if defined(PAIL_ENABLE_GRPC) && (PAIL_ENABLE_GRPC == 1)
      sc.grpc_built = true;
#else
      sc.grpc_built = false;
#endif
      sc.permit_grace_n = permit_grace_n_;
      sc.clock_skew_ms = clock_skew_ms_;
      sc.static_target_object_id = static_target_object_id_;
      sc.config_digest = config_digest_;
      // SK-3: the completion rules read the registry; without robot_class there is none
      // (S33 said so at preflight) and every step completes by its deadline.
      if (!robot_class_.empty()) {
        sc.skills_file = skills_dir_ + "/skills." + robot_class_ + ".yaml";
        sc.robot_class = robot_class_;
      }
      pail_pep_gate::SessionPolicy sp;
      sp.gate_mode = gate_mode_;
      sp.human_safety_enabled = human_safety_enabled_;
      sp.evidence_conf_threshold = evidence_conf_threshold_;
      sp.min_trust_rank = min_trust_rank_;
      sp.trust_rank_by_source = trust_rank_by_source_;
      sp.safety_stale_ms = safety_stale_ms_;
      sp.evidence_window_ms = evidence_window_ms_;
      sp.safety_exempt_in_progress_step = safety_exempt_in_progress_step_;
      session_ = std::make_unique<pail_pep_gate::GateSession>(sc, sp, keyring_,loaded_skills_snapshot_);
    }

    // DC-12 : reject every runtime parameter change. Each
    // parameter above was read once and sealed (SD4) — a post-startup
    // `ros2 param set` changes the parameter server's copy but not this gate's
    // members, EXCEPT use_sim_time, which rclcpp applies to the node clock
    // live; either way the seal stops describing the running configuration.
    // Registered after every declare_parameter, so the ctor's own initial
    // sets (including launch overrides) are not judged.
    param_seal_guard_ = add_on_set_parameters_callback(
        [this](const std::vector<rclcpp::Parameter> & params) {
          for (const auto & p : params) {
            RCLCPP_WARN(get_logger(),
                        "DC-12: runtime parameter change rejected: %s — parameters are "
                        "sealed at startup; restart with the new configuration",
                        p.get_name().c_str());
          }
          rcl_interfaces::msg::SetParametersResult res;
          res.successful = false;
          res.reason =
              "DC-12: parameters are sealed at startup (config seal); runtime changes "
              "are rejected — restart with the new configuration";
          return res;
        });
    const auto status_path=pail_robotops::Env("PAIL_ROBOTOPS_STATUS_SOCKET");
    if(!status_path.empty()) {
      try {
        status_server_=std::make_unique<pail_robotops::StatusServer>(status_path,pail_robotops::Env("PAIL_OPS_DEPLOYMENT_ID"),robot_id_,"pep_gate");
        size_t domain=0;const auto rc=rcl_node_get_domain_id(get_node_base_interface()->get_rcl_node_handle(),&domain);
        pail_robotops::Fields settings={{"robot_id",robot_id_},{"gate_mode",gate_mode_},{"provider_mode",provider_mode_},{"use_token_service",use_token_service_?"true":"false"},{"robot_class",robot_class_},{"policy_sha256",pail_robotops::Hash(loaded_policy_bytes_)},{"skills_sha256",session_->loaded_skills_digest()},{"permit_deadline_ms",std::to_string(permit_deadline_ms_)},{"permit_recheck_ms",std::to_string(permit_recheck_ms_)},{"permit_grace_n",std::to_string(permit_grace_n_)},{"rmw",rmw_get_implementation_identifier()},{"domain_id",rc==RCL_RET_OK?std::to_string(domain):"unknown"},{"node_name",get_fully_qualified_name()}};
        settings["settings_scope"]="resolved_gate_policy_and_session; DDS_credentials_not_attested";
        settings["evidence_confidence"]=pail_robotops::Decimal(evidence_conf_threshold_);
        settings["evidence_window_ms"]=std::to_string(evidence_window_ms_);
        settings["safety_stale_ms"]=std::to_string(safety_stale_ms_);
        settings["human_safety_enabled"]=human_safety_enabled_?"true":"false";
        settings["clock_skew_ms"]=std::to_string(clock_skew_ms_);
        settings["permit_rate_hz"]=std::to_string(permit_rate_hz_);
        settings["min_trust_rank"]=std::to_string(min_trust_rank_);
        settings["safety_exempt_in_progress_step"]=safety_exempt_in_progress_step_?"true":"false";
        pail_robotops::Fields ranks;for(const auto&kv:trust_rank_by_source_)ranks[kv.first]=std::to_string(kv.second);
        settings["trust_ranks_json"]=pail_robotops::JSON(ranks);
        status_settings_json_=pail_robotops::JSON(settings);status_generation_=pail_robotops::Hash("pail.robotops.component-settings/v1\n"+status_settings_json_);
        status_timer_=create_wall_timer(std::chrono::milliseconds(20),[this](){status_server_->Poll([this](){return status_snapshot();});});
      }catch(const std::exception&e){std::fprintf(stderr,"RO_STATUS: gate local status setup refused: %s\n",e.what());throw pail_deploy_guard::ConfigRefused("RO_STATUS: gate local status setup refused");}
    }

    // P15-H1: fatal reports leave through a worker that retries them until the issuer
    // confirms. Every outcome is logged: a failed attempt says the revocation is still
    // pending, the confirmation says it is done, and a report still pending at shutdown
    // is abandoned loudly. Created after the provider it uses; stopped in the destructor.
    {
      pail_pep_gate::FatalReportWorker::Hooks hooks;
      hooks.on_failed = [this](const pail_pep_gate::FatalReport &r, int attempts) {
        RCLCPP_ERROR(get_logger(),
                     "fatal report NOT confirmed by the issuer (%s %s chain=%s token=%s) after %d attempt(s) — revocation_pending, retrying",
                     r.decision.c_str(), r.reason_code.c_str(), r.chain_id.c_str(), r.token_id.c_str(), attempts);
      };
      hooks.on_confirmed = [this](const pail_pep_gate::FatalReport &r, int attempts) {
        // P18-H1: a report with no identity cannot confirm the revocation of a named chain;
        // what the issuer confirmed is that it revoked the robot's current chain, if any.
        const char *what = (r.chain_id.empty() && r.token_id.empty())
                               ? "robot-wide revocation acknowledged (no chain named)"
                               : "revocation confirmed";
        if (attempts > 1) {
          RCLCPP_WARN(get_logger(), "fatal report confirmed by the issuer after %d attempts (%s %s chain=%s token=%s) — %s",
                      attempts, r.decision.c_str(), r.reason_code.c_str(), r.chain_id.c_str(), r.token_id.c_str(), what);
        } else {
          RCLCPP_INFO(get_logger(), "fatal report confirmed by the issuer (%s %s chain=%s token=%s) — %s",
                      r.decision.c_str(), r.reason_code.c_str(), r.chain_id.c_str(), r.token_id.c_str(), what);
        }
      };
      hooks.on_abandoned = [this](const pail_pep_gate::FatalReport &r, int attempts) {
        RCLCPP_ERROR(get_logger(),
                     "fatal report ABANDONED (shutdown or durable terminal negative), never confirmed by the issuer (%s %s chain=%s token=%s, %d attempt(s)) — the chain may still be active there",
                     r.decision.c_str(), r.reason_code.c_str(), r.chain_id.c_str(), r.token_id.c_str(), attempts);
      };
      fatal_worker_ = std::make_unique<pail_pep_gate::FatalReportWorker>(*token_provider_, std::move(hooks));
    }
    // Readiness is diagnostic only: it neither grants a token nor proves motion.
    io_timer_ = create_wall_timer(std::chrono::seconds(1), [this]() {
      const auto now_ns = pail_robotops::MonoNS();
      const auto cmd = cmd_sub_->get_publisher_count();
      const auto evidence = evidence_sub_->get_publisher_count();
      const auto safety = safety_sub_->get_publisher_count();
      const auto safe = safe_pub_->get_subscription_count();
      const auto permit = permit_pub_->get_subscription_count();
      const bool serving = cmd && evidence && safety && safe && permit &&
          evidence_rx_ns_ > 0 && safety_rx_ns_ > 0 &&
          now_ns >= evidence_rx_ns_ && now_ns - evidence_rx_ns_ <= 2000000000LL &&
          now_ns >= safety_rx_ns_ && now_ns - safety_rx_ns_ <= 2000000000LL;
      RCLCPP_INFO(get_logger(),
          "PAIL_GATE_IO serving=%d cmd_publishers=%zu evidence_publishers=%zu safety_publishers=%zu safe_subscribers=%zu permit_subscribers=%zu evidence_seen=%d safety_seen=%d",
          serving, cmd, evidence, safety, safe, permit, evidence_rx_ns_ > 0, safety_rx_ns_ > 0);
    });
    RCLCPP_INFO(get_logger(), "PAIL_GATE_READY: construction complete; no motion authorized");
  }


private:
  rclcpp::TimerBase::SharedPtr io_timer_;
  int64_t evidence_rx_ns_{0}, safety_rx_ns_{0};
  pail_robotops::Fields status_snapshot()const {
    const auto mono=pail_robotops::MonoNS();
    const auto io=pail_robotops::JSON({
      {"contract_version","core-comm-ready/1"},
      {"scope","IO_TOPOLOGY_AND_REQUIRED_INPUTS"},
      {"physical_execution","NOT_OBSERVED"},
      {"cmd",pail_robotops::Endpoints(*this,"/cmd_vel",true,cmd_sub_->get_actual_qos())},
      {"evidence",pail_robotops::Endpoints(*this,evidence_sub_->get_topic_name(),true,evidence_sub_->get_actual_qos())},
      {"safety",pail_robotops::Endpoints(*this,safety_sub_->get_topic_name(),true,safety_sub_->get_actual_qos())},
      {"safe",pail_robotops::Endpoints(*this,"/safe_cmd_vel",false,safe_pub_->get_actual_qos())},
      {"permit",pail_robotops::Endpoints(*this,"/pail/permit",false,permit_pub_->get_actual_qos())},
      {"evidence_age_ms",pail_robotops::Age(evidence_rx_ns_,mono)},
      {"safety_age_ms",pail_robotops::Age(safety_rx_ns_,mono)}});
    pail_robotops::Fields result = {{"config_generation",status_generation_},{"resolved_settings_json",status_settings_json_},{"config_seal_digest",config_digest_},{"state",last_status_state_},{"reason",last_status_reason_},{"permit_active",session_->permit_active()?"true":"false"},{"step_active",session_->step_active()?"true":"false"},{"decision_seq",std::to_string(status_decision_seq_)},{"last_decision_mono_ns",std::to_string(last_decision_mono_ns_)},{"permit_publish_seq",std::to_string(status_permit_publish_seq_)},{"last_permit_mono_ns",std::to_string(status_last_permit_mono_ns_)},{"skills_seal_match",skills_file_sha256_==session_->loaded_skills_digest()?"true":"false"}};
 result["io_snapshot_json"]=io;result["trust_snapshot_json"]=keyring_.loaded_trust_json;return result;
  }
  std::unique_ptr<pail_robotops::StatusServer> status_server_;
  rclcpp::TimerBase::SharedPtr status_timer_;
  std::string loaded_policy_bytes_,status_settings_json_,status_generation_;
  pail_pep_gate::SkillRegistryView loaded_skills_snapshot_;
  std::string last_status_state_{"UNOBSERVED"},last_status_reason_;
  const std::string step_clock_id_{pail_pep_gate::ElapsedClockIdentity()};
  uint64_t status_decision_seq_{0},status_permit_publish_seq_{0};
  int64_t last_decision_mono_ns_{0},status_last_permit_mono_ns_{0};
  // SD4: the effective security configuration, as this process resolved it.
  pail_deploy_guard::SealInput build_seal_input() const {
    pail_deploy_guard::SealInput in;
    in.component = "pep_gate";
    in.robot_id = robot_id_;
    in.use_sim_time = use_sim_time_seal_;  // DC-11 / SD5 — canon v2 key 4

    in.profile = g_deploy_input.profile;
    in.security_enable = g_deploy_input.security_enable;
    in.security_strategy = g_deploy_input.security_strategy;
    in.keystore = g_deploy_input.keystore;
    in.enclave_provisioned = g_deploy_input.enclave_provisioned;
    in.effective_enclave = g_deploy_input.effective_enclave;

    in.token_provider_mode = provider_mode_;
    in.use_token_service = use_token_service_;
#if defined(PAIL_ENABLE_GRPC) && (PAIL_ENABLE_GRPC == 1)
    in.grpc_built = true;
    // DD-4 : seal the branch the channel factory actually
    // chose, not the env declaration — sealing the declaration would let the
    // seal certify a posture nobody is running. ControlTransportStrict is
    // memoized, so this is the *same* decision MakeControlChannel used (or
    // the process refused at startup and never reached sealing). The trust
    // anchor is the sha256 of the CA bytes actually read (mtls only — uds and
    // plaintext have no CA, and an empty list is that fact, not a gap).
    {
      const auto &t = pail_pep_gate::ControlTransportStrict();
      in.control_transport = t.transport;
      if (!t.ca_pem.empty()) {
        in.control_trust_roots_expected += 1;
        seal_add_trust_root(in, t.ca_pem);
      }
    }
#else
    // No control channel exists in this build configuration; leaving the
    // transport unset keeps the S21 degraded axis — honest, because "no
    // channel" is not "authenticated channel".
    in.grpc_built = false;
#endif
    // Baseline L3: the DDS trust roots, which live in the keystore whether or
    // not this build has gRPC. They are counted before they are read — a root
    // the gate could not open must widen the gap between expected and distinct,
    // and counting only what opened would make an unreadable CA look like a
    // deployment that never had one.
    if (!in.keystore.empty()) {
      for (const char *rel :
           {"/public/identity_ca.cert.pem", "/public/permissions_ca.cert.pem"}) {
        in.control_trust_roots_expected += 1;
        std::string pem;
        if (read_bytes(in.keystore + rel, pem)) {
          seal_add_trust_root(in, pem);
        }
      }
    }
    in.token_service_addr = token_service_addr_;
    in.keyring_mode = keyring_mode_;
    in.trusted_key_fingerprints = keyring_fingerprints_;

    in.thresholds.evidence_conf_threshold = evidence_conf_threshold_;
    in.thresholds.evidence_window_ms = evidence_window_ms_;
    in.thresholds.safety_stale_ms = safety_stale_ms_;
    in.thresholds.clock_skew_ms = clock_skew_ms_;
    in.thresholds.permit_grace_n = permit_grace_n_;
    in.thresholds.permit_recheck_ms = permit_recheck_ms_;
    in.permit_rate_hz = permit_rate_hz_;
    in.permit_deadline_ms = permit_deadline_ms_;
    // Key 27 (D §7.6): the bridge's OBSERVED window, never a derivation of
    // key 26 above (RA-R4). "unknown" until the first BridgeState arrives;
    // the S21 axis keeps that absence visible (CS2-05).
    in.motion_deadman_ms = motion_deadman_seal_;

    in.policy_file = policy_file_;
    in.policy_file_sha256 = policy_sha_for_seal();
    // v3 key 30 (SK-4): "" = no robot_class (no registry configured); "unknown" =
    // named but not read/hashed; hex = the bytes S33 judged by.
    in.skills_file_sha256 = robot_class_.empty() ? std::string()
                            : (skills_file_sha256_.empty() ? std::string("unknown") : skills_file_sha256_);
    in.safety_controller = safety_controller_;  // S36 (SK-5): measured here, always
    in.safety_controller_measured = true;
    in.human_safety_enabled = human_safety_enabled_;
    return in;
  }

  // RQ-7 consumption (DD-4): the seal must know the policy *content*, not just
  // its path — same path, different bytes must not seal identically. Vocabulary
  // (config_seal.hpp): "" = no policy path; "unknown" = path set but content
  // unhashable (unreadable, or no sha256 in this build) — the unknown stays
  // visibly unknown (H-B2) instead of folding to a value; else 64-hex.
  std::string policy_sha_for_seal() const {
    if (policy_file_.empty()) {
      return "";
    }
    if(loaded_policy_bytes_.empty())return "unknown";
    const std::string raw = sha256_raw(loaded_policy_bytes_);
    return raw.empty() ? "unknown" : to_hex(raw);
  }

  // Open-vs-empty stays a distinction the caller can act on: a policy file that
  // exists and is empty is not a policy file that could not be read, and a
  // single "" return would make those the same answer (H-B2).
  bool read_bytes(const std::string &path, std::string &out) const {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
      return false;
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    return true;
  }

  // Baseline L3. Every trust root enters the seal through here so that the
  // digest and the distinctness count can never disagree about what one root
  // is. A hash this build cannot compute is dropped rather than pushed as "" —
  // an empty string would count as a distinct root and quietly close the very
  // gap the count exists to open.
  void seal_add_trust_root(pail_deploy_guard::SealInput &in,
                           const std::string &pem) const {
    const std::string raw = sha256_raw(pem);
    if (!raw.empty()) {
      in.control_trust_anchors.push_back(to_hex(raw));
    }
  }

  // D §7.6 (F-CPP-7): seal v2 key 27. The bridge reports the silence window it
  // actually enforces; the gate seals the FIRST observation and re-seals once —
  // the transition unknown→value is itself the record (a second journal
  // declaration, SD4 상 두 번째 선언). Afterwards the seal stands: a different
  // window later is drift, logged loudly once per distinct value, never a
  // silent re-seal (DC-12 의 정신 — 재기동이 재봉인이다).
  void on_bridge_state(const pail_msgs::msg::BridgeState::SharedPtr msg) {
    if (msg->deadman_window_ms <= 0) {
      return;  // pre-field publisher: absence stays absence (H-B2), never a window
    }
    const std::string v = std::to_string(msg->deadman_window_ms);
    if (motion_deadman_seal_ == "unknown") {
      motion_deadman_seal_ = v;
      RCLCPP_INFO(get_logger(),
                  "motion_deadman_ms observed: %s ms (bridge-reported) — re-sealing once "
                  "(seal v2 key 27)", v.c_str());
      do_config_seal();
      return;
    }
    if (v != motion_deadman_seal_ && v != motion_deadman_drift_reported_) {
      motion_deadman_drift_reported_ = v;
      RCLCPP_ERROR(get_logger(),
                   "motion_deadman_ms drift: bridge now reports %s ms but the seal carries "
                   "%s ms — the sealed value stands; restart to re-seal (DC-12)",
                   v.c_str(), motion_deadman_seal_.c_str());
    }
  }

  // SD4: normalize → hash → declare. The digest computed here is for the
  // operator's eyes (the log line and GateState); the digest of record is the
  // one the ISSUER computes over the same text, which is why the canonical form
  // travels on the wire and the digest does not.
  void do_config_seal() {
    const auto in = build_seal_input();
    const auto assembled = pail_deploy_guard::CanonicalizeSeal(in);
    if (!assembled.ok) {
      // R-CS1 refused. There is no canonical form for this configuration, so
      // there is nothing honest to send: a placeholder seal would put bytes in
      // the journal that describe a configuration nobody is running. The
      // absence is the record, and it is loud (U-E6 precedent).
      std::fprintf(stderr,
                   "PAIL CONFIG SEAL: REFUSED (%s) — this run leaves no seal; the configuration "
                   "has no canonical form\n",
                   assembled.reject_reason.c_str());
      std::fflush(stderr);
      RCLCPP_ERROR(get_logger(), "config seal refused: %s", assembled.reject_reason.c_str());
      config_digest_.clear();
      return;
    }
    const std::string & canonical = assembled.text;
    const auto degraded = pail_deploy_guard::DegradedAxes(pail_deploy_guard::EvaluateSeal(in));
    const bool verifies = pail_deploy_guard::SealVerifiesAuthorization(in);
    const std::string degraded_str = pail_deploy_guard::JoinAxes(degraded);

    config_digest_ = to_hex(sha256_raw(canonical));
    if (session_) session_->SetConfigDigest(config_digest_);  // AD-4: carried on every input

    // Greppable and single-line: this is the fact an operator needs from a
    // console that scrolled past everything else.
    std::fprintf(stderr,
                 "PAIL CONFIG SEAL: v%d digest=%s verifies_authorization=%s degraded=%s "
                 "robot_id=%s mode=%s\n",
                 pail_deploy_guard::kConfigSealVersion,
                 config_digest_.empty() ? "(unavailable)" : config_digest_.c_str(),
                 verifies ? "true" : "false",
                 degraded_str.empty() ? "-" : degraded_str.c_str(),
                 robot_id_.c_str(), provider_mode_.c_str());
    std::fflush(stderr);
    // implementation contract: the observe banner is unconditional — an operator who
    // sees only this one line must already know motion is not being gated.
    // Enforce-mode output stays byte-identical (§4.2 기존 문장 불변).
    if (gate_mode_ == "observe") {
      std::fprintf(stderr,
                   "PAIL CONFIG SEAL: NOTICE — gate_mode=observe: decisions are verified and "
                   "recorded but NOT enforced; motion is not gated\n");
      std::fflush(stderr);
    }
    if (!verifies) {
      // F-SEAL-NOTOKEN (TB3 결과보고 §8.2②): 조건 하나로 세 구성이 같은 문장을
      // 받으면 notoken(fail-closed)에서 이 배너가 거짓이 되고, 늑대소년이 된
      // 배너는 static 모드의 진짜 경고까지 무디게 한다. 모드별로 사실을 말한다.
      // implementation contract: in observe the notoken sentence "every motion is
      // blocked" is false under the tap topology (nothing consumes permits),
      // so observe gets its own factual wording; enforce keeps the old bytes.
      if (provider_mode_ == "notoken" && gate_mode_ == "observe") {
        std::fprintf(stderr,
                     "PAIL CONFIG SEAL: NOTICE — token_provider_mode=notoken: no authorization "
                     "is verified because no token is ever issued; every decision records "
                     "BLOCK (ERR_NO_TOKEN) but motion is not gated (gate_mode=observe)\n");
      } else if (provider_mode_ == "notoken") {
        std::fprintf(stderr,
                     "PAIL CONFIG SEAL: NOTICE — token_provider_mode=notoken: no authorization "
                     "is verified because no token is ever issued; every motion is blocked "
                     "(fail-closed, ERR_NO_TOKEN)\n");
      } else {
        std::fprintf(stderr,
                     "PAIL CONFIG SEAL: WARNING — this gate verifies NO authorization; "
                     "motion is permitted without checking any issued token\n");
      }
      std::fflush(stderr);
    }
    // D-L8 (§7 항3): the revocation classes the operator declared, reported as
    // facts. Only the unbounded ones are named — a line per class would make
    // "this one has no bound" and "here is the list" the same output, and then
    // removing the distinction costs nothing and no row goes red.
    if (!revocation_classes_declared_) {
      std::fprintf(stderr,
                   "PAIL CONFIG SEAL: NOTICE — revocation_classes is not declared in this "
                   "policy file; this gate cannot say whether any revocation has a bounded "
                   "effective delay\n");
    }
    for (const auto &id : revocation_unbounded_ids_) {
      std::fprintf(stderr,
                   "PAIL CONFIG SEAL: NOTICE — revocation class \"%s\" has no bounded "
                   "effective delay; it takes effect at gate restart\n",
                   id.c_str());
    }
    for (const auto &id : revocation_unknown_ids_) {
      std::fprintf(stderr,
                   "PAIL CONFIG SEAL: NOTICE — revocation class \"%s\" declares no readable "
                   "max_effective_delay_ms; this gate treats it as unknown, not as bounded\n",
                   id.c_str());
    }
    std::fflush(stderr);
    RCLCPP_INFO(get_logger(), "config seal v%d digest=%s verifies_authorization=%s degraded=%s",
                pail_deploy_guard::kConfigSealVersion, config_digest_.c_str(),
                verifies ? "true" : "false", degraded_str.empty() ? "-" : degraded_str.c_str());

    const auto d = pail_pep_gate::SendConfigSeal(
        token_service_addr_, robot_id_, "pep_gate",
        pail_deploy_guard::kConfigSealVersion, canonical, verifies, degraded,
        attest_build_info_);

    if (d.sent && d.status == "OK") {
      if (!d.digest_hex.empty() && d.digest_hex != config_digest_) {
        // Two hashes of the same bytes disagreeing means they were not the same
        // bytes. Nothing here is authorized on this, but an auditor comparing
        // the journal against this log must not be left to guess.
        RCLCPP_ERROR(get_logger(),
                     "config seal: issuer digest %s != local %s — the sealed text is not the "
                     "one this gate canonicalized",
                     d.digest_hex.c_str(), config_digest_.c_str());
      } else {
        RCLCPP_INFO(get_logger(), "config seal journalled by issuer (digest=%s)",
                    d.digest_hex.c_str());
      }
      return;
    }
    // Best-effort by design (§3.3): a bench rig with no issuer must still run.
    // The absence is what an auditor reads as "unsealed", and it is loud here.
    RCLCPP_WARN(get_logger(),
                "config seal NOT journalled (status=%s addr=%s) — this run leaves no record of "
                "the configuration it ran under",
                d.status.c_str(), token_service_addr_.c_str());
  }

  std::string sha256_raw(const std::string &data) const {
#if defined(PAIL_ENABLE_GRPC) && (PAIL_ENABLE_GRPC == 1)
    unsigned char out[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(out, reinterpret_cast<const unsigned char *>(data.data()), data.size());
    return std::string(reinterpret_cast<const char *>(out), sizeof(out));
#else
    // No libsodium in this build configuration; the issuer still hashes the
    // canonical text it receives, so only the local display digest is lost.
    (void)data;
    return {};
#endif
  }

  // AS-2: measure the running binary. Returns the raw 32-byte sha256 of
  // /proc/self/exe, or empty on failure (empty measurement => issuer verdict
  // ERROR => fail-closed in required mode). grpc-only (libsodium linkage).
  std::string self_measure() {
#if defined(PAIL_ENABLE_GRPC) && (PAIL_ENABLE_GRPC == 1)
    std::ifstream f("/proc/self/exe", std::ios::binary);
    if (!f) {
      RCLCPP_WARN(get_logger(), "attest: cannot open /proc/self/exe for self-measurement");
      return {};
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    const std::string bin = ss.str();
    if (bin.empty()) return {};
    unsigned char out[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(out, reinterpret_cast<const unsigned char *>(bin.data()), bin.size());
    return std::string(reinterpret_cast<const char *>(out), sizeof(out));
#else
    return {};
#endif
  }

  static std::string to_hex(const std::string &raw) {
    static const char *k = "0123456789abcdef";
    std::string h;
    h.reserve(raw.size() * 2);
    for (unsigned char c : raw) { h.push_back(k[c >> 4]); h.push_back(k[c & 0xF]); }
    return h;
  }

  // Measure + attest to the issuer. The verdict is logged; enforcement is
  // issuer-side (it refuses tokens for an UNKNOWN/expired robot in required
  // mode), so a non-OK verdict here surfaces at GetActiveToken as NO_TOKEN.
  void do_attest() {
    const std::string meas = self_measure();
    if(attest_stopping_.load())return;
    const std::string verdict =
        token_provider_->Attest(robot_id_, attest_component_, meas, attest_build_info_);
    if (verdict == "OK") {
      RCLCPP_INFO(get_logger(), "attest OK: component=%s measurement=%s…",
                  attest_component_.c_str(), to_hex(meas).substr(0, 16).c_str());
    } else {
      RCLCPP_WARN(get_logger(),
                  "attest %s: component=%s measurement=%s… — issuer will refuse tokens in required mode",
                  verdict.c_str(), attest_component_.c_str(), to_hex(meas).substr(0, 16).c_str());
    }
  }

  // TB3 결과보고 §8.2①: PERMIT 샘플까지 무조건 "" 로 채우면 토픽 관측자에게
  // 「활성 체인이 없다」와 「있는데 말하지 않는다」가 같은 바이트다(H-B2).
  // permit_enter 는 publish_gate 뒤에 불리므로 멤버가 아니라 판정 시점 값을 받는다.
  // The one place a decision is reported to the issuer (P15-H1).
  //   fatal      → latched in the session at once (the chain is dead here whatever the
  //                issuer answers), then queued on the fatal worker: sent off this thread
  //                under PAIL_FATAL_REPORT_DEADLINE_MS and retried until confirmed.
  //   non-fatal  → one synchronous call as before; a step-complete report the issuer did
  //                not confirm is logged (the agent lease reconciles it, AV2 §3.3).
  void report_decision(const std::string &chain_id, const std::string &token_id,
                       const std::string &decision, const std::string &reason,
                       bool step_complete, bool fatal, const std::string &detail) {
    if (fatal) {
      session_->LatchFatal(chain_id, token_id);
      pail_pep_gate::FatalReport r;
      r.robot_id = robot_id_;
      r.chain_id = chain_id;
      r.token_id = token_id;
      r.decision = decision;
      r.reason_code = reason;
      r.detail = detail;
      fatal_worker_->Enqueue(std::move(r));
      return;
    }
    const bool confirmed = token_provider_->ReportDecision(robot_id_, chain_id, token_id, decision, reason,
                                                           step_complete, fatal, detail);
    if (!confirmed && step_complete) {
      RCLCPP_WARN(get_logger(), "step-complete report for token %s not confirmed by the issuer — the agent lease reconciles it",
                  token_id.c_str());
    }
  }

  void publish_gate(const std::string &state, const std::string &reason,
                    const std::string &active_chain_id = "",
                    const std::string &active_token_id = "",
                    const std::string &detail = "",
                    const std::string &completed_token_id = "") {
    // M4 fail-closed invariant (any non-PERMIT decision stops the heartbeat) is applied
    // by the session (ApplyDecision / ObserveSafety) before this is called — this function
    // only publishes. AD-4: it no longer owns permit state.
    pail_msgs::msg::GateState msg;
    msg.stamp = now();
    msg.state = state;
    msg.reason = reason;
    msg.detail = detail;
    msg.completed_token_id = completed_token_id;
    if (state == "PERMIT" && session_->step_active() && session_->step_uses_elapsed()) {
      msg.step_deadline_elapsed_ms = session_->step_deadline_elapsed_ms();
      msg.step_clock_id = step_clock_id_;
    }
    msg.active_chain_id = active_chain_id;
    msg.active_token_id = active_token_id;
    // SD4: every decision carries the configuration it was decided under, so a
    // live observer never has to assume which gate build it is watching.
    msg.config_digest = config_digest_;
    // implementation contract (D-S5): always stamped, never empty — a shadow PERMIT
    // and an enforce PERMIT must not be the same bytes (H-B2).
    msg.effective_mode = gate_mode_;
    gate_state_pub_->publish(msg);
    last_status_state_=state;last_status_reason_=reason;++status_decision_seq_;last_decision_mono_ns_=pail_robotops::MonoNS();
  }

  // DC-8 : judgment clock = system_clock, NOT node time.
  // now() follows /clock under use_sim_time — a frozen /clock froze held
  // expiry while strict_verify kept walking on system_clock (§1.6: one node,
  // two times). Publication stamps (msg.stamp = now()) stay on node time.
  int64_t now_unix_ms() { return pail_pep_gate::WallNowMs(); }

  // M3 (LLD-v2 §1.2): the single-use consumed cache (bounded, flushed on chain change)
  // lives in the session (GateSession::kConsumedCacheMax) since AD-4.

  // AD-4: mark_consumed / flush_consumed_if_chain_changed / begin_step_if_needed /
  // permit_enter / permit_stop moved into GateSession (gate_session.cpp cites the lines they
  // came from). The node keeps only what does I/O.

  // Bound only repetitive human-facing clock WARNs. Every decision/topic/report
  // still follows its original path; numeric detail remains on every GateState.
  pail_pep_gate::ClockWarningSummary clock_timer_warnings_{"step_timer"};
  pail_pep_gate::ClockWarningSummary clock_command_warnings_{"command"};
  pail_pep_gate::ClockWarningSummary clock_recheck_warnings_{"recheck"};
  void log_gate_detail(const std::string &state, const std::string &reason,
                       const std::string &detail, const std::string &path, bool log_non_clock = true) {
    auto &summary = path == "step_timer" ? clock_timer_warnings_ :
                    path == "command" ? clock_command_warnings_ : clock_recheck_warnings_;
    if (reason == "ERR_CLOCK_DRIFT") {
      const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now().time_since_epoch()).count();
      for (const auto &line : summary.Observe(detail, now))
        RCLCPP_WARN(get_logger(), "gate %s %s — %s", state.c_str(), reason.c_str(), line.c_str());
    } else {
      const auto ended = summary.End();
      if (!ended.empty()) RCLCPP_WARN(get_logger(), "%s", ended.c_str());
      if (log_non_clock && !detail.empty())
        RCLCPP_WARN(get_logger(), "gate %s %s — %s", state.c_str(), reason.c_str(), detail.c_str());
    }
  }

  void on_step_timer() {
    const auto o = session_->OnStepTimer(now_unix_ms());
    log_gate_detail(o.decision.state, o.decision.reason, o.decision.detail, "step_timer", false);
    if (!o.fired) {
      // GC-TIME-1: clock failure stops the session heartbeat but must also
      // be visible on the ROS verdict topic; never report false completion.
      if (!o.decision.state.empty()) {
        publish_gate(o.decision.state, o.decision.reason, "", "", o.decision.detail);
      }
      return;
    }
    // Step complete: the session consumed the token locally; the issuer is told the name.
    report_decision(o.report_chain_id, o.report_token_id, "PERMIT", "OK",
                    /*step_complete=*/true, /*fatal=*/false,
                    o.decision.detail);  // SK-3: "complete:timeout"
    publish_gate("BLOCK", "ERR_TOKEN_CONSUMED", "", "", o.decision.detail, o.report_token_id);
    RCLCPP_INFO(get_logger(), "step complete: token %s consumed", o.report_token_id.c_str());
  }

  // ---- M4 permit heartbeat (LLD-v2 §2.2) — state in the session, publication here ----

  void on_permit_heartbeat() {
    if (!session_->permit_active()) return;
    pail_msgs::msg::Permit msg;
    msg.stamp = now();
    msg.active_token_id = session_->permit_token_id();
    msg.permit_seq = ++permit_seq_;
    permit_pub_->publish(msg);
    ++status_permit_publish_seq_;status_last_permit_mono_ns_=pail_robotops::MonoNS();
  }

  // Re-confirm the granting token every recheck period so chain revocation
  // (e.g. CancelPlan while no cmd_vel flows) propagates within one period.
  // [implementation contract 커밋 ②] Collection → decision → execution; the recheck predicates
  // (expiry, grace ladder, REVOKED/NO_TOKEN, world hash) live in gate_core.
  void on_permit_recheck() {
    // GC-TIME-1: ordinary due completion is not a constraint violation.
    // The independent recheck deadline guard still protects a stalled timer.
    const auto in = build_inputs(pail_pep_gate::GatePath::Recheck, nullptr);
    // RPC/input collection can cross the deadline. Service completion against
    // a clock sample no earlier than 'in' before deciding that older snapshot.
    on_step_timer();
    if (!session_->permit_active()) return;
    const auto d = pail_pep_gate::decide(in);
    apply(d, nullptr, in);
  }

  // ---- M8 safety-state input + ESTOP path (LLD-v2 §4.2) ----

  // implementation contract (D-S3/D-S4): the gate's operating mode from the policy
  // file. Three outcomes, not two (H-B2):
  //  - file ABSENT: REFUSE (implementation contract, D-L2). Shadow originally read
  //    this as "결측 = enforce"; that held only while the policy governed the
  //    mode alone. Now it also governs the decision thresholds, and those have
  //    no safe default — so absence became a preflight failure.
  //  - file PRESENT but unparseable, gate_mode outside {enforce, observe}, or
  //    any rules[] entry carrying a `mode` key (§5.7 reserved, unimplemented):
  //    REFUSE. A present policy the gate cannot read might say "observe";
  //    guessing "enforce" would let the stamp disagree with the operator's
  //    written intent — the one lie this mechanism exists to make impossible.
  //  - gate_mode key MISSING in a readable file: "enforce" (D-S4 결측 규칙).
  std::string load_gate_mode_or_refuse(const std::string &path) {
    {
      std::ifstream probe(path, std::ios::binary);
      if (!probe) {
        // implementation contract (D-L2): 파일 부재는 더 이상 "gate_mode 결측"이 아니라
        // 기동 거부다. Shadow 의 결측 규칙은 *파일 안의 키*에만 걸린다 — 파일
        // 자체가 없으면 임계값의 출처가 없고, 임계의 보수측 극단(0ms · 1.0)은
        // 안전이 아니라 말없는 벽이다. 부재를 기본값으로 메우면 "정책이 지배한다"와
        // "아무도 정책을 안 줬다"가 같은 초록으로 도착한다 (H-B2).
        std::fprintf(stderr,
                     "PAIL PREFLIGHT FAIL: POLICY_ABSENT %s — the gate's decision thresholds "
                     "have no source; refusing to start (implementation contract D-L2)\n",
                     path.c_str());
        std::fflush(stderr);
        std::exit(pail_deploy_guard::kExitConfig);
      }
    }
    if(!read_bytes(path,loaded_policy_bytes_)) {
      std::fprintf(stderr,"PAIL PREFLIGHT FAIL: POLICY_UNREADABLE snapshot unavailable\n");std::exit(pail_deploy_guard::kExitConfig);
    }
    YAML::Node root;
    try {
      root = YAML::Load(loaded_policy_bytes_);
    } catch (const std::exception &e) {
      std::fprintf(stderr,
                   "PAIL PREFLIGHT FAIL: SHADOW_MODE policy %s exists but cannot be parsed (%s) "
                   "— a present policy may say observe; refusing to guess enforce\n",
                   path.c_str(), e.what());
      std::fflush(stderr);
      std::exit(pail_deploy_guard::kExitConfig);
    }
    // §5.7: rules[].mode is reserved, not implemented. A policy that writes it
    // expects per-rule override semantics this build does not have — starting
    // anyway would silently apply a mode the operator did not choose.
    const YAML::Node rules = PolicyKey(root, "rules");
    if (rules && rules.IsSequence()) {
      for (const auto &rule : rules) {
        if (rule.IsMap() && PolicyKey(rule, "rules[].mode")) {
          std::fprintf(stderr,
                       "PAIL PREFLIGHT FAIL: SHADOW_MODE policy %s uses rules[].mode — reserved "
                       ", not implemented in this build; refusing to start\n",
                       path.c_str());
          std::fflush(stderr);
          std::exit(pail_deploy_guard::kExitConfig);
        }
      }
    }
    const YAML::Node gate_mode = PolicyKey(root, "gate_mode");
    if (!gate_mode) {
      return "enforce";  // 결측 = enforce (D-S4)
    }
    std::string mode;
    try {
      mode = gate_mode.as<std::string>();
    } catch (const std::exception &) {
      mode.clear();  // non-scalar falls through to the vocabulary refusal below
    }
    if (mode != "enforce" && mode != "observe") {
      std::fprintf(stderr,
                   "PAIL PREFLIGHT FAIL: SHADOW_MODE policy %s: gate_mode=\"%s\" is outside "
                   "{enforce, observe} — refusing to guess (D-S4)\n",
                   path.c_str(), mode.c_str());
      std::fflush(stderr);
      std::exit(pail_deploy_guard::kExitConfig);
    }
    return mode;
  }

  // implementation contract (D-L1): 임계의 유일한 출처. 이 값은 policy.yaml 이
  // 이미 파싱하고 필수로 요구하던 것인데(Go 측 policy.go), 게이트는 같은 수를
  // ROS 파라미터 기본값으로 따로 들고 있었다 — 사본 셋이 우연히 일치(2000·0.90)해서
  // 정책을 조여도 판정이 안 움직였다(P-19). 기본값을 지우는 것이 수정의 본체다.
  //
  // 신선도 창 둘(`evidence_window_ms_`·`safety_stale_ms_`)은 **여기서 읽지
  // 않는다** — `preconditions[].freshness_ms` 가 그 절이고, 그 절을 걷는 것은
  // `load_policy_classes_or_refuse` 다. 같은 시퀀스를 두 로더가 걸으면 어휘의
  // 권위가 둘이 되고, 둘 중 조용한 쪽이 생긴다(단계 6, §3.1).
  //
  // 결측도 거부한다: 부재는 기본값이 아니다(D-L2). 임계에 "보수적 기본값"은
  // 없다 — 0ms · 1.0 은 전량 차단이고 그것은 안전이 아니라 말없는 벽이다.
  void load_evidence_limits_or_refuse(const std::string &path) {
    YAML::Node root;
    try {
      root = YAML::Load(loaded_policy_bytes_);
    } catch (const std::exception &e) {
      std::fprintf(stderr,
                   "PAIL PREFLIGHT FAIL: POLICY_UNREADABLE %s (%s) — evidence thresholds "
                   "have no source (implementation contract D-L1)\n",
                   path.c_str(), e.what());
      std::fflush(stderr);
      std::exit(pail_deploy_guard::kExitConfig);
    }
    auto refuse = [&](const char *key) {
      std::fprintf(stderr,
                   "PAIL PREFLIGHT FAIL: POLICY_INCOMPLETE %s: evidence.%s missing or not a "
                   "number — absence is not a default (implementation contract D-L2)\n",
                   path.c_str(), key);
      std::fflush(stderr);
      std::exit(pail_deploy_guard::kExitConfig);
    };
    // `PolicyKey` 는 중간 마디가 없거나 맵이 아니면 무효 노드를 낸다 — `evidence`
    // 절 자체의 부재와 잎의 부재가 같은 자리로 도착하고, 둘 다 잎 이름을 지목해
    // 거부한다(운영자가 고칠 수 있는 것은 잎이다).
    double threshold = 0.0;
    try {
      const YAML::Node n = PolicyKey(root, "evidence.confidence_threshold");
      if (!n) refuse("confidence_threshold");
      threshold = n.as<double>();
    } catch (const std::exception &) {
      refuse("confidence_threshold");
    }
    if (!(threshold > 0.0) || threshold > 1.0) {
      std::fprintf(stderr,
                   "PAIL PREFLIGHT FAIL: POLICY_RANGE %s: evidence.confidence_threshold=%.4f "
                   "must be in (0, 1] (implementation contract D-L1)\n",
                   path.c_str(), threshold);
      std::fflush(stderr);
      std::exit(pail_deploy_guard::kExitConfig);
    }
    evidence_conf_threshold_ = threshold;
  }

  // implementation contract D-L5 · D-L3 (§6.2, §9.2 PC-21~23·27): the classification the
  // gate enforces comes from the same file the issuer reads.
  //
  // Two clauses, two consumers, one refusal style. Absence is refused rather
  // than defaulted for the D-L2 reason: `min_trust_rank_ = 0` and
  // `safety_exempt_in_progress_step_ = false` are legal enforcement postures,
  // so a silent default would make "the operator wrote no floor" arrive as
  // "the operator wrote this floor".
  //
  // The gate does NOT re-validate the whole schema — the issuer does that
  // (S16f~S16i) and duplicating it here would make two authorities on one
  // vocabulary. The gate refuses only what it itself must read.
  // SK-2 : S33 — registry envelope ⊆ adapter measures. Three outcomes:
  //   robot_class unset      → WARN in every profile: the registry is not checked here
  //                            (the issuer still checks it against the robot's class, and
  //                            SK-4 seals the file — until then this is the declared gap)
  //   registry unreadable    → production FAIL, dev WARN (the issuer refuses it too, S39)
  //   unmeasured name(s)     → FAIL in every profile: the token would carry a bound this
  //                            adapter cannot compare, and gate_core blocks every command
  //                            as unmeasured — better read here than at the first command.
  void preflight_s33_or_refuse() {
    const char *profile_env = std::getenv("PAIL_PROFILE");
    const bool dev = profile_env && std::string(profile_env) == "dev";
    if (robot_class_.empty()) {
      std::fprintf(stderr,
                   "PAIL PREFLIGHT WARN: S33 skill registry not checked — no robot_class parameter; "
                   "the adapter measures [%s] and the issuer alone matches this robot's skills\n",
                   adapter_measures_.c_str());
      std::fflush(stderr);
      return;
    }
    const std::string path = skills_dir_ + "/skills." + robot_class_ + ".yaml";
    pail_pep_gate::SkillRegistryView reg;
    std::string err;
    if (!pail_pep_gate::LoadSkillRegistry(path, robot_class_, &reg, &err)) {
      std::fprintf(stderr, "PAIL PREFLIGHT %s: S33 %s\n", dev ? "WARN" : "FAIL", err.c_str());
      std::fflush(stderr);
      if (!dev) std::exit(pail_deploy_guard::kExitConfig);
      return;
    }
    const auto measures = pail_pep_gate::SplitMeasures(adapter_measures_);
    const auto missing = pail_pep_gate::UnmeasuredNames(reg, measures);
    if (!missing.empty()) {
      std::string names;
      for (const auto &n : missing) names += (names.empty() ? "" : ",") + n;
      std::fprintf(stderr,
                   "PAIL PREFLIGHT FAIL: S33 unmeasured guardrail %s — %s asks for it and this "
                   "adapter declares only [%s]; every command would block as unmeasured\n",
                   names.c_str(), path.c_str(), adapter_measures_.c_str());
      std::fflush(stderr);
      std::exit(pail_deploy_guard::kExitConfig);
    }
    // SK-5: every feed a row names must be one this gate observes, and every
    // safe_state one this adapter executes — same shape as the envelope check.
    const auto unobserved = pail_pep_gate::UnobservedFeeds(reg, {"safety_feed", "evidence_claim"});
    if (!unobserved.empty()) {
      std::string names;
      for (const auto &n : unobserved) names += (names.empty() ? "" : ",") + n;
      std::fprintf(stderr,
                   "PAIL PREFLIGHT %s: S33 unobserved feed %s — %s asks for it and this gate reads only "
                   "[safety_feed,evidence_claim]; a permit would hold on a feed nobody checks\n",
                   dev ? "WARN" : "FAIL", names.c_str(), path.c_str());
      std::fflush(stderr);
      if (!dev) std::exit(pail_deploy_guard::kExitConfig);
    }
    const auto unsupported = pail_pep_gate::UnsupportedSafeStates(reg, pail_pep_gate::SplitMeasures(adapter_safe_state_));
    if (!unsupported.empty()) {
      std::string names;
      for (const auto &n : unsupported) names += (names.empty() ? "" : ",") + n;
      std::fprintf(stderr,
                   "PAIL PREFLIGHT %s: S33 unsupported safe_state %s — %s names it and this adapter executes "
                   "only [%s]; revocation would have no motion behind it\n",
                   dev ? "WARN" : "FAIL", names.c_str(), path.c_str(), adapter_safe_state_.c_str());
      std::fflush(stderr);
      if (!dev) std::exit(pail_deploy_guard::kExitConfig);
    }
    skills_file_sha256_ = reg.sha256_hex;
    loaded_skills_snapshot_=reg;
    std::fprintf(stderr, "PAIL PREFLIGHT: S33 OK skill registry %s (%zu rows, %zu envelope names ⊆ measures) sha256=%s\n",
                 path.c_str(), reg.rows, reg.envelope_union.size(),
                 reg.sha256_hex.empty() ? "(not computed: no seal path)" : reg.sha256_hex.c_str());
    std::fflush(stderr);
  }

  // SK-5 (implementation contract, S36): PAIL never replaces the vendor safety function; a
  // production gate that cannot name the one it runs beside is degraded — WARN
  // here, and the S36 axis in the seal (config_seal.hpp). First edition: never a refusal.
  void preflight_s36_warn() {
    const char *profile_env = std::getenv("PAIL_PROFILE");
    const bool dev = profile_env && std::string(profile_env) == "dev";
    if (safety_controller_.empty()) {
      std::fprintf(stderr, "PAIL PREFLIGHT %s: S36 safety_controller undeclared — the vendor safety function "
                           "beside this gate is not named%s\n",
                   dev ? "INFO" : "WARN", dev ? "" : " (sealed as degraded=S36)");
    } else {
      std::fprintf(stderr, "PAIL PREFLIGHT: S36 safety_controller=%s\n", safety_controller_.c_str());
    }
    std::fflush(stderr);
  }

  void load_policy_classes_or_refuse(const std::string &path) {
    YAML::Node root;
    try {
      root = YAML::Load(loaded_policy_bytes_);
    } catch (const std::exception &e) {
      std::fprintf(stderr,
                   "PAIL PREFLIGHT FAIL: POLICY_UNREADABLE %s (%s) — trust classes "
                   "have no source (implementation contract D-L5)\n",
                   path.c_str(), e.what());
      std::fflush(stderr);
      std::exit(pail_deploy_guard::kExitConfig);
    }
    auto refuse = [&](const char *what) {
      std::fprintf(stderr,
                   "PAIL PREFLIGHT FAIL: POLICY_INCOMPLETE %s: %s (implementation contract D-L3)\n",
                   path.c_str(), what);
      std::fflush(stderr);
      std::exit(pail_deploy_guard::kExitConfig);
    };

    // ---- trust_classes[] → source-string → rank -----------------------------
    const YAML::Node classes = PolicyKey(root, "trust_classes");
    if (!classes || !classes.IsSequence() || classes.size() == 0) {
      refuse("trust_classes missing or empty");
    }
    std::unordered_map<std::string, int> id_rank;
    for (const YAML::Node &cls : classes) {
      if (!cls.IsMap()) refuse("trust_classes[] element is not a map");
      const YAML::Node id = PolicyKey(cls, "trust_classes[].id");
      const YAML::Node rank = PolicyKey(cls, "trust_classes[].rank");
      const YAML::Node sources = PolicyKey(cls, "trust_classes[].sources");
      if (!id || !rank || !sources || !sources.IsSequence()) {
        refuse("trust_classes[] element missing id / rank / sources");
      }
      int rank_value = 0;
      std::string id_value;
      try {
        id_value = id.as<std::string>();
        rank_value = rank.as<int>();
      } catch (const std::exception &) {
        refuse("trust_classes[] id is not a string or rank is not an integer");
      }
      // Rank 0 is the value an UNMAPPED source gets (§6.2). A class that
      // declares it would make "graded lowest" and "not graded at all"
      // the same number, and then the floor comparison cannot tell them apart.
      if (rank_value < 1) refuse("trust_classes[].rank must be >= 1 (0 means unmapped)");
      id_rank[id_value] = rank_value;
      for (const YAML::Node &src : sources) {
        std::string src_value;
        try {
          src_value = src.as<std::string>();
        } catch (const std::exception &) {
          refuse("trust_classes[].sources element is not a string");
        }
        trust_rank_by_source_[src_value] = rank_value;
      }
    }

    // ---- evidence.min_trust_class → the floor -------------------------------
    const YAML::Node floor_node = PolicyKey(root, "evidence.min_trust_class");
    if (!floor_node) refuse("evidence.min_trust_class missing");
    std::string floor_id;
    try {
      floor_id = floor_node.as<std::string>();
    } catch (const std::exception &) {
      refuse("evidence.min_trust_class is not a string");
    }
    const auto found = id_rank.find(floor_id);
    if (found == id_rank.end()) {
      std::fprintf(stderr,
                   "PAIL PREFLIGHT FAIL: POLICY_INCOMPLETE %s: evidence.min_trust_class="
                   "\"%s\" names no class in trust_classes — the floor would silently "
                   "become 0 (implementation contract D-L5)\n",
                   path.c_str(), floor_id.c_str());
      std::fflush(stderr);
      std::exit(pail_deploy_guard::kExitConfig);
    }
    min_trust_rank_ = found->second;

    // ---- preconditions[].freshness_ms · [safety_feed].exempt_in_progress_step
    //
    // 단계 6 (§3.1 이월분): 신선도 창 둘이 여기로 이사했다. 그전까지 게이트는
    // 증거 창을 `evidence.window_ms` 에서, 안전 창을 ROS 파라미터
    // `safety_stale_ms` 에서 읽었고 — 두 자리 모두 이 절과 **우연히 같은 수**를
    // 들고 있어서(2000 · 1000) 운영자가 이 절을 조여도 판정이 안 움직였다.
    // P-19 와 같은 형태이고, 그 우연이 곧 이 절을 장식으로 만들고 있었다.
    //
    // 범위는 여기서 재지 않는다. `S10`(`EnforceThresholds`, 생성자 뒤쪽)이 두
    // 값의 상하한을 이미 자기 권위로 재고 있고, 여기서 또 재면 같은 수에 대한
    // 판정이 두 벌이 된다. 이 로더가 거부하는 것은 **없거나 수가 아닌 것**뿐이다.
    const YAML::Node preconditions = PolicyKey(root, "preconditions");
    if (!preconditions || !preconditions.IsSequence()) refuse("preconditions missing");
    bool safety_seen = false;
    bool evidence_seen = false;
    auto read_freshness = [&](const YAML::Node &pc, const char *what) {
      const YAML::Node n = PolicyKey(pc, "preconditions[].freshness_ms");
      if (!n) refuse(what);
      try {
        return n.as<int>();
      } catch (const std::exception &) {
        refuse(what);
      }
      return 0;  // refuse() 는 돌아오지 않는다. 컴파일러를 위한 줄.
    };
    for (const YAML::Node &pc : preconditions) {
      if (!pc.IsMap()) refuse("preconditions[] element is not a map");
      const YAML::Node id = PolicyKey(pc, "preconditions[].id");
      if (!id) refuse("preconditions[].id missing");
      std::string id_value;
      try {
        id_value = id.as<std::string>();
      } catch (const std::exception &) {
        refuse("preconditions[].id is not a string");
      }
      const YAML::Node exempt = PolicyKey(pc, "preconditions[].exempt_in_progress_step");
      if (id_value == "safety_feed") {
        if (!exempt) refuse("preconditions[safety_feed].exempt_in_progress_step missing");
        try {
          safety_exempt_in_progress_step_ = exempt.as<bool>();
        } catch (const std::exception &) {
          refuse("preconditions[safety_feed].exempt_in_progress_step is not a boolean");
        }
        safety_stale_ms_ = read_freshness(
            pc, "preconditions[safety_feed].freshness_ms missing or not a number");
        safety_seen = true;
      } else if (id_value == "evidence_claim") {
        evidence_window_ms_ = read_freshness(
            pc, "preconditions[evidence_claim].freshness_ms missing or not a number");
        evidence_seen = true;
        // The gate has no evidence-side step exemption to grant. Accepting
        // `true` here would let the file claim a capability that does not
        // exist, which is the E-W5 shape: the document draws the code safer
        // (or here, more configurable) than it is. Same disposition as §7
        // rule 2 — an unimplementable declaration is refused, not ignored.
        bool exempt_value = false;
        if (exempt) {
          try {
            exempt_value = exempt.as<bool>();
          } catch (const std::exception &) {
            refuse("preconditions[evidence_claim].exempt_in_progress_step is not a boolean");
          }
        }
        if (exempt_value) {
          refuse("preconditions[evidence_claim].exempt_in_progress_step=true is not "
                 "implementable — the gate has no evidence-side step exemption");
        }
      }
    }
    if (!safety_seen) refuse("preconditions has no entry with id: safety_feed");
    // 두 항목을 **따로** 요구한다. 하나만 재면 다른 하나가 사라진 정책이
    // 그 창을 생성자 초기값(1000 · 0)으로 조용히 물려받는다 — 부재가 기본값이
    // 되는 것이 D-L2 가 막으려던 바로 그것이다.
    if (!evidence_seen) refuse("preconditions has no entry with id: evidence_claim");

    // ---- revocation_classes[] → the seal banner (D-L8, §7 항3) --------------
    //
    // This block does NOT refuse. The issuer owns this section's schema
    // (`S16h` parity, `S16i` mechanism↔bound), and a second authority on one
    // vocabulary is what §5.2.2 exists to prevent. The gate reads it for one
    // purpose: to say out loud, on the console an operator actually watches,
    // that some revocation here has no bounded effective delay.
    //
    // Three outcomes, three different bytes. Silence is reserved for the one
    // case where silence is TRUE — every declared class is bounded. Absence of
    // the section is NOT that case, and printing nothing for it would spell
    // "we did not look" the same way as "we looked and it was fine" (H-B2).
    const YAML::Node revocations = PolicyKey(root, "revocation_classes");
    revocation_classes_declared_ = revocations && revocations.IsSequence() &&
                                   revocations.size() > 0;
    if (revocation_classes_declared_) {
      for (const YAML::Node &rc : revocations) {
        std::string id_value = "(unnamed)";
        if (!rc.IsMap()) {
          revocation_unknown_ids_.push_back(id_value);
          continue;
        }
        const YAML::Node id = PolicyKey(rc, "revocation_classes[].id");
        if (id) {
          try {
            id_value = id.as<std::string>();
          } catch (const std::exception &) {
            id_value = "(unnamed)";
          }
        }
        const YAML::Node delay = PolicyKey(rc, "revocation_classes[].max_effective_delay_ms");
        if (!delay) {
          revocation_unknown_ids_.push_back(id_value);
          continue;
        }
        std::string delay_text;
        try {
          delay_text = delay.as<std::string>();
        } catch (const std::exception &) {
          revocation_unknown_ids_.push_back(id_value);
          continue;
        }
        if (delay_text == "unbounded") {
          revocation_unbounded_ids_.push_back(id_value);
        } else {
          // Anything else must read as a non-negative integer. The gate does not
          // judge the number — it only decides whether a bound EXISTS. A value
          // it cannot read is unknown, never bounded.
          try {
            if (delay.as<long long>() < 0) revocation_unknown_ids_.push_back(id_value);
          } catch (const std::exception &) {
            revocation_unknown_ids_.push_back(id_value);
          }
        }
      }
    }
  }

  // Fail-closed: unreadable/invalid policy means the safety interlock stays on.
  bool load_human_safety_enabled(const std::string &path) {
    try {
      YAML::Node root = YAML::Load(loaded_policy_bytes_);
      const YAML::Node n = PolicyKey(root, "human_safety.enabled");
      if (n) {
        return n.as<bool>();
      }
      RCLCPP_WARN(get_logger(), "policy %s has no human_safety.enabled — defaulting to true (fail-closed)", path.c_str());
    } catch (const std::exception &e) {
      RCLCPP_WARN(get_logger(), "policy load failed (%s) — human_safety enabled (fail-closed)", e.what());
    }
    return true;
  }

  void on_safety_state(const pail_msgs::msg::SafetyState::SharedPtr msg) {
    safety_rx_ns_ = pail_robotops::MonoNS();
    // D §4.1 (C-B7): the journal keeps the parsed value AND the raw string —
    // "the feed went silent" and "the feed speaks an unknown level" must stay
    // distinguishable after the fact (H-B2). Logged on change, not per message.
    const auto level = pail_pep_gate::ParseSafetyLevel(msg->level);
    if (level == pail_pep_gate::SafetyLevel::kUnknown && msg->level != session_->safety_level()) {
      RCLCPP_WARN(get_logger(),
                  "safety level UNKNOWN (raw=\"%s\" source=%s) — new permits blocked, E-STOP latch held",
                  msg->level.c_str(), msg->source.c_str());
    }
    // Snapshot BEFORE the transition: the report must name the token that WAS granting, and
    // "no permit was live" decides whether the issuer is asked for the current one below.
    const bool had_permit = session_->permit_active();

    // AD-4: the level → action switch (kOk the ONLY release path, no `default`, C-B7) and the
    // E-STOP latch live in the session (ObserveSafety). It transitions state and hands back
    // what to publish; it does no I/O, so the stop below is not delayed by it.
    pail_pep_gate::SafetyObservation obs;
    obs.level = msg->level;
    obs.source = msg->source;
    obs.detail = msg->detail;
    obs.observed_ms = pail_pep_gate::WallNowMs();  // DC-8: judgment input, wall clock
    const auto o = session_->ObserveSafety(obs);
    if (o.decision.state != "ESTOP") return;

    // 정지 발행이 먼저다 (D §7.7): 보고용 토큰 조회는 최대 200ms 블로킹하는
    // RPC 다 — 그것이 정지보다 앞이면 그 시간만큼 E-STOP 이 아직 걸리지 않은
    // 것이다. 1) permit heartbeat 즉시 정지(세션이 이미 접었다), 2) gate_state=ESTOP,
    // 3) stop_request — 보고는 그 다음에 조립한다.
    publish_gate("ESTOP", "ERR_SAFETY_UNSAFE");

    pail_msgs::msg::StopRequest stop;
    stop.stamp = now();
    stop.reason = "ERR_SAFETY_UNSAFE";
    stop_req_pub_->publish(stop);

    // Report against the granting token if a permit was live, else the issuer's
    // current active token; either way fatal=true revokes the chain. The node keeps its
    // synchronous fetch here (the session answered with its last pushed view; the fresh
    // answer is pushed back so the two never disagree).
    std::string chain_id = o.report_chain_id;
    std::string token_id = o.report_token_id;
    if (!had_permit) {
      auto tv = token_provider_->GetActiveToken(robot_id_);
      session_->SetTokenView(tv);
      // P18-H1: an unreachable issuer answers with no identity. The session already named
      // the chain whose step this gate was running (or last permitted); an empty fetch must
      // not overwrite that name with nothing.
      if (!tv.chain_id.empty() || !tv.token_id.empty()) {
        chain_id = tv.chain_id;
        token_id = tv.token_id;
      }
    }
    // P15-H1: the chain is dead in this session now (the identity learned by the fetch
    // above is latched too), and the revoking report is retried off this thread until
    // the issuer confirms it — never one 50 ms call whose result nobody reads.
    report_decision(chain_id, token_id, "ESTOP", "ERR_SAFETY_UNSAFE",
                    /*step_complete=*/false, /*fatal=*/true, "");

    if (chain_id.empty() && token_id.empty()) {
      // P18-H1: nothing to latch locally (this session never held a permit and never saw a
      // token); the report asks the issuer to revoke whatever chain the robot currently has.
      RCLCPP_ERROR(get_logger(), "ESTOP: safety UNSAFE (source=%s detail=%s) — no chain known to this gate, stop_request asserted, robot-wide revocation report queued",
                   msg->source.c_str(), msg->detail.c_str());
    } else {
      RCLCPP_ERROR(get_logger(), "ESTOP: safety UNSAFE (source=%s detail=%s) — chain %s latched dead here, stop_request asserted, revocation report queued",
                   msg->source.c_str(), msg->detail.c_str(), chain_id.c_str());
    }
  }

  void on_evidence(const pail_msgs::msg::Evidence::SharedPtr msg) {
    evidence_rx_ns_ = pail_robotops::MonoNS();
    // Use receipt time for freshness to avoid relying on upstream clocks.
    // DC-8: receipt time is a judgment input (evidence freshness) — wall clock.
    // D-L7 §6.4: ObserveEvidence is the only place ever_received becomes true.
    pail_pep_gate::EvidenceObservation obs;
    obs.object_id = msg->object_id;
    obs.confidence = msg->confidence;
    obs.source = msg->source;
    obs.received_ms = pail_pep_gate::WallNowMs();
    session_->ObserveEvidence(obs);
  }

  // ---- implementation contract 커밋 ②: collection → decision → execution ----
  // The gating predicates (ESTOP precedence, grace delegation, verification
  // outcome handling, single-use, action/constraint, evidence, safety, the
  // recheck ladder) live in gate_core::decide(). build_inputs() only collects;
  // its `if`s guard WHERE side effects happen (RPC, cache flush), never WHAT
  // the gate answers. apply() only executes what `d` says.
  //
  // TB-7 (implementation contract, IR-2): these two are public — the ONLY exposure — so the
  // wiring tests drive the exact functions the product callbacks call. No
  // test-only bypass exists: visibility changes nothing about the path.

public:
  pail_pep_gate::GateInputs build_inputs(pail_pep_gate::GatePath path,
                                         const geometry_msgs::msg::Twist *msg) {
    // AD-4: collection lives in GateSession::PrepareInputs (gate_session.cpp cites the
    // monolith line for every field). What stays here is the node's I/O: the ROS message
    // unpacking and the synchronous issuer round trip, at the monolith's positions (IR-1) —
    // the session says WHEN (WantsTokenFetch), the node does the fetch and pushes the answer,
    // and PrepareInputs then reads that fresh view. Same `now` for both, the expiry test is
    // time-dependent.
    const int64_t now = now_unix_ms();
    if (session_->WantsTokenFetch(path, now)) {
      session_->SetTokenView(token_provider_->GetActiveToken(robot_id_));
    }
    pail_pep_gate::CommandRequest cmd;
    // SK-4: /cmd_vel is the primitive skill `twist` (config/skills.diff_drive_amr.yaml);
    // a v5 token for any other skill does not authorize it, by name.
    cmd.skill = "twist";
    if (msg != nullptr) {
      cmd.linear_norm = std::sqrt(msg->linear.x * msg->linear.x +
                                  msg->linear.y * msg->linear.y +
                                  msg->linear.z * msg->linear.z);
      cmd.angular_norm = std::sqrt(msg->angular.x * msg->angular.x +
                                   msg->angular.y * msg->angular.y +
                                   msg->angular.z * msg->angular.z);
    }
    return session_->PrepareInputs(path, msg != nullptr ? &cmd : nullptr, now_unix_ms());
  }

  void apply(const pail_pep_gate::GateDecision &d,
             const geometry_msgs::msg::Twist *msg,
             const pail_pep_gate::GateInputs &in) {
    using pail_pep_gate::GatePath;
    const auto &tv = in.token_view;

    // AD-4: every state transition apply() used to make — the AV1 streak accounting, the M4
    // "non-PERMIT stops the heartbeat" fold, permit_enter, begin_step — is made by the
    // session (ApplyDecision restates the monolith's apply line for line), and the identity
    // the report should carry ([OR3/X12②]: verified ids on a verified command path, the
    // envelope's otherwise) comes back on the outcome. What stays here is the I/O.
    const auto o = session_->ApplyDecision(d, in);

    if (d.hold_permit) {
      RCLCPP_WARN(get_logger(), "permit recheck unreachable (%d/%d) — holding last permit",
                  o.unreachable_streak, permit_grace_n_);
      return;
    }

    if (d.forward && msg != nullptr) {
      safe_pub_->publish(*msg);
    }
    log_gate_detail(d.state, d.reason, d.detail,
                    in.path == GatePath::Command ? "command" : "recheck");
    if (!d.state.empty()) {
      // active_* = the granting token, PERMIT only — BLOCK/ESTOP means no
      // token is granting motion, so empty is the truthful value there.
      const bool granting = (d.state == "PERMIT");
      publish_gate(d.state, d.reason,  // non-PERMIT stopped the heartbeat (M4) in the session
                   granting ? o.report_chain_id : std::string(),
                   granting ? o.report_token_id : std::string(), d.detail);
    }
    if (d.report) {
      report_decision(o.report_chain_id, o.report_token_id,
                      d.state, d.reason, d.step_complete, d.fatal, d.detail);
    }

    if (d.reason == "ERR_WORLD_CHANGED") {
      if (in.path == GatePath::Command) {
        RCLCPP_WARN(get_logger(), "world changed under token %s — blocked (fatal)",
                    tv.token_id.c_str());
      } else {
        RCLCPP_WARN(get_logger(),
                    "permit recheck: world changed under token %s — heartbeat stopped (fatal)",
                    tv.token_id.c_str());
      }
    }
    if (in.path == GatePath::Recheck && d.state == "BLOCK") {
      if (d.reason == "ERR_ISSUER_UNREACHABLE") {
        RCLCPP_WARN(get_logger(), "permit recheck unreachable %d times — heartbeat stopped",
                    o.unreachable_streak);
      } else if (d.reason == "ERR_REVOKED" || d.reason == "ERR_NO_TOKEN") {
        RCLCPP_WARN(get_logger(), "permit recheck failed (status=%s token=%s) — heartbeat stopped",
                    tv.status.c_str(), tv.token_id.c_str());
      }
    }
  }

#ifdef PAIL_PEP_GATE_UNDER_TEST
  // [L-9/S3] Read-only observation of the step/consumption machine. These add
  // no state and take no branch the product path does not already take; they
  // exist because the step timer's effects (deadline choice, completion,
  // consumption write) are otherwise unobservable from any published topic —
  // a deformation that kills them leaves every battery green.
  bool test_step_active() const { return session_->step_active(); }
  int64_t test_step_deadline_ms() const { return session_->step_deadline_ms(); }
  const std::string &test_step_consumption_key() const { return session_->step_consumption_key(); }
  bool test_consumed_contains(const std::string &key) const {
    return session_->consumed_contains(key);
  }
  size_t test_consumed_size() const { return session_->consumed_size(); }
  // [L-9/S7] The mode the policy file actually produced. A battery that means to
  // measure observe must be able to fail when it silently got enforce instead —
  // otherwise "ran under observe" and "never reached observe" are the same green.
  const std::string &test_gate_mode() const { return gate_mode_; }
#endif  // PAIL_PEP_GATE_UNDER_TEST

private:
  void on_cmd_vel(const geometry_msgs::msg::Twist::SharedPtr msg) {
    const auto in = build_inputs(pail_pep_gate::GatePath::Command, msg.get());
    const auto d = pail_pep_gate::decide(in);
    apply(d, msg.get(), in);
  }

  rclcpp::Subscription<geometry_msgs::msg::Twist>::SharedPtr cmd_sub_;
  rclcpp::Subscription<pail_msgs::msg::Evidence>::SharedPtr evidence_sub_;
  rclcpp::Publisher<geometry_msgs::msg::Twist>::SharedPtr safe_pub_;
  rclcpp::Publisher<pail_msgs::msg::GateState>::SharedPtr gate_state_pub_;

  // D-L7 §6.4 (evidence third value) and the feeds' last values: in the session since AD-4.

  // DC-10: (steady, wall) pair captured at construction. DriftMs against this
  // baseline is how far the settable clock has strayed from the unsettable one.
  pail_pep_gate::ClockBaseline clock_baseline_ = pail_pep_gate::CaptureBaseline();

  std::string robot_id_;
  std::string provider_mode_;
  bool use_token_service_{false};
  std::string token_service_addr_;
  std::unique_ptr<pail_pep_gate::ITokenProvider> token_provider_;
  // AD-4: the permit state machine (libpail_gate). Constructed last in the ctor.
  std::unique_ptr<pail_pep_gate::GateSession> session_;
  // P15-H1: fatal reports leave through this worker (declared after the provider and
  // the session so it is destroyed — joined — before either of them).
  std::unique_ptr<pail_pep_gate::FatalReportWorker> fatal_worker_;
  pail_pep_gate::Keyring keyring_;

  // SD4: what the trust path actually resolved to, and the seal it produced.
  std::string keyring_mode_{"none"};
  std::vector<std::string> keyring_fingerprints_;
  std::string config_digest_;

  // DC-11 / SD5: resolved use_sim_time in the seal's value vocabulary.
  // "unknown" is the refusing default (H-B2) — a value the ctor never managed
  // to read must not canonicalize like one it read and found off.
  std::string use_sim_time_seal_{"unknown"};
  // DC-12: keeps the reject-all parameter callback registered for the node's
  // lifetime; dropping the handle would silently unregister the rejection.
  rclcpp::node_interfaces::OnSetParametersCallbackHandle::SharedPtr param_seal_guard_;

  // Static provider params
  std::string static_chain_id_;
  std::string static_token_id_;
  std::string static_target_object_id_;
  int static_sequence_index_{1};

  int evidence_window_ms_{0};
  double evidence_conf_threshold_;

  // D-L5 §6.2: policy trust_classes, resolved once at startup. The map is
  // source-string → rank; a source absent from it ranks 0. `min_trust_rank_` is
  // the rank of `evidence.min_trust_class`. Both are refused at startup rather
  // than defaulted (D-L2) — a floor nobody wrote is not a floor of zero.
  std::unordered_map<std::string, int> trust_rank_by_source_;
  int min_trust_rank_{0};
  // D-L3 preconditions[safety_feed].exempt_in_progress_step (PC-27). The
  // refusing value is the default here too, even though the loader refuses a
  // missing key: a default that grants the exemption would mean a loader that
  // silently skipped its clause reads exactly like one that read `true`.
  bool safety_exempt_in_progress_step_{false};

  // D-L8 §7 항3. `false` is the refusing default for the same reason as above:
  // a loader that never reached its clause must not be indistinguishable from
  // a policy file that declared nothing — but here the two ARE the same fact
  // ("this gate cannot say"), and that is exactly what the banner prints.
  bool revocation_classes_declared_{false};
  std::vector<std::string> revocation_unbounded_ids_;
  std::vector<std::string> revocation_unknown_ids_;

  // M3: single-use consumed cache + active step tracking
  rclcpp::TimerBase::SharedPtr step_timer_;

  // M4: permit heartbeat state
  int permit_rate_hz_{20};
  int permit_recheck_ms_{100};
  int permit_deadline_ms_{100};
  int clock_skew_ms_{500};
  int permit_grace_n_{3};        // AV1: consecutive unanswered rechecks tolerated
  uint32_t permit_seq_{0};
  rclcpp::Publisher<pail_msgs::msg::Permit>::SharedPtr permit_pub_;
  rclcpp::TimerBase::SharedPtr permit_hb_timer_;
  rclcpp::TimerBase::SharedPtr permit_recheck_timer_;

  // M8: safety-state input + ESTOP path
  // 0 으로 태어난다. 1000 이었을 때 그 수는 생산 정책의 선언과 우연히 같아서,
  // 로더가 이 값을 넣지 못하는 경로가 생겨도 게이트는 그럴듯하게 계속 돌았을
  // 것이다. 0 은 fail-closed 이고 무엇보다 **틀린 것으로 보인다** (단계 6).
  int safety_stale_ms_{0};
  std::string policy_file_;
  // implementation contract (D-S7): read once at startup, never switched at runtime.
  // "enforce" is the missing-key default; the loader refuses anything else.
  std::string gate_mode_{"enforce"};
  bool human_safety_enabled_{true};
  rclcpp::Subscription<pail_msgs::msg::SafetyState>::SharedPtr safety_sub_;
  rclcpp::Publisher<pail_msgs::msg::StopRequest>::SharedPtr stop_req_pub_;

  // D §7.6 (F-CPP-7): seal v2 key 27 — the bridge's observed silence window.
  // Text, not int: "unknown" must stay expressible (config_seal.hpp key 27).
  std::string motion_deadman_seal_{"unknown"};
  std::string motion_deadman_drift_reported_;  // drift logged once per distinct value
  rclcpp::Subscription<pail_msgs::msg::BridgeState>::SharedPtr bridge_state_sub_;

  // AS-2: PEP self-attestation
  std::string attest_component_;
  std::string attest_build_info_;
  // SK-2 (S33): the registry this gate serves and what the adapter measures.
  std::string robot_class_;
  std::string skills_dir_;
  std::string adapter_measures_;
  std::string adapter_safe_state_;  // SK-5
  std::string safety_controller_;   // SK-5 (S36)
  std::string skills_file_sha256_;  // SK-4 seal input; empty = not checked / not computed
  int attest_interval_s_{300};
  std::atomic<bool> attest_stopping_{false};
  std::unique_ptr<pail_pep_gate::AttestationWorker> attest_worker_;
  rclcpp::TimerBase::SharedPtr attest_timer_;
};

// TB-7: the wiring tests compile this translation unit with their own main().
#ifndef PAIL_PEP_GATE_UNDER_TEST
int main(int argc, char **argv) {
  g_deploy_input = pail_deploy_guard::ResolveDeployGuard("pep_gate", argc, argv);
  // SD3 (§3): the shell preflight is skipped whenever the entrypoint is replaced,
  // so S0~S3 are decided here, before any ROS participant is created.
  pail_deploy_guard::EnforceDeployGuard("pep_gate", argc, argv);
  rclcpp::init(argc, argv);
  // A configuration refusal raised while the node is being built (e.g. the robotops
  // status endpoint, RO_STATUS) must leave through here as exit 78, not through
  // std::exit inside the constructor: that path crashed with a segmentation fault
  // during rclcpp teardown on the TB3 rig (2026-09-23).
  try {
    rclcpp::spin(std::make_shared<PepGateNode>());
  } catch (const pail_deploy_guard::ConfigRefused &e) {
    std::fprintf(stderr, "PAIL STARTUP REFUSED: %s [component=pep_gate]\n", e.what());
    rclcpp::shutdown();
    return pail_deploy_guard::kExitConfig;
  }
  rclcpp::shutdown();
  return 0;
}
#endif  // PAIL_PEP_GATE_UNDER_TEST
