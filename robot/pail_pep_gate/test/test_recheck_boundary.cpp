// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
// Actual ROS callback, deterministic RPC delay crossing a verified step deadline.
// Grant injection is the existing decision/state seam, not a signature test.
#define PAIL_PEP_GATE_UNDER_TEST 1
#include "../src/pep_gate_node.cpp"
#include "tb7_policy_fixture.hpp"
#include <thread>
struct BoundaryProvider : pail_pep_gate::ITokenProvider {
  int completed=0;
  pail_pep_gate::ActiveTokenView GetActiveToken(const std::string &) override {
    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    pail_pep_gate::ActiveTokenView v; v.ok=true;v.status="OK";v.token_id="boundary-token";
    v.chain_id="boundary-chain";v.current_subgraph_hash=std::string(32,'a');return v;
  }
  bool ReportDecision(const std::string&,const std::string&,const std::string&,
      const std::string&,const std::string&,bool done,bool,const std::string&) override {completed+=done;return true;}
  std::string Attest(const std::string&,const std::string&,const std::string&,const std::string&) override {return "OK";}
};
struct Preview12Probe {
  static bool run(PepGateNode &node) {
    using namespace pail_pep_gate;
    SessionConfig c;SessionPolicy p;p.human_safety_enabled=false;
    node.session_=std::make_unique<GateSession>(c,p,Keyring{});
    auto provider=std::make_unique<BoundaryProvider>();auto *observed=provider.get();
    node.token_provider_=std::move(provider);
    auto in=node.session_->PrepareInputs(GatePath::Command,nullptr,WallNowMs());
    in.verify_ok=true;in.token_info.chain_id="boundary-chain";in.token_info.token_id="boundary-token";
    in.token_info.consumption_key="boundary-key";in.token_info.max_duration_sec=.06;
    in.token_info.not_after_unix_ms=WallNowMs()+10000;in.token_info.subgraph_snapshot_hash=std::string(32,'a');
    GateDecision d;d.state="PERMIT";d.reason="OK";d.enter_permit=true;d.begin_step=true;
    node.session_->ApplyDecision(d,in);
    node.on_permit_recheck();
    bool ok=!node.session_->step_active() && node.session_->consumed_contains("boundary-key") && observed->completed==1;
    std::printf("%s recheck RPC crossing deadline consumes exactly once; active=%d completed=%d\n",
                ok?"PASS":"FAIL",node.session_->step_active(),observed->completed);
    node.on_permit_recheck();
    return ok && observed->completed==1;
  }
};
int main() {
  // One communication contract (0.2.0-preview.40): no selecting setting; this fixture injects a non-gRPC
  // (non-reporting) test provider.
  unsetenv("PAIL_CORE_COMM_CONTRACT");
  setenv("PAIL_PROFILE", "dev", 1);
  setenv("PAIL_SEAL_DEADLINE_MS", "50", 1);
  setenv("PAIL_GRPC_TLS", "off", 1);
  setenv("PAIL_GRPC_INSECURE_ACK", "i-accept-plaintext", 1);
  const char *args[]={"test_recheck_boundary","--ros-args","-p","token_provider_mode:=notoken","-p",kTb7PolicyFileArg};
  rclcpp::init(sizeof(args)/sizeof(args[0]),args);
  bool ok=false;{PepGateNode node;ok=Preview12Probe::run(node);}
  rclcpp::shutdown();return ok?0:1;
}
