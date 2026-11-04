// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
// Linux process-local clock interposition. Neither the host nor another process
// is adjusted. The real shared library, verifier and C ABI see the same clocks.
#include <sys/syscall.h>
#include <unistd.h>
#include <time.h>
#include <sodium.h>
#include <cerrno>
#include <cstdio>
#include <fstream>
#include <limits>
#include "pail.pb.h"
#include "token_service.pb.h"
#include "pail_gate_abi.pb.h"
#include "pail_gate/gate_session.hpp"
#include "pail_gate/pail_gate.h"
using namespace pail_pep_gate;
namespace abi = pail::gate::abi::v1;
namespace {
bool inject = false, boot_fail = false;
int64_t wall = 1750000000000LL, mono = 1000000, boot = 1000000;
int failures = 0;
void check(const char *name, bool ok) {
  std::printf("%s %s\n", ok ? "PASS" : "FAIL", name);
  if (!ok) ++failures;
}
void reset() { wall = 1750000000000LL; mono = boot = 1000000; boot_fail = false; inject = true; }
void advance(int ms) { wall += ms; mono += ms; boot += ms; }
}
extern "C" int clock_gettime(clockid_t id, timespec *ts) noexcept {
  if (!inject || (id != CLOCK_REALTIME && id != CLOCK_MONOTONIC && id != CLOCK_BOOTTIME))
    return static_cast<int>(syscall(SYS_clock_gettime, id, ts));
  if (id == CLOCK_BOOTTIME && boot_fail) { errno = EIO; return -1; }
  const int64_t n = id == CLOCK_REALTIME ? wall : id == CLOCK_MONOTONIC ? mono : boot;
  ts->tv_sec = n / 1000; ts->tv_nsec = n % 1000 * 1000000;
  return 0;
}
namespace {
struct Key {
  unsigned char pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
  Key() { crypto_sign_keypair(pk, sk); }
  Keyring keyring() const { Keyring k; k.pubkeys["clock-key"] = {pk, pk + sizeof pk}; return k; }
  std::string json() const {
    char b[128]; sodium_bin2base64(b,sizeof b,pk,sizeof pk,sodium_base64_VARIANT_ORIGINAL);
    return std::string("{\"keys\":[{\"key_id\":\"clock-key\",\"ed25519_public_key_base64\":\"") + b + "\"}]}";
  }
  pail::token::v1::GetActiveTokenResponse token(double duration=1., int ttl=60000) const {
    pail::v1::ActionToken t;
    t.set_token_id("tok"); t.set_chain_id("chain"); t.set_plan_id("plan");
    t.set_robot_id("robot-1"); t.set_sequence_index(1); t.set_step_id("s1");
    t.set_schema_version(4); t.set_action_type(static_cast<pail::v1::ActionType>(1));
    t.set_issued_at_unix_ms(wall); t.set_not_before_unix_ms(wall-1000); t.set_not_after_unix_ms(wall+ttl);
    t.set_subgraph_snapshot_hash(std::string(32,'w'));
    auto *c=t.mutable_constraints(); c->set_max_linear_speed_mps(.5); c->set_max_angular_speed_rps(1.);
    c->set_max_duration_sec(duration);
    const std::string bytes=t.SerializeAsString(); unsigned char sig[crypto_sign_BYTES];
    crypto_sign_detached(sig,nullptr,reinterpret_cast<const unsigned char*>(bytes.data()),bytes.size(),sk);
    pail::token::v1::GetActiveTokenResponse r;
    r.set_status(pail::token::v1::OK); r.set_chain_id("chain"); r.set_expected_sequence_index(1);
    r.set_current_subgraph_hash(t.subgraph_snapshot_hash());
    auto *st=r.mutable_token(); st->set_action_token_bytes(bytes); st->set_key_id("clock-key");
    st->set_signature(std::string(reinterpret_cast<char*>(sig),sizeof sig));
    return r;
  }
};
SessionConfig config() { SessionConfig c; c.robot_id="robot-1"; return c; }
SessionPolicy policy() { SessionPolicy p; p.human_safety_enabled=false; return p; }
ActiveTokenView view(const pail::token::v1::GetActiveTokenResponse &r) {
  ActiveTokenView v; v.ok=true; v.status="OK"; v.token_id="tok"; v.chain_id="chain";
  v.expected_sequence_index=1; v.current_subgraph_hash=r.current_subgraph_hash();
  v.action_token_bytes=r.token().action_token_bytes(); v.signature_bytes=r.token().signature();
  v.key_id_bytes=r.token().key_id(); v.signed_token_bytes=r.token().SerializeAsString(); return v;
}
struct Rig {
  Key k; GateSession s{config(),policy(),k.keyring()};
  Rig(double duration=1., int ttl=60000) { s.SetTokenView(view(k.token(duration,ttl))); }
  SessionOutcome cmd(int64_t at=0) { CommandRequest c; c.linear_norm=.1; c.requested_class=kClassMove; return s.OnCommand(c,at); }
  void start() { check("signed_permit_control",cmd().decision.forward); }
  void offline() { ActiveTokenView v; v.status="UNREACHABLE"; s.SetTokenView(v); }
};
bool blocked(const SessionOutcome &o,const char *reason="ERR_CONSTRAINT") {
  return o.decision.state=="BLOCK" && o.decision.reason==reason && !o.decision.forward && !o.permit_active;
}
}
int main() {
  if (sodium_init()<0) return 2;
  reset(); check("clock_interposition_active", WallNowMs()==wall && ElapsedNowMs()==boot);
  {
    Rig r; r.start(); advance(700); wall+=400;
    check("forward_jump_no_early_command_refusal",r.cmd().decision.forward);
    check("forward_jump_no_early_timer",!r.s.OnStepTimer().fired);
    advance(300); check("forward_jump_exact_elapsed_timer",r.s.OnStepTimer().fired);
  }
  reset(); {
    Rig r; r.start(); const auto deadline=r.s.step_deadline_elapsed_ms();
    advance(600); wall-=400;
    check("rewind_inside_budget_permits",r.cmd().decision.forward);
    check("repeat_does_not_reset_budget",r.s.step_deadline_elapsed_ms()==deadline);
    advance(400);
    auto o=r.cmd(); check("rewind_command_at_boundary_blocks",blocked(o));
    check("detail_identifies_elapsed_clock",o.decision.detail.find("clock=elapsed")!=std::string::npos && o.decision.detail.find("overrun_ms=0")!=std::string::npos);
    check("rewind_timer_consumes",r.s.OnStepTimer().fired);
    check("timer_exactly_once",!r.s.OnStepTimer().fired && r.s.consumed_size()==1);
    check("replay_after_wall_rewind_refused",blocked(r.cmd(),"ERR_TOKEN_CONSUMED"));
  }
  reset(); {
    Rig r; r.start(); r.offline(); advance(999); wall-=400;
    check("offline_command_before_boundary_permits",r.cmd().decision.forward);
    advance(1); check("offline_command_at_boundary_blocks",blocked(r.cmd()));
  }
  reset(); {
    Rig r; r.start(); r.offline(); advance(1000); wall-=400;
    check("offline_recheck_never_extends_budget",blocked(r.s.OnRecheck()));
  }
  reset(); {
    Rig r; r.start(); advance(1000); wall-=400;
    check("reachable_recheck_checks_budget",blocked(r.s.OnRecheck()));
  }
  reset(); {
    Rig r(10.,100); r.start(); advance(601);
    check("absolute_expiry_still_blocks_recheck",blocked(r.s.OnRecheck(),"ERR_EXPIRED"));
    check("absolute_expiry_still_blocks_command",blocked(r.cmd(),"ERR_EXPIRED"));
  }
  reset(); {
    Rig r(0.,1000); r.start(); advance(700); wall+=300;
    check("zero_duration_keeps_absolute_fallback",r.s.OnStepTimer().fired);
  }
  reset(); {
    Rig r; r.start(); wall+=501;
    check("large_jump_still_blocks",blocked(r.cmd(),"ERR_CLOCK_DRIFT"));
    auto o=r.s.OnStepTimer(); check("drift_timer_never_claims_completion",blocked(o,"ERR_CLOCK_DRIFT") && !o.fired && !o.decision.step_complete);
    check("timer_drift_has_numeric_cause",o.decision.detail.find("drift_ms=501")!=std::string::npos && o.decision.detail.find("cause=wall_drift")!=std::string::npos && o.decision.detail.find("path=step_timer")!=std::string::npos);
    wall-=501;check("wall_return_does_not_latch_elapsed_fault",r.cmd().decision.forward);
    check("wall_return_does_not_reset_budget",r.s.step_deadline_elapsed_ms()==1001000);
  }
  reset(); {
    Rig r; r.start(); boot_fail=true;
    auto o=r.s.OnStepTimer(); check("clock_read_failure_stops_without_completion",blocked(o,"ERR_CLOCK_DRIFT") && !o.fired);
    check("timer_read_fault_is_named",o.decision.detail.find("cause=elapsed_unavailable")!=std::string::npos);
    boot_fail=false; check("clock_fault_latched",blocked(r.cmd(),"ERR_CLOCK_DRIFT"));
  }
  reset(); {
    Rig r; r.start(); boot-=1;
    check("elapsed_clock_reversal_refused",blocked(r.cmd(),"ERR_CLOCK_DRIFT"));
    check("timer_reversal_is_named",r.s.OnStepTimer().decision.detail.find("cause=elapsed_reversed")!=std::string::npos);
    boot+=2; check("elapsed_reversal_cannot_reset_budget",blocked(r.cmd(),"ERR_CLOCK_DRIFT"));
  }
  reset(); {
    Rig r(.2); r.start(); boot+=250; wall+=250; // suspend: MONOTONIC does NOT advance
    check("suspend_time_consumes_budget",r.s.OnStepTimer().fired);
  }
  for (double bad : {-1., std::numeric_limits<double>::infinity(), std::numeric_limits<double>::quiet_NaN(), 1e100, .0001}) {
    reset(); Rig r(bad); check("invalid_or_unrepresentable_duration_refused",blocked(r.cmd()));
  }
  reset(); {
    Rig r; r.start(); advance(50); auto o=r.cmd(); check("normal_progress_permits",o.decision.forward);
    GateSession fresh(config(),policy(),r.k.keyring());
    check("new_session_restores_no_active_permit",!fresh.permit_active() && !fresh.step_active());
    check("new_session_without_view_refuses",blocked(fresh.OnCommand(CommandRequest{}),"ERR_NO_TOKEN"));
  }
  reset(); {
    Rig r; wall+=500; r.start(); advance(1000); wall-=1000;
    check("opposite_allowed_drift_extremes_do_not_extend",blocked(r.cmd()));
  }
  reset(); {
    Rig r; r.start(); CommandRequest cmd; cmd.linear_norm=.1; cmd.requested_class=kClassMove;
    auto in=r.s.PrepareInputs(GatePath::Command,&cmd);
    in.elapsed_now_ms=-1;
    check("unknown_elapsed_in_core_refuses",decide(in).reason=="ERR_CLOCK_DRIFT");
    in=r.s.PrepareInputs(GatePath::Command,&cmd); in.step_deadline_elapsed_ms=-1;
    check("unknown_elapsed_deadline_refuses",decide(in).reason=="ERR_CLOCK_DRIFT");
    in=r.s.PrepareInputs(GatePath::Command,&cmd); in.clock_drift_ms=std::numeric_limits<int64_t>::min();
    check("int64_min_drift_refuses_without_abs_overflow",decide(in).reason=="ERR_CLOCK_DRIFT");
    int64_t deadline=0;
    check("duration_addition_overflow_refused",!DurationDeadlineMs(std::numeric_limits<int64_t>::max()-5,1.,&deadline));
    check("duration_fraction_never_rounded_up",DurationDeadlineMs(1000,.0019,&deadline) && deadline==1001);
  }
  // Same process-local jump through the public C ABI, with real signature bytes.
  reset(); {
    setenv("PAIL_KEYRING_MODE", "unsigned-dev", 1);
    Key k; char path[]="/tmp/pail-clock-key-XXXXXX"; int fd=mkstemp(path);
    if(fd<0) return 2;
    close(fd); std::ofstream(path)<<k.json();
    abi::Config c; c.set_robot_id("robot-1"); c.set_policy_path(PAIL_CLOCK_POLICY); c.set_keyring_path(path);
    c.set_clock_skew_ms(500); c.set_permit_grace_n(3);
    char *err=nullptr; auto bytes=c.SerializeAsString();
    pail_gate_t *h=pail_gate_new(reinterpret_cast<const uint8_t*>(bytes.data()),bytes.size(),&err);
    pail_gate_free_buf(err); unlink(path); check("abi_created",h!=nullptr);
    if(!h) return 1;
    abi::TokenInput u; u.set_reachable(true); *u.mutable_response()=k.token();
    bytes=u.SerializeAsString(); check("abi_signed_token_pushed",pail_gate_set_token(h,reinterpret_cast<const uint8_t*>(bytes.data()),bytes.size())==0);
    abi::SafetyInput so; so.set_level("OK"); so.set_observed_ms(wall); bytes=so.SerializeAsString();
    uint8_t *out=nullptr; size_t out_len=0; pail_gate_observe_safety(h,reinterpret_cast<const uint8_t*>(bytes.data()),bytes.size(),&out,&out_len); pail_gate_free_buf(out);
    abi::CommandInput cmd; cmd.set_linear_norm(.1); cmd.set_requested_class(kClassMove);
    auto command=[&]() { auto b=cmd.SerializeAsString(); uint8_t *out_command=nullptr; size_t command_len=0;
      int rc=pail_gate_command(h,reinterpret_cast<const uint8_t*>(b.data()),b.size(),&out_command,&command_len); abi::Outcome r;
      bool parsed=rc==0 && r.ParseFromArray(out_command,static_cast<int>(command_len)); pail_gate_free_buf(out_command); check("abi_command_parsed",parsed); std::printf("ABI verdict %s/%s %s\n",r.state().c_str(),r.reason().c_str(),r.detail().c_str()); return r; };
    check("abi_permit_control",command().forward());
    advance(1000); wall-=400;
    auto o=command(); check("abi_rewind_duration_refused",o.state()=="BLOCK" && o.reason()=="ERR_CONSTRAINT" && !o.forward());
    abi::TickInput tick; bytes=tick.SerializeAsString();
    check("abi_tick_call",pail_gate_tick(h,reinterpret_cast<const uint8_t*>(bytes.data()),bytes.size(),&out,&out_len)==0);
    abi::TickOutcome to; bool parsed=to.ParseFromArray(out,static_cast<int>(out_len)); pail_gate_free_buf(out);
    check("abi_timer_consumes_same_deadline",parsed && to.step().fired() && to.step().step_complete() && !to.step().permit_active());
    pail_gate_free(h);
    // Ordinary idle completion must not create a spurious constraint refusal:
    // no command crosses the boundary; both paths share one adapter tick.
    reset();
    char path2[]="/tmp/pail-clock-key-XXXXXX"; fd=mkstemp(path2);
    if(fd<0) return 2;
    close(fd); std::ofstream(path2)<<k.json(); c.set_keyring_path(path2);
    bytes=c.SerializeAsString(); err=nullptr;
    h=pail_gate_new(reinterpret_cast<const uint8_t*>(bytes.data()),bytes.size(),&err);
    pail_gate_free_buf(err); unlink(path2); if(!h) return 2;
    *u.mutable_response()=k.token(); bytes=u.SerializeAsString();
    pail_gate_set_token(h,reinterpret_cast<const uint8_t*>(bytes.data()),bytes.size());
    so.set_observed_ms(wall); bytes=so.SerializeAsString();
    pail_gate_observe_safety(h,reinterpret_cast<const uint8_t*>(bytes.data()),bytes.size(),&out,&out_len); pail_gate_free_buf(out);
    check("abi_idle_completion_permit_control",command().forward()); advance(1000);
    bytes=tick.SerializeAsString();
    pail_gate_tick(h,reinterpret_cast<const uint8_t*>(bytes.data()),bytes.size(),&out,&out_len);
    parsed=to.ParseFromArray(out,static_cast<int>(out_len)); pail_gate_free_buf(out);
    check("abi_idle_completion_no_spurious_refusal",parsed && to.recheck().state().empty() && to.step().fired() && to.step().step_complete());
    pail_gate_free(h);
  }
  inject=false;
  std::printf("step_clock_injection failures=%d\n",failures);
  return failures ? 1 : 0;
}
