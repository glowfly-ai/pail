// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
// P37-L2 (preview.38): the HOLD/RESUME diagnostics name their measurement point and never invent a count.
// Exercises the real methods with a deterministic elapsed clock, like test_elapsed_deadman.cpp.
#define PAIL_MOTION_BRIDGE_UNDER_TEST 1
#include "../src/motion_bridge_node.cpp"
#include <cstdio>
struct BridgeClockTestPeer {
  static void permit(MotionBridgeNode &n, uint32_t seq) {
    auto p=std::make_shared<pail_msgs::msg::Permit>(); p->permit_seq=seq; n.on_permit(p);
  }
  static void command(MotionBridgeNode &n, double x) {
    auto p=std::make_shared<geometry_msgs::msg::Twist>(); p->linear.x=x; n.on_safe_cmd_vel(p);
  }
  static bool active(MotionBridgeNode &n) { return n.forwarding_; }
  static void watch(MotionBridgeNode &n) { n.on_watchdog(); }
  static uint64_t outputs(MotionBridgeNode &n) { return n.output_seq_; }
  static uint64_t nonzero(MotionBridgeNode &n) { return n.nonzero_publish_calls_; }
  static uint64_t holds(MotionBridgeNode &n) { return n.hold_count_; }
  static uint64_t unobserved(MotionBridgeNode &n) { return n.permits_unobserved_total_; }
  static uint64_t suppressed(MotionBridgeNode &n) { return n.transitions_suppressed_total_; }
  static const std::string &kind(MotionBridgeNode &n) { return n.last_gap_kind_; }
  static const std::string &reason(MotionBridgeNode &n) { return n.last_hold_reason_; }
  static int64_t gap(MotionBridgeNode &n) { return n.last_gap_ms_; }
  static std::string field(MotionBridgeNode &n, const char *k) { auto f=n.status_snapshot(); return f.count(k)?f.at(k):"<missing>"; }
};
int main(int argc,char **argv) {
  rclcpp::init(argc,argv); int failures=0;
  {
    int64_t elapsed=1000;
    MotionBridgeNode n([&](){return elapsed;});
    auto check=[&](bool ok,const char *name){ std::printf("%s %s\n",ok?"PASS":"FAIL",name); if(!ok)++failures; };
    using P=BridgeClockTestPeer;
    // first permit: nothing to measure a gap against
    P::permit(n,342);
    check(P::active(n)&&P::kind(n)=="unavailable"&&P::gap(n)==-1,"first permit: gap and unobserved count unavailable");
    P::command(n,0.1); P::command(n,0.0); P::command(n,0.2);
    check(P::outputs(n)==3&&P::nonzero(n)==2,"nonzero publish calls exclude zero commands");
    // silence hold at seq 342, resume at seq 406 one second later: 63 permits not observed
    elapsed=1300; P::watch(n);
    check(!P::active(n)&&P::holds(n)==1&&P::reason(n)=="permit silence","watchdog silence holds and names the reason");
    check(P::outputs(n)==4&&P::nonzero(n)==2,"the hold's zero-twist is a publish call but not a nonzero one");
    elapsed=2300; P::permit(n,406);
    check(P::active(n)&&P::kind(n)=="counted"&&P::unobserved(n)==63&&P::gap(n)==1000,"forward sequence gap is counted (406-342-1) with the elapsed gap");
    // the very next sequence number after a hold: counted, zero unobserved
    elapsed=2600; P::watch(n); elapsed=3000; P::permit(n,407);
    check(P::kind(n)=="counted"&&P::unobserved(n)==63,"adjacent sequence after a hold counts zero unobserved");
    // same sequence number after a hold: a replayed or restarted stream, not a count
    elapsed=3300; P::watch(n); elapsed=3500; P::permit(n,407);
    check(P::active(n)&&P::kind(n)=="reset_or_regression"&&P::unobserved(n)==63,"equal sequence after a hold is reset_or_regression");
    // lower sequence number after a hold (restart): not a count
    elapsed=3800; P::watch(n); elapsed=4000; P::permit(n,5);
    check(P::active(n)&&P::kind(n)=="reset_or_regression"&&P::unobserved(n)==63,"lower sequence after a hold is reset_or_regression");
    // wrap-around: a stream already at 0xFFFFFFFE that resumes at 1 after a hold is a regression, never 2^32
    // unobserved permits (a separate node: the first permit of a stream is never counted against anything)
    {
      int64_t e2=1000; MotionBridgeNode w([&](){return e2;});
      P::permit(w,0xFFFFFFFE); e2=1300; P::watch(w); e2=1500; P::permit(w,1);
      check(P::active(w)&&P::kind(w)=="reset_or_regression"&&P::unobserved(w)==0,"sequence wrap after a hold is reset_or_regression");
    }
    // clock error hold: the gap is unavailable at the next resume
    elapsed=-1; P::permit(n,6);   // a monotonic sequence: the hold must come from the clock, not from a replay suspicion
    check(!P::active(n)&&P::reason(n)=="elapsed clock unavailable or reversed","unavailable elapsed clock holds");
    elapsed=6000; P::permit(n,7);
    check(P::active(n)&&P::gap(n)==-1,"gap after a clock-error hold is unavailable (-1)");
    // deadline/zero invariants unchanged: an expired command door still holds, forwards nothing
    elapsed=6201; P::command(n,0.3);
    const auto before=P::nonzero(n);
    check(!P::active(n)&&P::nonzero(n)==before,"expired command door holds and publishes no nonzero command");
    // rate cap: many transitions inside one elapsed second are counted but their lines are suppressed after two
    const auto suppressed_before=P::suppressed(n);
    const auto holds_before=P::holds(n);
    for(uint32_t i=0;i<6;++i){ elapsed=7000+i*250; P::permit(n,100+i); elapsed=7000+i*250+201; P::watch(n); }  // monotonic elapsed: resume+hold per 250 ms
    check(P::holds(n)==holds_before+6&&P::suppressed(n)>suppressed_before,"transition lines are capped per elapsed second (counters keep every transition)");
    // the status snapshot carries the named fields
    check(P::field(n,"nonzero_publish_calls")==std::to_string(P::nonzero(n))&&P::field(n,"last_gap_kind")==P::kind(n)
          &&P::field(n,"permits_unobserved_total")==std::to_string(P::unobserved(n))&&P::field(n,"clock_basis")=="elapsed_suspend_inclusive"
          &&P::field(n,"hold_count")==std::to_string(P::holds(n))&&P::field(n,"transitions_suppressed_total")==std::to_string(P::suppressed(n)),"status snapshot exposes the diagnostics by name");
  }
  rclcpp::shutdown();return failures?1:0;
}
