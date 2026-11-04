// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
// Exercise the actual forwarding/watchdog methods with a deterministic clock.
#define PAIL_MOTION_BRIDGE_UNDER_TEST 1
#include "../src/motion_bridge_node.cpp"
#include <cstdio>
struct BridgeClockTestPeer {
  static void permit(MotionBridgeNode &n) {
    auto p=std::make_shared<pail_msgs::msg::Permit>(); p->permit_seq=++seq; n.on_permit(p);
  }
  static void command(MotionBridgeNode &n) {
    auto p=std::make_shared<geometry_msgs::msg::Twist>(); p->linear.x=0.1; n.on_safe_cmd_vel(p);
  }
  static bool fresh_output(MotionBridgeNode &n) {
    auto q=n.drive_pub_->get_actual_qos().get_rmw_qos_profile();
    return q.depth==1 && q.reliability==RMW_QOS_POLICY_RELIABILITY_RELIABLE &&
      q.durability==RMW_QOS_POLICY_DURABILITY_VOLATILE && q.lifespan.sec==0 && q.lifespan.nsec==100000000;
  }
  static bool active(MotionBridgeNode &n) { return n.forwarding_; }
  static void watch(MotionBridgeNode &n) { n.on_watchdog(); }
  static uint64_t outputs(MotionBridgeNode &n) { return n.output_seq_; }
  static inline uint32_t seq=0;
};
int main(int argc,char **argv) {
  rclcpp::init(argc,argv); int failures=0;
  {
    int64_t elapsed=1000;
    MotionBridgeNode n([&](){return elapsed;});
    auto check=[&](bool ok,const char *name){ std::printf("%s %s\n",ok?"PASS":"FAIL",name); if(!ok)++failures; };
    using P=BridgeClockTestPeer;
    check(P::fresh_output(n),"output samples expire in permit deadline; reliable compatibility retained");
    P::permit(n); P::command(n);
    check(P::active(n)&&P::outputs(n)==1,"live permit forwards");
    elapsed=1201; P::command(n);
    check(!P::active(n)&&P::outputs(n)==2,"expired command door holds before timer");
    P::command(n);check(P::outputs(n)==2,"hold does not forward");
    elapsed=2000;P::permit(n);elapsed=2201;P::watch(n);
    check(!P::active(n),"watchdog silence independent of wall clock");
    elapsed=3000;P::permit(n);elapsed=2999;P::watch(n);
    check(!P::active(n),"elapsed reversal holds");
    elapsed=4000;P::permit(n);elapsed=-1;P::command(n);
    check(!P::active(n),"unavailable elapsed clock holds");
    elapsed=5000;P::permit(n);elapsed=65000;P::watch(n);
    check(!P::active(n),"suspend-inclusive gap holds");
  }
  rclcpp::shutdown();return failures?1:0;
}
