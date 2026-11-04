#include "pail_deploy_guard/core_comm_io.hpp"
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// pail_motion_bridge (M4, LLD-v2 §2.3).
//
// The last fail-closed barrier before the drive stack. Forwards /safe_cmd_vel
// to /drive_cmd_vel ONLY while the permit heartbeat (/pail/permit) is alive.
// Deadline miss, heartbeat silence (2x deadline), or a non-monotonic
// permit_seq (replay suspicion) => publish one zero-twist, then HOLD.
//
// Deliberately kept small and verifiable: single source file, no token or
// authorization/signature logic. Diagnostic fingerprints use SHA-256 only. The PEP gate decides; this node only enforces "absence = stop".

#include <algorithm>
#include <chrono>
#include <string>
#include <cmath>
#include <functional>
#include "rmw/rmw.h"
#include "pail_deploy_guard/robotops_status.hpp"

#include "rclcpp/rclcpp.hpp"
#include "geometry_msgs/msg/twist.hpp"
#include "pail_msgs/msg/bridge_state.hpp"
#include "pail_msgs/msg/permit.hpp"

#include "pail_deploy_guard/deploy_guard.hpp"
// DC-8 : the silence watchdog is half of the deadman and a
// judgment — it must read the same clock as the gate. Under use_sim_time a
// frozen /clock made the node-time permit age stop growing: the watchdog
// half of the deadman silently vanished while the DDS deadline half survived
// (redundancy loss, no log). Only this one header is imported; no token or
// crypto logic crosses the package boundary.
#include "pail_gate/wall_clock.hpp"

using namespace std::chrono_literals;

class MotionBridgeNode final : public rclcpp::Node {
public:
  explicit MotionBridgeNode(std::function<int64_t()> elapsed_clock = pail_pep_gate::ElapsedNowMs)
      : Node("motion_bridge_node"), elapsed_clock_(std::move(elapsed_clock)) {
    permit_deadline_ms_ = declare_parameter<int>("permit_deadline_ms", 100);

    if (permit_deadline_ms_ <= 0) {
      throw pail_deploy_guard::ConfigRefused("permit_deadline_ms must be positive");
    }
    // Retain RELIABLE compatibility with vendor subscribers, but never retry
    // an old velocity indefinitely. KEEP_LAST(1) alone does not expire a
    // sample already in the transport; lifespan is essential on BOTH hops.
    rclcpp::QoS drive_qos(rclcpp::KeepLast(1));
    drive_qos.reliable().durability_volatile();
    drive_qos.lifespan(std::chrono::milliseconds(permit_deadline_ms_));
    drive_pub_ = create_publisher<geometry_msgs::msg::Twist>("/drive_cmd_vel", drive_qos);
    bridge_state_pub_ = create_publisher<pail_msgs::msg::BridgeState>("/pail/bridge_state", 10);

    rclcpp::QoS permit_qos(rclcpp::KeepLast(1));
    permit_qos.best_effort();
    permit_qos.deadline(std::chrono::milliseconds(permit_deadline_ms_));
    permit_qos.lifespan(std::chrono::milliseconds(permit_deadline_ms_));

    rclcpp::SubscriptionOptions permit_opts;
    permit_opts.event_callbacks.deadline_callback =
        [this](rclcpp::QOSDeadlineRequestedInfo & /*info*/) { to_hold("deadline missed"); };

    permit_sub_ = create_subscription<pail_msgs::msg::Permit>(
        "/pail/permit", permit_qos,
        std::bind(&MotionBridgeNode::on_permit, this, std::placeholders::_1), permit_opts);

    safe_sub_ = create_subscription<geometry_msgs::msg::Twist>(
        "/safe_cmd_vel", 10,
        std::bind(&MotionBridgeNode::on_safe_cmd_vel, this, std::placeholders::_1));

    // Silence watchdog: independent of DDS deadline events so a paused (hung)
    // PEP is also caught within the observation window of 2x deadline.
    watchdog_timer_ = create_wall_timer(
        std::chrono::milliseconds(std::max(1, permit_deadline_ms_ / 4)),
        std::bind(&MotionBridgeNode::on_watchdog, this));

    state_timer_ = create_wall_timer(1s, [this]() { publish_state(); });
    const auto socket=pail_robotops::Env("PAIL_ROBOTOPS_STATUS_SOCKET");
    if(!socket.empty()) {
      try {
        const auto robot=pail_robotops::Env("PAIL_ROBOT_ID");
        status_server_=std::make_unique<pail_robotops::StatusServer>(socket,pail_robotops::Env("PAIL_OPS_DEPLOYMENT_ID"),robot,"motion_bridge");
        size_t domain=0;const auto rc=rcl_node_get_domain_id(get_node_base_interface()->get_rcl_node_handle(),&domain);
        status_settings_={{"robot_id",robot},{"permit_deadline_ms",std::to_string(permit_deadline_ms_)},{"deadman_window_ms",std::to_string(2*permit_deadline_ms_)},{"rmw",rmw_get_implementation_identifier()},{"domain_id",rc==RCL_RET_OK?std::to_string(domain):"unknown"},{"node_name",get_fully_qualified_name()}};
        status_settings_json_=pail_robotops::JSON(status_settings_);
        status_generation_=pail_robotops::Hash("pail.robotops.component-settings/v1\n"+status_settings_json_);
        status_timer_=create_wall_timer(20ms,[this](){status_server_->Poll([this](){return status_snapshot();});});
      } catch(const std::exception&e) {std::fprintf(stderr,"RO_STATUS: bridge local status setup refused: %s\n",e.what());throw pail_deploy_guard::ConfigRefused("RO_STATUS: bridge local status setup refused");}
    }


    RCLCPP_INFO(get_logger(), "motion bridge up: HOLD (deadline=%dms, window=%dms)",
                permit_deadline_ms_, 2 * permit_deadline_ms_);
  }

private:
#ifdef PAIL_MOTION_BRIDGE_UNDER_TEST
  friend struct BridgeClockTestPeer;
#endif
  void publish_state() {
    pail_msgs::msg::BridgeState msg;
    msg.stamp = now();
    msg.state = forwarding_ ? "FORWARDING" : "HOLD";
    // D §7.6 (F-CPP-7): report the window the watchdog enforces (on_watchdog
    // compares against this same expression), not the parameter — the seal
    // must carry what is held to, and only this node knows that number.
    msg.deadman_window_ms = 2 * permit_deadline_ms_;
    bridge_state_pub_->publish(msg);
    RCLCPP_INFO(get_logger(),
        "PAIL_BRIDGE_IO safe_publishers=%zu permit_publishers=%zu drive_subscribers=%zu forwarding=%d safe_samples=%llu output_samples=%llu",
        safe_sub_->get_publisher_count(), permit_sub_->get_publisher_count(),
        drive_pub_->get_subscription_count(), forwarding_,
        static_cast<unsigned long long>(safe_samples_), static_cast<unsigned long long>(output_seq_));
  }

  void to_hold(const char *why) {
    if (!forwarding_) return;
    forwarding_ = false;
    // Zero-twist once, then silence (the drive stack's own deadman may apply).
    geometry_msgs::msg::Twist zero;
    drive_pub_->publish(zero);
    note_output(zero);
    publish_state();
    const bool permit_was_valid = last_permit_valid_;
    const int64_t since_ms = last_permit_valid_
        ? permit_age_ms() : -1;
    last_permit_valid_ = false;  // require a fresh permit stream to resume
    RCLCPP_WARN(get_logger(), "HOLD (%s): zero-twist published, clock=elapsed age_ms=%ld (-1=unavailable/reversed)",
                why, static_cast<long>(since_ms));
    // P37-L2 diagnostics: one line per transition that names what was measured. The permit_seq at the hold is
    // remembered so the resume can count the permits this node did not observe in the gap — only when the
    // permit stream is the same forward generation (on_permit decides).
    const int64_t elapsed = elapsed_clock_();
    ++hold_count_;
    last_hold_reason_ = why;
    hold_started_elapsed_ms_ = elapsed;
    hold_permit_seq_ = last_permit_seq_;
    hold_seq_known_ = permit_was_valid;
    const int64_t forwarded_ms = (forwarding_since_elapsed_ms_ >= 0 && elapsed >= forwarding_since_elapsed_ms_)
        ? elapsed - forwarding_since_elapsed_ms_ : -1;
    forwarding_since_elapsed_ms_ = -1;
    if (transition_event_allowed(elapsed)) {
      RCLCPP_WARN(get_logger(),
          "PAIL_BRIDGE_HOLD reason=%s permit_seq=%u permit_age_ms=%ld clock=elapsed forwarded_ms=%ld nonzero_publishes=%llu",
          why, last_permit_seq_, static_cast<long>(since_ms), static_cast<long>(forwarded_ms),
          static_cast<unsigned long long>(nonzero_publish_calls_));
    }
  }

  // Transition lines are capped at two per elapsed second; a flapping permit stream is then summarised once per
  // second instead of flooding the log (the counters keep every transition).
  bool transition_event_allowed(int64_t elapsed) {
    const int64_t second = elapsed >= 0 ? elapsed / 1000 : -1;
    if (second != transition_second_) {
      if (transitions_suppressed_ > 0) {
        RCLCPP_WARN(get_logger(), "PAIL_BRIDGE_TRANSITIONS suppressed=%d clock=elapsed second=%ld",
                    transitions_suppressed_, static_cast<long>(transition_second_));
      }
      transition_second_ = second;
      transitions_this_second_ = 0;
      transitions_suppressed_ = 0;
    }
    if (++transitions_this_second_ > 2) {
      ++transitions_suppressed_;
      ++transitions_suppressed_total_;
      return false;
    }
    return true;
  }

  void on_permit(const pail_msgs::msg::Permit::SharedPtr msg) {
    if (last_permit_valid_ && msg->permit_seq <= last_permit_seq_) {
      to_hold("permit_seq non-monotonic (replay suspicion)");
      return;
    }
    last_permit_seq_ = msg->permit_seq;
    last_permit_mono_ns_=pail_robotops::MonoNS();
    const int64_t elapsed = elapsed_clock_();
    if (elapsed < 0 || (last_elapsed_ms_ >= 0 && elapsed < last_elapsed_ms_)) {
      to_hold("elapsed clock unavailable or reversed");
      return;
    }
    last_elapsed_ms_ = elapsed;
    last_permit_elapsed_ms_ = elapsed;
    last_permit_valid_ = true;
    if (!forwarding_) {
      forwarding_ = true;
      publish_state();
      RCLCPP_INFO(get_logger(), "FORWARDING (permit_seq=%u)", msg->permit_seq);
      // P37-L2 diagnostics: the gap and, when the stream is the same forward generation, how many permits this
      // node did not observe while holding (new > old: new-old-1). Equal, lower or wrapped sequence numbers are a
      // restart or regression — not a count; an unknown sequence at the hold (first permit, invalid stream) is
      // unavailable. Only counted values accumulate.
      const int64_t gap_ms = (hold_started_elapsed_ms_ >= 0 && elapsed >= hold_started_elapsed_ms_)
          ? elapsed - hold_started_elapsed_ms_ : -1;
      std::string unobserved;
      if (!hold_seq_known_) {
        last_gap_kind_ = "unavailable";
        unobserved = last_gap_kind_;
      } else if (msg->permit_seq > hold_permit_seq_) {
        last_gap_kind_ = "counted";
        const uint64_t n = static_cast<uint64_t>(msg->permit_seq - hold_permit_seq_) - 1;
        permits_unobserved_total_ += n;
        unobserved = std::to_string(n);
      } else {
        last_gap_kind_ = "reset_or_regression";
        unobserved = last_gap_kind_;
      }
      last_gap_ms_ = gap_ms;
      forwarding_since_elapsed_ms_ = elapsed;
      if (transition_event_allowed(elapsed)) {
        RCLCPP_INFO(get_logger(), "PAIL_BRIDGE_RESUME gap_ms=%ld clock=elapsed permits_unobserved_in_gap=%s permit_seq=%u",
                    static_cast<long>(gap_ms), unobserved.c_str(), msg->permit_seq);
      }
    }
  }

  void on_watchdog() {
    if (!forwarding_ || !last_permit_valid_) return;
    // Duration uses suspend-inclusive elapsed time, never the adjustable wall clock — node time freezes with /clock.
    const int64_t age_ms = permit_age_ms();
    if (age_ms < 0 || age_ms > 2 * permit_deadline_ms_) {
      to_hold("permit silence");
    }
  }

  void on_safe_cmd_vel(const geometry_msgs::msg::Twist::SharedPtr msg) {
    ++safe_samples_;
    if (!forwarding_) return;  // absence of permit = stop
    // Check again at the forwarding door: a queued timer must not let stale
    // authority through after a stall/suspend.
    const int64_t age = permit_age_ms();
    if (age < 0 || age > 2 * permit_deadline_ms_) {
      to_hold("permit silence or invalid elapsed clock");
      return;
    }
    drive_pub_->publish(*msg);
    note_output(*msg);
  }


  void note_output(const geometry_msgs::msg::Twist&v){
    ++output_seq_;last_output_mono_ns_=pail_robotops::MonoNS();
    const bool finite=std::isfinite(v.linear.x)&&std::isfinite(v.linear.y)&&std::isfinite(v.linear.z)&&std::isfinite(v.angular.x)&&std::isfinite(v.angular.y)&&std::isfinite(v.angular.z);
    last_output_=!finite?"NONFINITE":(v.linear.x==0&&v.linear.y==0&&v.linear.z==0&&v.angular.x==0&&v.angular.y==0&&v.angular.z==0?"ZERO":"NONZERO");
    // output_seq_ counts every publish call (the hold's zero-twist included); this counts the nonzero ones. Both
    // are publish calls — delivery to the driver and physical execution are not observed here (P37-L2, RV07).
    if(last_output_=="NONZERO")++nonzero_publish_calls_;
  }
  pail_robotops::Fields status_snapshot()const{
    const auto io=pail_robotops::JSON({
      {"contract_version","core-comm-ready/1"},{"scope","IO_TOPOLOGY_AND_REQUIRED_INPUTS"},
      {"physical_execution","NOT_OBSERVED"},
      {"safe",pail_robotops::Endpoints(*this,"/safe_cmd_vel",true,safe_sub_->get_actual_qos())},
      {"permit",pail_robotops::Endpoints(*this,"/pail/permit",true,permit_sub_->get_actual_qos())},
      {"drive",pail_robotops::Endpoints(*this,"/drive_cmd_vel",false,drive_pub_->get_actual_qos())}});
    pail_robotops::Fields result = {{"config_generation",status_generation_},{"resolved_settings_json",status_settings_json_},{"state",forwarding_?"FORWARDING":"HOLD"},{"permit_seen",last_permit_mono_ns_>0?"true":"false"},{"permit_valid",last_permit_valid_?"true":"false"},{"permit_seq",std::to_string(last_permit_seq_)},{"last_permit_mono_ns",std::to_string(last_permit_mono_ns_)},{"output_seq",std::to_string(output_seq_)},{"last_output_mono_ns",std::to_string(last_output_mono_ns_)},{"last_output",last_output_},{"output_basis","ROS_publish_returned; driver/physical_delivery_NOT_observed"},
      {"nonzero_publish_calls",std::to_string(nonzero_publish_calls_)},{"hold_count",std::to_string(hold_count_)},{"last_hold_reason",last_hold_reason_},
      {"last_gap_ms",std::to_string(last_gap_ms_)},{"last_gap_kind",last_gap_kind_},{"permits_unobserved_total",std::to_string(permits_unobserved_total_)},
      {"transitions_suppressed_total",std::to_string(transitions_suppressed_total_)},{"clock_basis","elapsed_suspend_inclusive"}};
 result["io_snapshot_json"]=io;return result;
  }
  std::unique_ptr<pail_robotops::StatusServer> status_server_;
  rclcpp::TimerBase::SharedPtr status_timer_;
  pail_robotops::Fields status_settings_;
  std::string status_settings_json_,status_generation_,last_output_{"NONE"};
  uint64_t output_seq_{0};int64_t last_output_mono_ns_{0},last_permit_mono_ns_{0};
  // P37-L2 diagnostics (preview.38): named measurement points, never delivery claims.
  uint64_t nonzero_publish_calls_{0}, hold_count_{0}, permits_unobserved_total_{0}, transitions_suppressed_total_{0};
  std::string last_hold_reason_{"NONE"}, last_gap_kind_{"unavailable"};
  int64_t last_gap_ms_{-1}, hold_started_elapsed_ms_{-1}, forwarding_since_elapsed_ms_{-1};
  uint32_t hold_permit_seq_{0};
  bool hold_seq_known_{false};
  int64_t transition_second_{-2};
  int transitions_this_second_{0}, transitions_suppressed_{0};
  int permit_deadline_ms_{100};
  bool forwarding_{false};
  bool last_permit_valid_{false};
  uint32_t last_permit_seq_{0};
  int64_t permit_age_ms() {
    const int64_t t = elapsed_clock_();
    if (t < 0 || t < last_permit_elapsed_ms_ || (last_elapsed_ms_ >= 0 && t < last_elapsed_ms_)) return -1;
    last_elapsed_ms_ = t;
    return t - last_permit_elapsed_ms_;
  }
  std::function<int64_t()> elapsed_clock_;
  int64_t last_permit_elapsed_ms_{0}, last_elapsed_ms_{-1};

  rclcpp::Subscription<pail_msgs::msg::Permit>::SharedPtr permit_sub_;
  rclcpp::Subscription<geometry_msgs::msg::Twist>::SharedPtr safe_sub_;
  rclcpp::Publisher<geometry_msgs::msg::Twist>::SharedPtr drive_pub_;
  rclcpp::Publisher<pail_msgs::msg::BridgeState>::SharedPtr bridge_state_pub_;
  uint64_t safe_samples_{0};
  rclcpp::TimerBase::SharedPtr watchdog_timer_;
  rclcpp::TimerBase::SharedPtr state_timer_;
};

// TB-7: the deadman wiring test compiles this translation unit with its own main().
#ifndef PAIL_MOTION_BRIDGE_UNDER_TEST
int main(int argc, char **argv) {
  // SD3 (§3): the shell preflight is skipped whenever the entrypoint is replaced,
  // so S0~S3 are decided here, before any ROS participant is created.
  pail_deploy_guard::EnforceDeployGuard("motion_bridge", argc, argv);
  rclcpp::init(argc, argv);
  // See pep_gate_node.cpp: a constructor-time configuration refusal exits 78 here.
  try {
    rclcpp::spin(std::make_shared<MotionBridgeNode>());
  } catch (const pail_deploy_guard::ConfigRefused &e) {
    std::fprintf(stderr, "PAIL STARTUP REFUSED: %s [component=motion_bridge]\n", e.what());
    rclcpp::shutdown();
    return pail_deploy_guard::kExitConfig;
  }
  rclcpp::shutdown();
  return 0;
}
#endif  // PAIL_MOTION_BRIDGE_UNDER_TEST
