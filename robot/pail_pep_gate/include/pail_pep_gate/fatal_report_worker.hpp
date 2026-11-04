// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

#pragma once

// P15-H1 (preview.15 evaluation, TB3 judge2 scene 8, 2026-10-16).
//
// A fatal report (ESTOP, fatal BLOCK) is the message that revokes the robot's
// current chain at the issuer. The node used to send it on the callback thread
// with the 50 ms command-path deadline and discard the result: one lost RPC and
// the issuer kept the chain active, served the same token when safety returned
// to OK, and the robot resumed its interrupted plan without an operator.
//
// This worker owns fatal reports. The node enqueues them (after it has already
// published the stop and latched the chain in its session) and returns at once;
// the worker thread delivers them in order, under the provider's fatal deadline,
// and retries with bounded backoff until the provider reports confirmation.
// Every failed attempt and the eventual confirmation are handed to the node's
// hooks so they are visible in the log ("revocation_pending" / "revocation
// confirmed"); a report still unconfirmed at shutdown is handed to on_abandoned.
//
// std-only (no rclcpp, no grpc): pinned by test_fatal_report_worker.

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <utility>

#include "pail_gate/token_provider.hpp"
#include "pail_gate/report_identity.hpp"

namespace pail_pep_gate {

struct FatalReport {
  std::string robot_id;
  std::string chain_id;
  std::string token_id;
  std::string decision;     // ESTOP | BLOCK
  std::string reason_code;  // ERR_SAFETY_UNSAFE, ERR_WORLD_CHANGED, ...
  std::string detail;
  std::string report_id;
};

class FatalReportWorker {
 public:
  struct Hooks {
    // Called after each failed attempt (attempts = number made so far, >= 1).
    std::function<void(const FatalReport &, int attempts)> on_failed;
    // Called once the provider confirmed the report (attempts = number made).
    std::function<void(const FatalReport &, int attempts)> on_confirmed;
    // Called from Stop() for every report still unconfirmed.
    std::function<void(const FatalReport &, int attempts)> on_abandoned;
  };

  FatalReportWorker(ITokenProvider &provider, Hooks hooks,
                    std::chrono::milliseconds retry_floor = std::chrono::milliseconds(200),
                    std::chrono::milliseconds retry_cap = std::chrono::milliseconds(2000))
      : provider_(provider), hooks_(std::move(hooks)), retry_floor_(retry_floor), retry_cap_(retry_cap) {
    thread_ = std::thread([this] { Run(); });
  }

  ~FatalReportWorker() { Stop(); }

  FatalReportWorker(const FatalReportWorker &) = delete;
  FatalReportWorker &operator=(const FatalReportWorker &) = delete;

  // Never blocks on the network: the report is queued and the caller returns.
  void Enqueue(FatalReport report) {

    {
      std::lock_guard<std::mutex> lock(mu_);
      if(report.report_id.empty())report.report_id=instance_id_+"-"+std::to_string(++report_seq_);
      queue_.push_back(std::move(report));
    }
    cv_.notify_all();
  }

  // Joins the thread. Idempotent. Reports still unconfirmed are reported through
  // on_abandoned, in queue order; nothing is retried after this returns.
  void Stop() {
    {
      std::lock_guard<std::mutex> lock(mu_);
      if (stopping_) {
        return;
      }
      stopping_ = true;
    }
    cv_.notify_all();
    if (thread_.joinable()) thread_.join();
    std::deque<FatalReport> left;
    int attempts_front = 0;
    {
      std::lock_guard<std::mutex> lock(mu_);
      left.swap(queue_);
      attempts_front = attempts_;
    }
    bool first = true;
    for (const auto &r : left) {
      if (hooks_.on_abandoned) hooks_.on_abandoned(r, first ? attempts_front : 0);
      first = false;
    }
  }

  // Reports queued and not yet confirmed (the one in flight included).
  size_t pending() const {
    std::lock_guard<std::mutex> lock(mu_);
    return queue_.size();
  }
  long confirmed() const { return confirmed_.load(); }
  long attempts_total() const { return attempts_total_.load(); }

 private:
  const std::string instance_id_{NewReportIdentity()};
  uint64_t report_seq_{0};
  void Run() {
    std::chrono::milliseconds backoff(0);
    for (;;) {
      FatalReport current;
      {
        std::unique_lock<std::mutex> lock(mu_);
        cv_.wait(lock, [this] { return stopping_ || !queue_.empty(); });
        if (stopping_) return;
        current = queue_.front();
      }
      const auto outcome = provider_.ReportFatalOutcome(current.robot_id, current.chain_id, current.token_id,
                                               current.decision, current.reason_code,
                                               current.detail,current.report_id);
      attempts_total_.fetch_add(1);
      int attempts = 0;
      {
        std::lock_guard<std::mutex> lock(mu_);
        attempts = ++attempts_;
      }
      if (outcome != ReportOutcome::Retry) {
        {
          std::lock_guard<std::mutex> lock(mu_);
          if (!queue_.empty()) queue_.pop_front();
          attempts_ = 0;
        }
        if(outcome==ReportOutcome::Confirmed){
          confirmed_.fetch_add(1);
          if(hooks_.on_confirmed)hooks_.on_confirmed(current,attempts);
        }else if(hooks_.on_abandoned)hooks_.on_abandoned(current,attempts);
        // A durable terminal negative retires delivery, NOT the local latch.
        // Never count it as confirmed or prevent newer revocations from sending.
        backoff = std::chrono::milliseconds(0);
        continue;
      }
      if (hooks_.on_failed) hooks_.on_failed(current, attempts);
      backoff = backoff.count() == 0 ? retry_floor_ : std::min(backoff * 2, retry_cap_);
      std::unique_lock<std::mutex> lock(mu_);
      cv_.wait_for(lock, backoff, [this] { return stopping_; });
      if (stopping_) return;
    }
  }

  ITokenProvider &provider_;
  Hooks hooks_;
  const std::chrono::milliseconds retry_floor_;
  const std::chrono::milliseconds retry_cap_;

  mutable std::mutex mu_;
  std::condition_variable cv_;
  std::deque<FatalReport> queue_;
  int attempts_{0};  // attempts made on the report at the front of the queue
  bool stopping_{false};
  std::atomic<long> confirmed_{0};
  std::atomic<long> attempts_total_{0};
  std::thread thread_;
};

}  // namespace pail_pep_gate
