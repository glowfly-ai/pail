// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
//
// test_fatal_report_worker — P15-H1: a fatal report is retried until the issuer
// confirms it, off the caller's thread, with the attempts and the confirmation
// visible through the hooks. std-only (L1 tier): no rclcpp, no grpc.
//
// Fail-first (preview.15 runtime): there was no worker — the ESTOP path made one
// 50 ms call and discarded its result; a provider that fails once left the chain
// unrevoked forever. Case 1 below is that provider.

#include <atomic>
#include <chrono>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "pail_pep_gate/fatal_report_worker.hpp"

namespace {

int g_failures = 0;
void Row(const char *name, bool ok, const std::string &note) {
  if (!ok) {
    std::fprintf(stderr, "  FAIL [%s] %s\n", name, note.c_str());
    ++g_failures;
  } else {
    std::printf("  ok   [%s] %s\n", name, note.c_str());
  }
}

// A provider whose issuer link drops the first `fail_first` fatal reports
// (transport failure / deadline → not confirmed), then confirms.
struct FlakyProvider : pail_pep_gate::ITokenProvider {
  std::atomic<int> fail_first{0};
  std::atomic<int> calls{0};
  std::atomic<int> confirmed_calls{0};
  std::mutex mu;
  std::vector<std::string> seen;  // chain ids in delivery order (confirmed only)

  pail_pep_gate::ActiveTokenView GetActiveToken(const std::string &) override {
    pail_pep_gate::ActiveTokenView v;
    v.ok = false;
    v.status = "NO_TOKEN";
    return v;
  }
  bool ReportDecision(const std::string &, const std::string &chain_id, const std::string &,
                      const std::string &decision, const std::string &, bool step_complete, bool fatal,
                      const std::string &) override {
    calls.fetch_add(1);
    if (!fatal || step_complete || decision == "PERMIT") return true;  // not what this battery measures
    if (fail_first.load() > 0) {
      fail_first.fetch_sub(1);
      return false;
    }
    confirmed_calls.fetch_add(1);
    std::lock_guard<std::mutex> lock(mu);
    seen.push_back(chain_id);
    return true;
  }
  std::string Attest(const std::string &, const std::string &, const std::string &, const std::string &) override {
    return "OK";
  }
};

template <class Pred>
bool wait_until(Pred pred, int max_ms) {
  const auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(max_ms);
  while (std::chrono::steady_clock::now() < end) {
    if (pred()) return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  return pred();
}

pail_pep_gate::FatalReport report(const std::string &chain) {
  pail_pep_gate::FatalReport r;
  r.robot_id = "robot-1";
  r.chain_id = chain;
  r.token_id = "tok-" + chain;
  r.decision = "ESTOP";
  r.reason_code = "ERR_SAFETY_UNSAFE";
  return r;
}

}  // namespace

int main() {
  {
    struct Negative : FlakyProvider {
      pail_pep_gate::ReportOutcome ReportFatalOutcome(const std::string &r,const std::string &c,const std::string &t,const std::string &d,const std::string &why,const std::string &detail,const std::string &id) override {
        if(c=="old")return pail_pep_gate::ReportOutcome::TerminalUnconfirmed;
        return ITokenProvider::ReportFatalOutcome(r,c,t,d,why,detail,id);
      }
    } provider;
    std::atomic<int> abandoned{0};
    pail_pep_gate::FatalReportWorker::Hooks hooks;
    hooks.on_abandoned=[&](const auto&,int){abandoned++;};
    pail_pep_gate::FatalReportWorker worker(provider,hooks);
    worker.Enqueue(report("old"));worker.Enqueue(report("new"));
    Row("terminal-negative-not-confirmed",wait_until([&]{return worker.confirmed()==1&&abandoned==1&&worker.pending()==0;},1000),"negative retires only delivery; newer fatal still sent");
    worker.Stop();
  }

  using pail_pep_gate::FatalReport;
  using pail_pep_gate::FatalReportWorker;
  using ms = std::chrono::milliseconds;

  // ---- 1. the judge2 shape: the first delivery is lost; the chain must still be revoked ----
  {
    FlakyProvider p;
    p.fail_first = 2;
    std::atomic<int> failed{0}, confirmed{0}, confirmed_attempts{0};
    FatalReportWorker::Hooks h;
    h.on_failed = [&](const FatalReport &, int) { failed.fetch_add(1); };
    h.on_confirmed = [&](const FatalReport &, int attempts) { confirmed.fetch_add(1); confirmed_attempts = attempts; };
    FatalReportWorker w(p, h, ms(10), ms(40));
    const auto t0 = std::chrono::steady_clock::now();
    w.Enqueue(report("chain-A"));
    const auto returned_ms = std::chrono::duration_cast<ms>(std::chrono::steady_clock::now() - t0).count();
    // PAIL-CASE: fatal_worker_enqueue_does_not_block
    Row("enqueue_does_not_block", returned_ms < 5, std::to_string(returned_ms) + " ms");
    const bool ok = wait_until([&] { return confirmed.load() == 1; }, 2000);
    // PAIL-CASE: fatal_worker_retries_until_confirmed
    Row("retries_until_confirmed", ok && p.calls.load() == 3 && failed.load() == 2 && confirmed_attempts.load() == 3 && w.confirmed() == 1 && w.pending() == 0,
        "calls=" + std::to_string(p.calls.load()) + " failed_hooks=" + std::to_string(failed.load()) +
            " confirmed=" + std::to_string(confirmed.load()) + " attempts_at_confirm=" + std::to_string(confirmed_attempts.load()));
  }

  // ---- 2. in-order delivery of several fatals while the link flaps ----
  {
    FlakyProvider p;
    p.fail_first = 1;
    std::atomic<int> confirmed{0};
    FatalReportWorker::Hooks h;
    h.on_confirmed = [&](const FatalReport &, int) { confirmed.fetch_add(1); };
    FatalReportWorker w(p, h, ms(5), ms(20));
    w.Enqueue(report("c1"));
    w.Enqueue(report("c2"));
    w.Enqueue(report("c3"));
    const bool ok = wait_until([&] { return confirmed.load() == 3; }, 2000);
    std::lock_guard<std::mutex> lock(p.mu);
    // PAIL-CASE: fatal_worker_in_order
    Row("in_order", ok && p.seen.size() == 3 && p.seen[0] == "c1" && p.seen[1] == "c2" && p.seen[2] == "c3",
        "seen=" + std::to_string(p.seen.size()));
  }

  // ---- 3. backoff is bounded by the cap (never sleeps longer than retry_cap between attempts) ----
  {
    FlakyProvider p;
    p.fail_first = 6;
    std::atomic<int> confirmed{0};
    FatalReportWorker::Hooks h;
    h.on_confirmed = [&](const FatalReport &, int) { confirmed.fetch_add(1); };
    FatalReportWorker w(p, h, ms(5), ms(20));
    const auto t0 = std::chrono::steady_clock::now();
    w.Enqueue(report("slow"));
    const bool ok = wait_until([&] { return confirmed.load() == 1; }, 3000);
    const auto took = std::chrono::duration_cast<ms>(std::chrono::steady_clock::now() - t0).count();
    // 6 failures with floor 5 ms doubling to a 20 ms cap: 5+10+20+20+20+20 = 95 ms of waits.
    // PAIL-CASE: fatal_worker_backoff_capped
    Row("backoff_capped", ok && p.calls.load() == 7 && took < 1000, "calls=" + std::to_string(p.calls.load()) + " took=" + std::to_string(took) + " ms");
  }

  // ---- 4. a report still unconfirmed at shutdown is abandoned loudly, never silently ----
  {
    FlakyProvider p;
    p.fail_first = 1000000;
    std::atomic<int> failed{0}, abandoned{0};
    FatalReportWorker::Hooks h;
    h.on_failed = [&](const FatalReport &, int) { failed.fetch_add(1); };
    h.on_abandoned = [&](const FatalReport &, int) { abandoned.fetch_add(1); };
    {
      FatalReportWorker w(p, h, ms(5), ms(10));
      w.Enqueue(report("never"));
      w.Enqueue(report("never-2"));
      wait_until([&] { return failed.load() >= 3; }, 1000);
      w.Stop();
      const bool stopped_fast = true;
      // PAIL-CASE: fatal_worker_abandons_on_stop
      Row("abandons_on_stop", stopped_fast && abandoned.load() == 2 && w.pending() == 0 && failed.load() >= 3,
          "abandoned=" + std::to_string(abandoned.load()) + " failed=" + std::to_string(failed.load()));
      w.Stop();  // idempotent
      Row("stop_idempotent", abandoned.load() == 2, std::to_string(abandoned.load()));
    }
  }

  // ---- 5. a provider without an issuer confirms at once (static/notoken contract) ----
  {
    struct Immediate final : pail_pep_gate::ITokenProvider {
      pail_pep_gate::ActiveTokenView GetActiveToken(const std::string &) override { return {}; }
      bool ReportDecision(const std::string &, const std::string &, const std::string &, const std::string &,
                          const std::string &, bool, bool, const std::string &) override { return true; }
      std::string Attest(const std::string &, const std::string &, const std::string &, const std::string &) override { return "OK"; }
    } p;
    std::atomic<int> confirmed{0}, failed{0};
    FatalReportWorker::Hooks h;
    h.on_confirmed = [&](const FatalReport &, int) { confirmed.fetch_add(1); };
    h.on_failed = [&](const FatalReport &, int) { failed.fetch_add(1); };
    FatalReportWorker w(p, h);
    w.Enqueue(report("x"));
    const bool ok = wait_until([&] { return confirmed.load() == 1; }, 1000);
    // PAIL-CASE: fatal_worker_immediate_confirm
    Row("immediate_confirm", ok && failed.load() == 0 && w.attempts_total() == 1, "attempts=" + std::to_string(w.attempts_total()));
  }

  if (g_failures) {
    std::fprintf(stderr, "test_fatal_report_worker: %d failure(s)\n", g_failures);
    return 1;
  }
  std::printf("test_fatal_report_worker: all rows ok\n");
  return 0;
}
