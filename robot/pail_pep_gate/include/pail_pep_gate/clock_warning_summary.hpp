// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
#pragma once
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace pail_pep_gate {
// Presentation only: never gates a decision, topic publication, or audit report.
// One bounded stream per callback path; elapsed time is supplied from steady_clock.
class ClockWarningSummary {
 public:
  explicit ClockWarningSummary(std::string path) : path_(std::move(path)) {}
  std::vector<std::string> Observe(const std::string &detail, int64_t now_ms) {
    std::vector<std::string> lines;
    const auto at = detail.find("cause=");
    const auto end = at == std::string::npos ? at : detail.find(' ', at);
    const std::string cause = at == std::string::npos ? "cause=unspecified" : detail.substr(at, end-at);
    if (active_ && cause != cause_) lines.push_back(End());
    const bool first = !active_;
    if (first) { active_=true; cause_=cause; total_=pending_=0; }
    detail_=detail; ++total_; ++pending_;
    if (first || now_ms < last_ms_ || now_ms-last_ms_ >= 1000) {
      lines.push_back(Line(first ? "start" : "summary"));
      pending_=0; last_ms_=now_ms;
    }
    return lines;
  }
  std::string End() {
    if (!active_) return {};
    std::string result=Line("end");
    active_=false; total_=pending_=0;
    return result;  // end of this warning stream, NOT proof of trusted time recovery
  }
 private:
  std::string Line(const char *event) const {
    return "clock_warning event=" + std::string(event) + " path=" + path_ +
        " interval_count=" + std::to_string(pending_) + " total_count=" + std::to_string(total_) +
        " last_detail={" + detail_ + "}";
  }
  std::string path_,cause_,detail_;
  bool active_=false;
  uint64_t total_=0,pending_=0;
  int64_t last_ms_=0;
};
}  // namespace pail_pep_gate
