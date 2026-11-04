// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
#include "pail_pep_gate/clock_warning_summary.hpp"
#include <cassert>
#include <cstdio>
int main() {
  pail_pep_gate::ClockWarningSummary s("step_timer");
  size_t emitted=0;
  for(int i=0;i<90;++i) {
    auto lines=s.Observe("drift_ms="+std::to_string(600+i)+" cause=wall_drift path=step_timer", i*34);
    emitted+=lines.size();
    if(i==0) {assert(lines.size()==1);assert(lines[0].find("event=start")!=std::string::npos);}
  }
  assert(emitted==3); // 90 changing numeric details, three WARN lines, not 90
  auto end=s.End();assert(end.find("total_count=90")!=std::string::npos);
  assert(end.find("interval_count=29")!=std::string::npos);assert(s.End().empty());
  assert(s.Observe("cause=wall_drift",4000).size()==1);
  auto changed=s.Observe("cause=elapsed_unavailable",4001);
  assert(changed.size()==2 && changed[0].find("event=end")!=std::string::npos);
  assert(changed[1].find("event=start")!=std::string::npos);
  assert(s.Observe("cause=elapsed_unavailable",4002).empty());
  auto reversed=s.Observe("cause=elapsed_unavailable",3999);assert(reversed.size()==1);
  assert(s.End().find("total_count=3")!=std::string::npos);
  std::puts("PASS clock warning first/changed/summary/end, counters and elapsed clock reversal");
}
