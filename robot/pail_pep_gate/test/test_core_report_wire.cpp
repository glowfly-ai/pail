// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
#include "token_service.pb.h"
#include "../src/grpc/core_report.hpp"
#include <cstdio>
#include <limits>
int main(){
 const char* expected[]={"cc4b2936c795da8273764c0626e705be47ee6a8960a0c33efc21197703183a32","59eabb954480f7c7dc1165da7b332b8291a7537465cfaf35a448be14e249be33"};
 for(int i=0;i<2;i++){
  pail::token::v1::ReportDecisionRequest r;r.set_robot_id("robot-1");r.set_chain_id("chain-1");r.set_token_id("token-1");r.set_decision(pail::token::v1::PERMIT);r.set_reason_code("OK");r.set_step_complete(true);r.set_detail("complete:timeout");r.set_evidence_provenance("enforced");r.set_effective_mode("enforce");r.set_report_id("event-1");r.set_receipt_contract_version(1);
  if(i){auto*e=r.mutable_evidence();e->set_source("camera");e->set_object_id("box-12");e->set_confidence(.75f);e->set_unix_ms(1234);}
  const auto digest=pail_core_comm::Digest(r);char hex[65];sodium_bin2hex(hex,sizeof(hex),reinterpret_cast<const unsigned char*>(digest.data()),digest.size());
  if(std::string(hex)!=expected[i]){std::fprintf(stderr,"golden mismatch: %s\n",hex);return 1;}
  r.mutable_evidence()->set_confidence(std::numeric_limits<float>::quiet_NaN());
  bool rejected=false;try{pail_core_comm::Digest(r);}catch(const std::exception&){rejected=true;}
  if(!rejected)return 2;
 }
 std::puts("core-comm C++/Go/Python/Rust report vectors match");return 0;
}
