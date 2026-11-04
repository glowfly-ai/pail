# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Authorization receipt correlation; not a robot-execution protocol."""
import hashlib
import os
from core_report_wire import _canonical

# One communication contract (0.2.0-preview.40). PAIL_CORE_COMM_CONTRACT used to select `legacy` or `v1`; the setting is
# gone and the variable being present at all — any value, an empty one included (0.2.0-preview.41, P40-L2) — refuses by
# name. The same message lives in the Go library (internal/corecomm), the gate (core_contract.hpp), the Microduck
# adapter and the hardware scripts; spec/CORE_COMM.md is the source.
CONTRACT_SETTING_REMOVED='CORE_COMM_CONTRACT_SETTING_REMOVED: PAIL_CORE_COMM_CONTRACT has no meaning (there is one communication contract); unset it'

def check_no_contract_setting(value=None,present=None):
 """True when the variable is absent. A present variable — any value, including '' — raises with the one message.

 With no arguments the process environment is read ('PAIL_CORE_COMM_CONTRACT' in os.environ). A string `value` means
 "the variable is present with this value" (so '' refuses); `present=False` names an absent variable explicitly."""
 if present is None:present=('PAIL_CORE_COMM_CONTRACT' in os.environ) if value is None else True
 if present:raise ValueError(CONTRACT_SETTING_REMOVED)
 return True

def operation_digest(request):
 name=request.DESCRIPTOR.name
 if name=='SubmitActionPlanRequest':include,exclude={1,2,3},{4}
 elif name=='CancelPlanRequest':include,exclude={1},{2}
 else:raise ValueError('OPERATION_TYPE_UNSUPPORTED')
 return hashlib.sha256(b'pail-core-operation:v1\0'+_canonical(request,False,include=include,exclude=exclude)).digest()

def _receipt(request,response,robot,method):
 r=response.receipt
 plan=request.plan.plan_id if method==1 else request.plan_id
 identifier=request.operation_id or plan
 if (r.contract_version!=1 or r.operation_id!=identifier or r.plan_id!=plan or r.method!=method
     or not r.robot_id or (robot and r.robot_id!=robot) or r.request_digest!=operation_digest(request)):
  raise ValueError('OPERATION_RECEIPT_INVALID')
 if r.operation_state not in (1,2,3,4,5):raise ValueError('OPERATION_RECEIPT_INVALID')
 if r.operation_state in (2,3,5) and not r.durable_record_ref:raise ValueError('OPERATION_RECEIPT_NOT_DURABLE')
 return r

def submit_outcome(request,response):
 check_no_contract_setting()
 r=_receipt(request,response,request.robot_id,1)
 if r.operation_state==3:
  if response.status!=2:raise ValueError('OPERATION_RECEIPT_INVALID')
  return 'REJECTED'
 if r.operation_state==2:
  if response.status!=1 or not response.chain_id or r.original_chain_id!=response.chain_id:raise ValueError('OPERATION_RECEIPT_INVALID')
  return 'AUTHORIZED' if r.current_authority_state=='ACTIVE' and response.tokens else 'HISTORICAL_ONLY'
 return 'UNKNOWN'

def cancel_outcome(request,response,robot):
 check_no_contract_setting()
 r=_receipt(request,response,robot,2)
 if response.plan_id!=request.plan_id:raise ValueError('OPERATION_RECEIPT_INVALID')
 if r.operation_state==2 and response.cancelled and r.current_authority_state!='ACTIVE':return 'WITHDRAWAL_RECORDED'
 if r.operation_state==3 and not response.cancelled:return 'REJECTED'
 return 'UNKNOWN'
