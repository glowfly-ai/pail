// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
//! core-comm-v1 immutable report encoding. This digest never grants authority.
use crate::agent::pb::pail::token::v1 as tp;
use sha2::{Digest,Sha256};
use std::io::Read;
fn field(out:&mut Vec<u8>,n:u32,k:u8,b:&[u8]){out.extend(n.to_be_bytes());out.push(k);out.extend((b.len() as u64).to_be_bytes());out.extend(b);}
pub fn digest(r:&tp::ReportDecisionRequest)->Result<Vec<u8>,String>{
 if !matches!(r.decision,0..=3){return Err("unknown report decision".into())}
 let mut out=b"pail-core-report:v1\0".to_vec();
 field(&mut out,1,8,r.robot_id.as_bytes());field(&mut out,2,8,r.chain_id.as_bytes());field(&mut out,3,8,r.token_id.as_bytes());
 field(&mut out,4,13,&r.decision.to_be_bytes());field(&mut out,5,8,r.reason_code.as_bytes());
 let mut evidence=Vec::new();if let Some(e)=&r.evidence{
  if !e.confidence.is_finite(){return Err("nonfinite evidence".into())}
  field(&mut evidence,1,8,e.source.as_bytes());field(&mut evidence,2,8,e.object_id.as_bytes());
  field(&mut evidence,3,6,&(if e.confidence==0.0{0.0f32}else{e.confidence}).to_bits().to_be_bytes());field(&mut evidence,4,4,&e.unix_ms.to_be_bytes());
 }
 field(&mut out,6,10,&evidence);field(&mut out,7,1,&[r.step_complete as u8]);field(&mut out,8,1,&[r.fatal as u8]);
 field(&mut out,9,8,r.evidence_provenance.as_bytes());field(&mut out,10,8,r.effective_mode.as_bytes());field(&mut out,11,8,r.detail.as_bytes());field(&mut out,16,8,r.report_id.as_bytes());
 if out.len()>1<<20{return Err("report too large".into())}Ok(Sha256::digest(&out).to_vec())
}
pub fn prepare(r:&mut tp::ReportDecisionRequest)->Result<(),String>{
 let mut entropy=[0u8;16];std::fs::File::open("/dev/urandom").and_then(|mut f|f.read_exact(&mut entropy)).map_err(|e|e.to_string())?;
 r.report_id=crate::agent::hex(&entropy);r.receipt_contract_version=1;r.report_digest=digest(r)?;Ok(())
}
pub fn accepted(r:&tp::ReportDecisionRequest,a:&tp::ReportDecisionResponse)->bool{
 if !a.accepted{return false}if r.receipt_contract_version==0{return true}
 let Some(x)=&a.receipt else{return false};
 if x.contract_version!=1||x.report_id!=r.report_id||x.report_digest!=r.report_digest||x.robot_id!=r.robot_id||x.receiver_instance_id.is_empty(){return false}
 let disposition=matches!(x.disposition,1|2)||(r.step_complete&&!r.fatal&&x.storage==3&&x.effect_scope==2&&x.disposition==3);
 if !disposition{return false}
 if r.fatal{return x.storage==4&&x.effect==3&&x.effect_scope==3&&!x.journal_record_ref.is_empty()}
 if r.step_complete{return matches!(x.storage,3|4)&&x.effect==3&&matches!(x.effect_scope,2|3)}
 matches!(x.storage,2|3|4)&&matches!(x.effect,1|3)
}
pub fn terminal_rejection(r:&tp::ReportDecisionRequest,a:&tp::ReportDecisionResponse)->bool{
 let Some(x)=&a.receipt else{return false};!a.accepted&&x.contract_version==1&&x.report_id==r.report_id&&x.report_digest==r.report_digest&&x.robot_id==r.robot_id&&x.storage==4&&matches!(x.effect,4|5)&&x.disposition==5&&!x.journal_record_ref.is_empty()
}

#[cfg(test)]mod tests{
 use super::*;
 #[test]fn independent_python_golden(){
  let expected=["cc4b2936c795da8273764c0626e705be47ee6a8960a0c33efc21197703183a32","59eabb954480f7c7dc1165da7b332b8291a7537465cfaf35a448be14e249be33"];
  for (i,h) in expected.iter().enumerate(){
   let r=tp::ReportDecisionRequest{robot_id:"robot-1".into(),chain_id:"chain-1".into(),token_id:"token-1".into(),decision:1,reason_code:"OK".into(),step_complete:true,detail:"complete:timeout".into(),evidence_provenance:"enforced".into(),effective_mode:"enforce".into(),report_id:"event-1".into(),receipt_contract_version:1,evidence:if i==1{Some(tp::EvidenceSummary{source:"camera".into(),object_id:"box-12".into(),confidence:0.75,unix_ms:1234})}else{None},..Default::default()};
   assert_eq!(crate::agent::hex(&digest(&r).unwrap()),*h);
  }
 }
 #[test]fn local_storage_cannot_confirm_fatal(){
  let mut req=tp::ReportDecisionRequest{robot_id:"r".into(),report_id:"id".into(),fatal:true,receipt_contract_version:1,..Default::default()};req.report_digest=digest(&req).unwrap();
  let r=tp::ReportDecisionResponse{accepted:true,receipt:Some(tp::ReportReceipt{contract_version:1,robot_id:req.robot_id.clone(),report_id:req.report_id.clone(),report_digest:req.report_digest.clone(),receiver_instance_id:"gw".into(),storage:3,effect:3,effect_scope:2,..Default::default()})};
  assert!(!accepted(&req,&r));
 }
}
