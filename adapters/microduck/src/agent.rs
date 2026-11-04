// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

//! The PAIL robot agent over gRPC (contract ⑤): the token view the gate judges against, the
//! decision reports, and the periodic self-attestation. Transport-agnostic on purpose — this
//! module has no idea a duck exists.
//!
//! Endpoint forms: `unix:/path/agent.sock` (the agent's `PAIL_GRPC_UDS_PATH`, peer-cred
//! authenticated, the shape a board deployment uses) or `http://host:port` (plaintext, DEV
//! ONLY — the agent itself refuses it outside `PAIL_PROFILE=dev`). mTLS over TCP is not wired
//! in MD-2a; a board runs the agent beside the adapter and the socket is the boundary.

use std::sync::Arc;
use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tokio::sync::{mpsc, watch};
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

pub mod pb {
    pub mod pail {
        pub mod v1 {
            tonic::include_proto!("pail.v1");
        }
        pub mod token {
            pub mod v1 {
                tonic::include_proto!("pail.token.v1");
            }
        }
        pub mod gate {
            pub mod abi {
                // Consumed only by gate_ffi (feature libgate); generated regardless so the
                // schema stays one .proto for both builds.
                #[allow(dead_code)]
                pub mod v1 {
                    tonic::include_proto!("pail.gate.abi.v1");
                }
            }
        }
    }
}
use pb::pail::token::v1 as tokenv1;
use tokenv1::token_service_client::TokenServiceClient;

/// The gate's input from the agent. `reachable=false` with a stale `resp` is *not* a token —
/// the gate reads `ok()` and the streak, never the stale body (LLD §4 "마지막 토큰 재사용 금지").
// `unreachable_streak` / `ok()` / the response body are what the enforcing gate (AD-1) reads;
// NoGate reads nothing, hence the allow. Removing them would be removing the gate's input.
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct TokenView {
    pub reachable: bool,
    pub unreachable_streak: u32,
    pub fetched_ms: i64,
    pub resp: Option<tokenv1::GetActiveTokenResponse>,
}

#[allow(dead_code)]
impl TokenView {
    pub fn ok(&self) -> bool {
        self.reachable
            && self
                .resp
                .as_ref()
                .map(|r| r.status == tokenv1::ActiveTokenStatus::Ok as i32 && r.token.is_some())
                .unwrap_or(false)
    }
    pub fn status_name(&self) -> &'static str {
        match self.resp.as_ref().map(|r| r.status) {
            _ if !self.reachable => "UNREACHABLE",
            Some(s) if s == tokenv1::ActiveTokenStatus::Ok as i32 => "OK",
            Some(s) if s == tokenv1::ActiveTokenStatus::NoToken as i32 => "NO_TOKEN",
            Some(s) if s == tokenv1::ActiveTokenStatus::Revoked as i32 => "REVOKED",
            Some(s) if s == tokenv1::ActiveTokenStatus::Error as i32 => "ERROR",
            Some(_) => "UNSPECIFIED",
            None => "NONE",
        }
    }
    pub fn chain_id(&self) -> &str {
        self.resp.as_ref().map(|r| r.chain_id.as_str()).unwrap_or("")
    }
    pub fn token_id(&self) -> String {
        self.resp
            .as_ref()
            .and_then(|r| r.token.as_ref())
            .and_then(|t| t.token.as_ref())
            .map(|a| a.token_id.clone())
            .unwrap_or_default()
    }
}

pub struct Agent {
    core_contract: bool,
    execution_id: tonic::metadata::MetadataValue<tonic::metadata::Ascii>,
    endpoint: String,
    robot_id: String,
    channel: Channel,
    token_tx: watch::Sender<TokenView>,
    critical_lost: AtomicBool,
    report_tx: mpsc::Sender<tokenv1::ReportDecisionRequest>,
    /// Issuer-first: false after a report failed and until one succeeds again. The relay reads
    /// this before forwarding a judged intent (contract I-5).
    report_healthy: Arc<AtomicBool>,
    reports_failed: Arc<AtomicU32>,
}

pub struct AgentHandles {
    pub token_rx: watch::Receiver<TokenView>,
    pub report_healthy: Arc<AtomicBool>,
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

async fn connect(endpoint: &str) -> Result<Channel, String> {
    if let Some(path) = endpoint.strip_prefix("unix:") {
        let path = std::path::PathBuf::from(path);
        // The URI is a placeholder hyper needs; the connector ignores it.
        Endpoint::try_from("http://pail-agent.uds")
            .map_err(|e| e.to_string())?
            .connect_timeout(Duration::from_secs(2))
            .connect_with_connector(service_fn(move |_: Uri| {
                let p = path.clone();
                async move { UnixStream::connect(p).await.map(TokioIo::new) }
            }))
            .await
            .map_err(|e| e.to_string())
    } else if endpoint.starts_with("http://") {
        Endpoint::try_from(endpoint.to_owned())
            .map_err(|e| e.to_string())?
            .connect_timeout(Duration::from_secs(2))
            .connect()
            .await
            .map_err(|e| e.to_string())
    } else {
        Err(format!("unsupported agent endpoint {endpoint:?} (want unix:/path or http://host:port)"))
    }
}

impl Agent {
    /// Connects lazily-but-now: a first failure is returned so startup can say so, later
    /// failures are absorbed into the token view (`reachable=false`).
    pub async fn new(endpoint: &str, robot_id: &str) -> Result<(Arc<Self>, AgentHandles), String> {
        // One communication contract (0.2.0-preview.40): the selecting variable is gone — the variable being present at
        // all, an empty value included (0.2.0-preview.41, P40-L2), refuses by name (same wording as internal/corecomm;
        // source spec/CORE_COMM.md). Reports always use the C1 receipt form.
        if std::env::var_os("PAIL_CORE_COMM_CONTRACT").is_some(){return Err("CORE_COMM_CONTRACT_SETTING_REMOVED: PAIL_CORE_COMM_CONTRACT has no meaning (there is one communication contract); unset it".into());}
        let core_contract=true;
        let mut entropy=[0u8;16];
        std::fs::File::open("/dev/urandom").and_then(|mut f|f.read_exact(&mut entropy))
            .map_err(|e|format!("execution identity unavailable: {e}"))?;
        let execution_id=hex(&entropy).parse().map_err(|e|format!("execution identity: {e}"))?;
        let channel = connect(endpoint).await?;
        let (token_tx, token_rx) = watch::channel(TokenView::default());
        let (report_tx, report_rx) = mpsc::channel(256);
        let report_healthy = Arc::new(AtomicBool::new(true));
        let agent = Arc::new(Self {
            core_contract,
            execution_id,
            endpoint: endpoint.to_owned(),
            robot_id: robot_id.to_owned(),
            channel,
            token_tx,
            critical_lost: AtomicBool::new(false),
            report_tx,
            report_healthy: report_healthy.clone(),
            reports_failed: Arc::new(AtomicU32::new(0)),
        });
        tokio::spawn(agent.clone().report_loop(report_rx));
        Ok((agent, AgentHandles { token_rx, report_healthy }))
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// GetActiveToken every `every` (the gate's `permit_recheck_ms`). Each answer, or each
    /// failure, replaces the view — the streak is what grace counts on.
    pub async fn token_loop(self: Arc<Self>, every: Duration) {
        let mut client = TokenServiceClient::new(self.channel.clone());
        let mut streak: u32 = 0;
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let req = tokenv1::GetActiveTokenRequest { robot_id: self.robot_id.clone() };
            let mut call = tonic::Request::new(req);
            call.set_timeout(every.max(Duration::from_millis(50)) * 2);
            call.metadata_mut().insert("pail-execution-instance",self.execution_id.clone());
            match client.get_active_token(call).await {
                Ok(resp) => {
                    if !execution_ack(resp.metadata(),&self.execution_id) {
                        tracing::warn!("execution identity not acknowledged; refusing token response");
                        let _=self.token_tx.send(TokenView{reachable:true,unreachable_streak:0,fetched_ms:now_ms(),
                            resp:Some(tokenv1::GetActiveTokenResponse{status:tokenv1::ActiveTokenStatus::Error as i32,..Default::default()})});
                        continue;
                    }
                    if streak > 0 {
                        tracing::info!(streak, "agent reachable again");
                    }
                    streak = 0;
                    let r = resp.into_inner();
                    let _ = self.token_tx.send(TokenView {
                        reachable: true,
                        unreachable_streak: 0,
                        fetched_ms: now_ms(),
                        resp: Some(r),
                    });
                }
                Err(e) => {
                    streak = streak.saturating_add(1);
                    if streak == 1 || streak % 50 == 0 {
                        tracing::warn!(streak, error = %e, "GetActiveToken failed");
                    }
                    let _ = self.token_tx.send(TokenView {
                        reachable: false,
                        unreachable_streak: streak,
                        fetched_ms: now_ms(),
                        resp: None,
                    });
                }
            }
        }
    }

    /// Queue a decision report. Backpressure = the queue is full = the agent is not keeping
    /// up; that is a failed report, not a dropped one (issuer-first).
    pub fn report(&self, mut req: tokenv1::ReportDecisionRequest) {
        if self.core_contract {
            if let Err(e)=crate::core_report::prepare(&mut req){self.report_healthy.store(false,Ordering::Relaxed);tracing::error!(error=%e,"report encoding failed");return;}
        }
        let critical=self.core_contract && (req.fatal || req.step_complete);
        if self.report_tx.try_send(req).is_err() {
            if critical{self.critical_lost.store(true,Ordering::Relaxed);}
            self.report_healthy.store(false, Ordering::Relaxed);
            self.reports_failed.fetch_add(1, Ordering::Relaxed);
            tracing::warn!("report queue full; forwarding suspended until a report succeeds");
        }
    }

    async fn report_loop(self: Arc<Self>, mut rx: mpsc::Receiver<tokenv1::ReportDecisionRequest>) {
        let mut client = TokenServiceClient::new(self.channel.clone());
        while let Some(req) = rx.recv().await {
            loop {
                let mut call=tonic::Request::new(req.clone());call.set_timeout(Duration::from_millis(500));
                let mut terminal=false;
                let ok=match client.report_decision(call).await {
                    Ok(resp)=>{let response=resp.into_inner();terminal=crate::core_report::terminal_rejection(&req,&response);crate::core_report::accepted(&req,&response)},
                    Err(e)=>{tracing::warn!(error=%e,"report unconfirmed");false}
                };
                self.report_healthy.store(ok && !self.critical_lost.load(Ordering::Relaxed),Ordering::Relaxed);
                if !ok{self.reports_failed.fetch_add(1,Ordering::Relaxed);}
                if ok||terminal||req.receipt_contract_version==0||!(req.fatal||req.step_complete){break;}
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }

    /// Self-attestation (contract I-8): sha256 of our own executable + build_info, every
    /// `every`. The first call happens immediately so the journal has us before the first
    /// intent.
    pub async fn attest_loop(self: Arc<Self>, component: String, build_info: String, every: Duration) {
        let mut client = TokenServiceClient::new(self.channel.clone());
        let measurement = match self_measurement().await {
            Ok(m) => m,
            Err(e) => {
                tracing::error!(error = %e, "cannot measure own executable; attestation disabled");
                return;
            }
        };
        let mut tick = tokio::time::interval(every);
        loop {
            tick.tick().await;
            let req = tokenv1::AttestRequest {
                robot_id: self.robot_id.clone(),
                component: component.clone(),
                measurement_sha256: measurement.clone(),
                build_info: build_info.clone(),
            };
            let mut call = tonic::Request::new(req);
            call.set_timeout(Duration::from_secs(2));
            match client.attest(call).await {
                Ok(r) => {
                    let r = r.into_inner();
                    // The gateway owns lease effects. This producer observes them;
                    // it never duplicates invalidation or grants local authority.
                    let bound = r.effect_contract_version == 1 && r.robot_id == self.robot_id
                        && r.component == component && r.measurement_sha256 == measurement;
                    let mode = match r.enforcement_mode.as_str() {
                        "off" => "off", "log" => "log", "required" => "required", _ => "unknown",
                    };
                    let status = match r.status.as_str() {
                        "OK" => "OK", "ERROR" => "ERROR", "UNKNOWN_MEASUREMENT" => "UNKNOWN_MEASUREMENT", _ => "UNKNOWN_STATUS",
                    };
                    tracing::info!(status, ttl_s = r.ttl_s, measurement = hex(&measurement),
                        effect_contract_version = r.effect_contract_version, authority_effect = r.authority_effect,
                        enforcement_mode = mode, effect_request_bound = bound, issuer_epoch = r.issuer_epoch,
                        "Attest (effect applied by gateway; not a token grant)");
                }
                Err(e) => tracing::warn!(error = %e, "Attest failed"),
            }
        }
    }
}

async fn self_measurement() -> Result<Vec<u8>, String> {
    use sha2::{Digest, Sha256};
    let bytes = tokio::fs::read("/proc/self/exe").await.map_err(|e| e.to_string())?;
    Ok(Sha256::digest(&bytes).to_vec())
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn execution_ack(meta: &tonic::metadata::MetadataMap, id: &tonic::metadata::MetadataValue<tonic::metadata::Ascii>) -> bool {
    let all=meta.get_all("pail-execution-instance");
    let mut values=all.iter();
    values.next()==Some(id) && values.next().is_none()
}

#[cfg(test)]
mod execution_tests {
    use super::*;
    #[test]
    fn exactly_one_ack() {
        let id: tonic::metadata::MetadataValue<tonic::metadata::Ascii>="execution-a".parse().unwrap();
        let mut meta=tonic::metadata::MetadataMap::new();
        assert!(!execution_ack(&meta,&id));
        meta.append("pail-execution-instance",id.clone());
        assert!(execution_ack(&meta,&id));
        meta.append("pail-execution-instance",id.clone());
        assert!(!execution_ack(&meta,&id));
    }
}
