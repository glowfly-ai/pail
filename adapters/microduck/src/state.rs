// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

//! Process-wide state shared by all connections: connection counter, the robot-release record
//! learned from `hello`, the gate, the agent, the safety/evidence feeds and the PERMIT→BLOCK
//! transition tracker. `judge()` is contract ①→②; `handle()` is where every gate outcome —
//! from a command, a recheck tick, a step deadline or the safety feed — turns into a report
//! and, on the first refusal after a permit, one `robot.stop`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use duck_ipc_proto as proto;
use tokio::sync::{mpsc, watch};

use crate::agent::{Agent, TokenView, pb::pail::token::v1 as tokenv1};
use crate::classify::ActionClass;
use crate::skills::SkillTable;
use crate::evidence::EvidenceSnapshot;
use crate::gate::{Gate, Intent, Judgment, PermitTracker};
use crate::safety::SafetyState;

#[derive(Debug, Clone, Copy)]
pub struct Peer {
    pub uid: u32,
    pub gid: u32,
    pub pid: Option<i32>,
}

/// What `hello` told us about the robot we sit in front of (LLD D8 — surfaced, not chained).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct RobotRelease {
    pub api_version: Option<u32>,
    pub daemon_version: Option<String>,
    /// `None` is honest: a non-CI build reports no revision (EVIDENCE_MD0 §6).
    pub revision: Option<String>,
}

/// The feeds the gate reads. Each is a `watch` so the relay always sees the newest value and
/// never blocks on a producer.
pub struct Feeds {
    pub token: watch::Receiver<TokenView>,
    pub safety: watch::Receiver<Option<SafetyState>>,
    pub evidence: watch::Receiver<Option<EvidenceSnapshot>>,
    /// Issuer-first (contract I-5): cleared by a failed report, set by a successful one.
    pub report_healthy: Arc<AtomicBool>,
}

pub struct Shared {
    /// Optional NDJSON decision log (`--gate-log`): one line per gate outcome handled, plus
    /// stop events. The adapter's counterpart of the ROS gate's `/pail/gate_state` topic —
    /// an observation surface for operators and the conformance harness, not a ledger (the
    /// ledger is the issuer's chain, fed by ReportDecision).
    gate_log: Mutex<Option<std::fs::File>>,
    conns: AtomicU64,
    release: Mutex<RobotRelease>,
    judged: AtomicU64,
    dropped: AtomicU64,
    reported: AtomicU64,
    pub gate: Arc<dyn Gate>,
    pub agent: Option<Arc<Agent>>,
    pub feeds: Feeds,
    /// LLD §3.1 skill name table — resolves `robot.do{skill}` to a class before the gate sees
    /// it. Unmapped stays `class: None` and the gate refuses it (`ERR_ACTION_UNMAPPED`).
    pub skills: SkillTable,
    tracker: Mutex<PermitTracker>,
    stop_tx: mpsc::Sender<()>,
    pub robot_id: String,
}

impl Shared {
    pub fn new(
        gate: Arc<dyn Gate>,
        agent: Option<Arc<Agent>>,
        feeds: Feeds,
        stop_tx: mpsc::Sender<()>,
        robot_id: String,
        gate_log: Option<std::fs::File>,
        skills: SkillTable,
    ) -> Self {
        Self {
            gate_log: Mutex::new(gate_log),
            conns: AtomicU64::new(0),
            release: Mutex::new(RobotRelease::default()),
            judged: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            reported: AtomicU64::new(0),
            gate,
            agent,
            feeds,
            skills,
            tracker: Mutex::new(PermitTracker::default()),
            stop_tx,
            robot_id,
        }
    }

    pub fn next_conn(&self) -> u64 {
        self.conns.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn record_hello(&self, conn: u64, h: &proto::HelloResult) {
        let rec = RobotRelease {
            api_version: Some(h.api_version),
            daemon_version: h.daemon_version.as_ref().map(|v| v.to_string()),
            revision: h.revision.clone(),
        };
        tracing::info!(conn, ?rec, "robot release learned from hello");
        *self.release.lock().expect("release lock") = rec;
    }

    pub fn release(&self) -> RobotRelease {
        self.release.lock().expect("release lock").clone()
    }

    /// Contract ①→②: push the newest token view, hand the intent to the gate, obey the
    /// verdict. Returns `true` = forward the bytes.
    pub fn judge(&self, conn: u64, peer: &Peer, method: &str, class: Option<ActionClass>, skill: Option<&str>, linear_norm: f64, angular_norm: f64) -> bool {
        let n = self.judged.fetch_add(1, Ordering::Relaxed) + 1;
        // A named skill takes its class from the deployment's table (LLD §3.1); a name the
        // table does not carry keeps `None`, which the gate refuses — never a default class.
        let class = match (class, skill) {
            (None, Some(name)) => self.skills.class_of(name),
            (c, _) => c,
        };
        // SK-2: a named skill's envelope is what the robot said it drives (learned at
        // connect); the gate compares that, by name, against the token. Unknown skill or
        // nothing learned yet → empty map → the library derives from the norms (0,0).
        let measured = skill.and_then(|n| self.skills.envelope_of(n)).map(|e| e.measured()).unwrap_or_default();
        let intent = Intent {
            method: method.to_owned(),
            class,
            skill: skill.map(str::to_owned),
            linear_norm,
            angular_norm,
            measured,
            peer: *peer,
            now_ms: crate::agent::now_ms(),
        };
        // The node fetches the token synchronously per command; here the poll loop's latest
        // answer is pushed right before judging so the view is at most one poll old.
        self.gate.set_token(&self.feeds.token.borrow());
        let mut j = self.gate.judge(&intent);
        let enforcing = self.gate.enforces();

        // Issuer-first (contract I-5): an enforcing gate may not forward while reports are
        // failing — there would be a decision the ledger never sees.
        if enforcing && j.forward && !self.feeds.report_healthy.load(Ordering::Relaxed) {
            j.forward = false;
            j.state = "BLOCK".to_owned();
            j.reason = "ERR_REPORT_UNAVAILABLE".to_owned();
        }

        let forward = self.handle(conn, Some(peer), &j, enforcing);
        if forward {
            tracing::debug!(conn, uid = peer.uid, method, ?class, skill, reason = j.reason, mode = j.effective_mode, judged_total = n, "forward");
        } else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            tracing::info!(conn, uid = peer.uid, method, ?class, skill, state = j.state, reason = j.reason, mode = j.effective_mode, "drop");
        }
        forward
    }

    /// Every gate outcome passes through here: the report (only from an enforcing gate — a
    /// non-judging gate must not write PERMITs it never judged, H-B2), the stop-once
    /// transition, and the observe-mode passthrough. Returns whether the bytes may be
    /// forwarded (meaningful for the command path only).
    fn log_line(&self, v: serde_json::Value) {
        use std::io::Write;
        if let Some(f) = self.gate_log.lock().expect("gate log lock").as_mut() {
            let _ = writeln!(f, "{}", v);
        }
    }

    pub fn record_note(&self,conn:u64,peer:&Peer,text_len:usize)->std::io::Result<()> {
        use std::io::Write;
        let value=serde_json::json!({"t_ms":crate::agent::now_ms(),"kind":"note","method":"robot.vetbookNote", "conn":conn,"uid":peer.uid,"text_len_bytes":text_len,"scope":"adapter_local_audit_not_blackbox"});
        let mut guard=self.gate_log.lock().expect("gate log lock");
        if let Some(f)=guard.as_mut(){writeln!(f,"{}",value)}else{writeln!(std::io::stderr().lock(),"{}",value)}
    }

    pub fn handle(&self, conn: u64, peer: Option<&Peer>, j: &Judgment, enforcing: bool) -> bool {
        let observe = j.effective_mode == "observe";
        self.log_line(serde_json::json!({
            "t_ms": crate::agent::now_ms(), "kind": "outcome", "path": j.path, "state": j.state,
            "reason": j.reason, "detail": j.detail, "forward": j.forward, "report": j.report,
            "permit_active": j.permit_active, "step_active": j.step_active,
            "estop_active": j.estop_active, "step_complete": j.step_complete, "fatal": j.fatal,
            "mode": j.effective_mode, "enforcing": enforcing, "conn": conn,
            "uid": peer.map(|p| p.uid),
            // M1-b (2026-09-15): the ids this outcome was reported under, so an observer can
            // tie a PERMIT to the token the issuer signed instead of pairing by clock.
            "chain_id": j.report_chain_id, "token_id": j.report_token_id,
        }));
        // observe-mode contract / contract I-7: under observe the verdict is recorded, never applied —
        // no drop, no stop. Under enforce the verdict is the whole answer.
        let verdict_forward = j.forward;
        let forward = if !enforcing { true } else if observe { true } else { verdict_forward };

        if enforcing && !observe {
            // A command refusal and a recheck/step/safety refusal both end the permit; the
            // tracker sends robot.stop exactly once per PERMIT→refusal edge (LLD D5).
            let passed = if j.path == "command" { verdict_forward } else { !j.is_stop_event() && !(j.path == "step" && j.step_complete) };
            let transition = self.tracker.lock().expect("tracker lock").observe(passed);
            if transition {
                tracing::warn!(conn, path = j.path, state = j.state, reason = j.reason, "PERMIT ended — requesting robot.stop");
                self.log_line(serde_json::json!({"t_ms": crate::agent::now_ms(), "kind": "stop", "path": j.path, "state": j.state, "reason": j.reason}));
                if self.stop_tx.try_send(()).is_err() {
                    tracing::warn!(conn, "stop request could not be queued (safety task busy or gone)");
                }
            }
        }

        if enforcing && j.report {
            if let Some(agent) = &self.agent {
                let decision = match j.state.as_str() {
                    "PERMIT" => tokenv1::Decision::Permit,
                    "ESTOP" => tokenv1::Decision::Estop,
                    _ => tokenv1::Decision::Block,
                };
                let ev = self.feeds.evidence.borrow().clone();
                agent.report(tokenv1::ReportDecisionRequest {
                    robot_id: self.robot_id.clone(),
                    chain_id: j.report_chain_id.clone(),
                    token_id: j.report_token_id.clone(),
                    decision: decision as i32,
                    reason_code: j.reason.clone(),
                    evidence: ev.map(|e| tokenv1::EvidenceSummary {
                        source: e.source,
                        object_id: e.object_id,
                        confidence: e.confidence as f32,
                        unix_ms: e.received_ms,
                    }),
                    step_complete: j.step_complete,
                    // SK-3: what consumed the step (complete:timeout on this adapter's
                    // duration rows) — the issuer's completion rule reads it.
                    detail: if !j.step_complete && (j.fatal || j.path=="safety") {
                        let safety=self.feeds.safety.borrow().clone();
                        match safety {Some(s) if !s.detail.is_empty()=>format!("{}; safety={}",j.detail,serde_json::to_string(&s.detail).unwrap_or_default()),_=>j.detail.clone()}
                    } else {j.detail.clone()},
                    fatal: j.fatal,
                    // The UDS/plaintext evidence plane carries no SROS2-style sender auth.
                    evidence_provenance: "unenforced".to_owned(),
                    effective_mode: j.effective_mode.clone(),
                    // OI-01 (2026-10-01): delivery metadata is the robot agent's to stamp
                    // (decided_unix_ms, agent_run_id, agent_seq, delivery); the adapter
                    // leaves the fields empty — "did not say", never a claim.
                    decided_unix_ms: 0,
                    agent_seq: 0,
                    agent_run_id: String::new(),
                    delivery: String::new(),
                    ..Default::default()
                });
                self.reported.fetch_add(1, Ordering::Relaxed);
                let _ = peer;
            }
        }
        forward
    }

    pub fn judged_total(&self) -> u64 {
        self.judged.load(Ordering::Relaxed)
    }
    pub fn dropped_total(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
    pub fn reported_total(&self) -> u64 {
        self.reported.load(Ordering::Relaxed)
    }
    pub fn stops_sent(&self) -> u64 {
        self.tracker.lock().expect("tracker lock").stops_sent()
    }
}

/// The gate's clock: every `every`, push the newest token view and run the recheck + step
/// timer paths (the node's `on_permit_recheck` / `on_step_timer`). Outcomes that publish or
/// report go through `handle()`.
pub async fn tick_loop(shared: Arc<Shared>, every: std::time::Duration) {
    let mut tick = tokio::time::interval(every);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        shared.gate.set_token(&shared.feeds.token.borrow());
        let enforcing = shared.gate.enforces();
        for j in shared.gate.tick(crate::agent::now_ms()) {
            tracing::info!(path = j.path, state = j.state, reason = j.reason, step_complete = j.step_complete, permit = j.permit_active, "gate tick");
            shared.handle(0, None, &j, enforcing);
        }
    }
}

/// Feeds → gate: the safety feed on every change (an UNSAFE reading may latch E-STOP, whose
/// outcome is handled like any other), the evidence feed on every change.
pub async fn feed_loop(shared: Arc<Shared>) {
    let mut safety = shared.feeds.safety.clone();
    let mut evidence = shared.feeds.evidence.clone();
    loop {
        tokio::select! {
            r = safety.changed() => {
                if r.is_err() { return; }
                let cur = safety.borrow_and_update().clone();
                if let Some(s) = cur {
                    if let Some(j) = shared.gate.observe_safety(&s) {
                        tracing::warn!(state = j.state, reason = j.reason, "safety feed outcome");
                        let enforcing = shared.gate.enforces();
                        shared.handle(0, None, &j, enforcing);
                    }
                }
            }
            r = evidence.changed() => {
                if r.is_err() { return; }
                let cur = evidence.borrow_and_update().clone();
                if let Some(e) = cur {
                    shared.gate.observe_evidence(&e);
                }
            }
        }
    }
}
