// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

//! The judgment seam (contract ①/②). The adapter never judges — it feeds a [`Gate`] and obeys
//! its [`Judgment`]s. Two implementations: [`NoGate`] (MD-2a, not a gate, dev only) and
//! `gate_ffi::LibGate` (MD-2b, `libpail_gate` over its C ABI — the same `decide()` the ROS
//! gate node runs, with the permit/step/consumption state machine inside the library).

use std::collections::BTreeMap;

use crate::agent::TokenView;
use crate::classify::ActionClass;
use crate::evidence::EvidenceSnapshot;
use crate::safety::SafetyState;
use crate::state::Peer;

// Read by the enforcing gate; NoGate ignores its input by definition.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Intent {
    pub method: String,
    pub class: Option<ActionClass>,
    pub skill: Option<String>,
    pub linear_norm: f64,
    pub angular_norm: f64,
    /// SK-2 (public skill contract): what this adapter measured, by GUARDRAILS.tsv name. Empty =
    /// the two norms only (the library derives sls.linear_mps / sls.angular_rps from them).
    /// For a `robot.do` skill this is the skill's own envelope learned from `robot.skills`.
    pub measured: BTreeMap<String, f64>,
    pub peer: Peer,
    pub now_ms: i64,
}

/// One outcome of the gate, on any of its paths. Mirrors `pail.gate.abi.v1.Outcome`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Judgment {
    pub path: &'static str,        // command | recheck | step | safety
    pub state: String,             // PERMIT | BLOCK | ESTOP | "" (nothing published)
    pub reason: String,            // OK | ERR_* | NOGATE
    pub detail: String,            // SK-2: which name/value/bound — never a new reason code
    pub forward: bool,
    pub report: bool,
    pub report_chain_id: String,
    pub report_token_id: String,
    pub step_complete: bool,
    pub fatal: bool,
    pub permit_active: bool,
    pub step_active: bool,
    pub estop_active: bool,
    pub effective_mode: String,    // enforce | observe | none
}

impl Judgment {
    pub fn is_stop_event(&self) -> bool {
        self.state == "ESTOP" || (self.path != "command" && self.state == "BLOCK")
    }
}

pub trait Gate: Send + Sync {
    /// Human-readable identity for the startup banner and the journal.
    fn name(&self) -> String;
    /// True when this gate actually enforces authorization. `false` is refused in production.
    fn enforces(&self) -> bool;
    /// Policy `gate_mode` (enforce|observe) or "none".
    fn effective_mode(&self) -> String;
    fn set_token(&self, view: &TokenView);
    /// May return an ESTOP outcome when the feed trips the latch.
    fn observe_safety(&self, s: &SafetyState) -> Option<Judgment>;
    fn observe_evidence(&self, e: &EvidenceSnapshot);
    fn judge(&self, intent: &Intent) -> Judgment;
    /// Recheck + step timer; call every permit_recheck_ms after set_token. Returns the outcomes
    /// that carry a publication or a report (silent holds are filtered).
    fn tick(&self, now_ms: i64) -> Vec<Judgment>;
}

/// MD-2a: no gate linked. Every intent is forwarded, nothing is judged or reported. Exists so
/// the plumbing can be wired and measured; refused outside `PAIL_PROFILE=dev`.
pub struct NoGate;

impl Gate for NoGate {
    fn name(&self) -> String {
        "none (NOT ENFORCING — every intent is forwarded)".to_owned()
    }
    fn enforces(&self) -> bool {
        false
    }
    fn effective_mode(&self) -> String {
        "none".to_owned()
    }
    fn set_token(&self, _view: &TokenView) {}
    fn observe_safety(&self, _s: &SafetyState) -> Option<Judgment> {
        None
    }
    fn observe_evidence(&self, _e: &EvidenceSnapshot) {}
    fn judge(&self, _intent: &Intent) -> Judgment {
        Judgment { path: "command", reason: "NOGATE".to_owned(), forward: true, effective_mode: "none".to_owned(), ..Default::default() }
    }
    fn tick(&self, _now_ms: i64) -> Vec<Judgment> {
        Vec::new()
    }
}

/// LLD D5: on the PERMIT→BLOCK transition the adapter sends `robot.stop` **once**; every
/// further BLOCK is a plain drop and robotd's deadman does the rest. Process-wide, because the
/// permit is process-wide (one gate, one robot).
#[derive(Debug, Default)]
pub struct PermitTracker {
    last_forwarded: bool,
    stops_sent: u64,
}

impl PermitTracker {
    /// `forwarded=true` records a permitted pass; `false` a refusal. Returns true when this
    /// refusal is the first after a pass — the caller sends stop.
    pub fn observe(&mut self, forwarded: bool) -> bool {
        if forwarded {
            self.last_forwarded = true;
            return false;
        }
        let transition = self.last_forwarded;
        self.last_forwarded = false;
        if transition {
            self.stops_sent += 1;
        }
        transition
    }
    pub fn stops_sent(&self) -> u64 {
        self.stops_sent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_is_sent_once_per_transition() {
        let mut t = PermitTracker::default();
        assert!(!t.observe(false), "a drop before any forward is not a transition");
        assert!(!t.observe(true));
        assert!(t.observe(false), "first drop after forward → stop");
        assert!(!t.observe(false), "second drop → no second stop");
        assert!(!t.observe(false));
        assert!(!t.observe(true));
        assert!(t.observe(false));
        assert_eq!(t.stops_sent(), 2);
    }

    #[test]
    fn nogate_declares_itself() {
        assert!(!NoGate.enforces());
        assert!(NoGate.name().contains("NOT ENFORCING"));
        assert_eq!(NoGate.effective_mode(), "none");
    }

    #[test]
    fn stop_events_are_the_non_command_refusals() {
        let mut j = Judgment { path: "recheck", state: "BLOCK".into(), ..Default::default() };
        assert!(j.is_stop_event());
        j.path = "command";
        assert!(!j.is_stop_event(), "a command BLOCK is a drop, the tracker decides about stop");
        j.state = "ESTOP".into();
        assert!(j.is_stop_event());
    }
}
