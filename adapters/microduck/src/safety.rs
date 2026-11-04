// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

//! Safety ingress (contract ③, LLD §6.1): the adapter's *own* upstream connection subscribes
//! to `robot.state` and maps it to a PAIL `SafetyState`. Not read off a client's stream — a
//! client that never subscribes must not silence the safety feed. The same connection is the
//! one `robot.stop` goes out on (LLD D5).

use std::path::PathBuf;
use std::time::Duration;

use duck_ipc_proto as proto;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, watch};

use crate::agent::now_ms;

/// LLD §6.1 mapping. `level` uses the gate's vocabulary (`OK|WARN|UNSAFE`); the raw fields are
/// kept for the report and the log. Absence is `None` in the watch — the adapter never
/// synthesises an "OK" (contract I-6).
#[derive(Debug, Clone, PartialEq)]
pub struct SafetyState {
    pub level: &'static str,
    pub source: &'static str,
    pub observed_ms: i64,
    pub fallen: bool,
    pub limp: bool,
    pub picked_up: bool,
    pub detail: Vec<String>,
    pub battery_percent: Option<f64>,
    pub loop_hz: Option<f64>,
    pub loop_missed: Option<u64>,
}

pub struct SafetyConfig {
    pub raw: PathBuf,
    pub hz: u32,
    pub battery_floor: f64,
    /// `robot.health` poll period (LLD D6). Zero = no poll, battery stays absent.
    pub health_poll: Duration,
    /// The skill table (LLD §3.1) — compared once per session against what the robot says it
    /// answers to (`robot.skills`); the difference is a banner.
    pub skills: crate::skills::SkillTable,
    /// SK-2 (S33): production refuses a table that names skills the robot does not answer to.
    pub production: bool,
}

/// Runs forever: connect → hello → subscribe → stream. On any error the watch is *not*
/// touched (staleness is the gate's `safety_stale_ms` to judge) and we reconnect after a
/// backoff. `stop_rx` carries stop requests from the relay.
pub async fn run(cfg: SafetyConfig, tx: watch::Sender<Option<SafetyState>>, mut stop_rx: mpsc::Receiver<()>) {
    let mut backoff = Duration::from_millis(250);
    loop {
        match session(&cfg, &tx, &mut stop_rx).await {
            Ok(()) => tracing::info!("safety stream closed by upstream"),
            Err(e) => tracing::warn!(error = %e, "safety stream error"),
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(2));
    }
}

async fn session(
    cfg: &SafetyConfig,
    tx: &watch::Sender<Option<SafetyState>>,
    stop_rx: &mut mpsc::Receiver<()>,
) -> Result<(), String> {
    let stream = UnixStream::connect(&cfg.raw).await.map_err(|e| e.to_string())?;
    let (rd, mut wr) = stream.into_split();
    let mut rd = BufReader::new(rd);
    let mut line: Vec<u8> = Vec::with_capacity(4096);

    let hello = proto::Request::call(
        proto::Id::Number(1),
        &proto::Call::Hello(proto::HelloParams { api_version: proto::API_VERSION }),
    );
    send(&mut wr, &hello).await?;
    let sub = proto::Request::call(
        proto::Id::Number(2),
        &proto::Call::RobotSubscribe(proto::SubscribeParams { hz: Some(cfg.hz) }),
    );
    send(&mut wr, &sub).await?;
    tracing::info!(hz = cfg.hz, "safety: subscribed to robot.state");
    // LLD §3.1: ask once what the robot answers to, and say which of those names the table
    // does not map. Not a refusal — the refusal is per intent — but the operator sees the gap
    // before the first `robot.do`.
    const SKILLS_ID: u64 = 3;
    send(&mut wr, &proto::Request::call(proto::Id::Number(SKILLS_ID), &proto::Call::RobotSkills)).await?;

    // LLD D6: the battery is not in `robot.state`; it is polled from `robot.health` and folded
    // into the next state frame. Until the first answer it is absent (contract I-6).
    let mut battery: Option<f64> = None;
    let mut health_id: u64 = 2000;
    let mut pending_health: Option<u64> = None;
    let mut health_tick = tokio::time::interval(if cfg.health_poll.is_zero() { Duration::from_secs(3600) } else { cfg.health_poll });
    health_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    health_tick.tick().await; // the first tick fires immediately; poll on the next

    let mut stop_id: u64 = 1000;
    loop {
        tokio::select! {
            r = rd.read_until(b'\n', &mut line) => {
                match r {
                    Ok(0) => return Ok(()),
                    Ok(_) => {}
                    Err(e) => return Err(e.to_string()),
                }
                if let Ok(req) = serde_json::from_slice::<proto::Request>(&line) {
                    if req.method == proto::method::ROBOT_STATE {
                        if let Some(p) = req.params {
                            match serde_json::from_value::<proto::RobotState>(p) {
                                Ok(st) => { let _ = tx.send(Some(map(&st, cfg.battery_floor, battery))); }
                                Err(e) => tracing::warn!(error = %e, "robot.state did not parse; feed not updated"),
                            }
                        }
                    }
                } else if let Ok(resp) = serde_json::from_slice::<proto::Response>(&line) {
                    match resp.id {
                        Some(proto::Id::Number(id)) if id == SKILLS_ID => match resp.result.map(serde_json::from_value::<proto::SkillsResult>) {
                            Some(Ok(sk)) => {
                                let names: Vec<String> = sk.skills.iter().map(|p| p.name.clone()).chain(sk.built_in.iter().cloned()).collect();
                                // SK-2 (public skill contract): the robot's own numbers become the measured
                                // envelope of every `robot.do` from here on.
                                cfg.skills.learn(&sk);
                                tracing::info!(learned = cfg.skills.learned(), "skill envelopes learned from robot.skills (duration, command twist)");
                                let unmapped = cfg.skills.unmapped(names.iter().map(String::as_str));
                                if unmapped.is_empty() {
                                    tracing::info!(robot_skills = names.len(), "skill table covers every skill the robot answers to");
                                } else {
                                    tracing::warn!(?unmapped, robot_skills = names.len(), "skills the robot answers to that the table does not map — each will be refused (ERR_ACTION_UNMAPPED)");
                                }
                                // S33 (Microduck side), three-valued like S27: a table name the robot
                                // does not answer to is refused in production — but only when the
                                // answer is one that CAN be judged. The daemon lists its built-ins
                                // (ground_pick, sit_toggle, …) in `built_in`; a daemon that answers
                                // with `built_in: []` (the fake, 2026-09-09 rig) has not named them,
                                // and "not listed" must not read as "not there" (H-B2). That answer
                                // is `unverifiable`: banner in every profile, no refusal.
                                let missing = cfg.skills.not_on_robot(names.iter().map(String::as_str));
                                if !missing.is_empty() {
                                    if sk.built_in.is_empty() {
                                        tracing::warn!(?missing, "S33 unverifiable: the table names skills not in robot.skills, and the daemon listed no built-ins — cannot tell absent from unlisted; each will be judged by its table row when called");
                                    } else if cfg.production {
                                        tracing::error!(?missing, "STARTUP REFUSED: S33 skill table names skills this robot does not answer to — a token could carry an envelope for a skill it cannot run (public skill contract)");
                                        std::process::exit(78);
                                    } else {
                                        tracing::warn!(?missing, "S33 skill table names skills this robot does not answer to (PAIL_PROFILE=dev: continuing)");
                                    }
                                }
                            }
                            Some(Err(e)) => tracing::warn!(error = %e, "robot.skills did not parse"),
                            None => tracing::warn!(error = ?resp.error, "robot.skills answered with an error"),
                        },
                        Some(proto::Id::Number(id)) if Some(id) == pending_health => {
                            pending_health = None;
                            match resp.result.map(serde_json::from_value::<proto::HealthResult>) {
                                Some(Ok(h)) => {
                                    let prev = battery;
                                    battery = h.battery.as_ref().map(|b| b.percent);
                                    if prev.is_none() && battery.is_some() {
                                        tracing::info!(percent = ?battery, healthy = h.healthy, "robot.health: battery now known");
                                    }
                                    if !h.healthy {
                                        tracing::warn!(reason = ?h.reason, degraded = h.degraded, "robot.health reports unhealthy");
                                    }
                                }
                                Some(Err(e)) => tracing::warn!(error = %e, "robot.health did not parse; battery unchanged"),
                                None => tracing::warn!(error = ?resp.error, "robot.health answered with an error; battery unchanged"),
                            }
                        }
                        _ => {}
                    }
                }
                line.clear();
            }
            _ = health_tick.tick(), if !cfg.health_poll.is_zero() => {
                if pending_health.is_some() {
                    // The previous poll never answered: the bus may be wedged. Do not stack
                    // requests; the battery goes back to absent so a stale value cannot
                    // read as "fine" (contract I-6).
                    tracing::warn!("robot.health did not answer within a poll period; battery reported absent");
                    battery = None;
                }
                health_id += 1;
                pending_health = Some(health_id);
                send(&mut wr, &proto::Request::call(proto::Id::Number(health_id), &proto::Call::RobotHealth)).await?;
            }
            Some(()) = stop_rx.recv() => {
                stop_id += 1;
                let stop = proto::Request::call(proto::Id::Number(stop_id), &proto::Call::RobotStop);
                send(&mut wr, &stop).await?;
                tracing::warn!(id = stop_id, "robot.stop sent (PERMIT→BLOCK transition)");
            }
        }
    }
}

async fn send(wr: &mut tokio::net::unix::OwnedWriteHalf, req: &proto::Request) -> Result<(), String> {
    let mut b = serde_json::to_vec(req).map_err(|e| e.to_string())?;
    b.push(b'\n');
    wr.write_all(&b).await.map_err(|e| e.to_string())
}

/// `robot.state` carries no battery (MD-2a measurement: the frame keys are head/joints/loop/
/// move/odom/policy/safety/t/targets — battery lives in `robot.health`). The session polls it
/// (MD-2b) and hands the last answer in here; `None` until the first answer, and back to
/// `None` when a poll goes unanswered. LLD D6: `fallen ∨ limp` → UNSAFE, else
/// `percent < floor` → WARN, else OK. Absent battery is absent — never "fine" (I-6).
pub fn map(st: &proto::RobotState, battery_floor: f64, battery_percent: Option<f64>) -> SafetyState {
    let fallen = st.safety.fallen;
    let limp = st.safety.limp;
    let picked_up=st.safety.picked_up;
    let level = if fallen || limp || picked_up {
        "UNSAFE"
    } else if matches!(battery_percent, Some(p) if p < battery_floor) {
        "WARN"
    } else {
        "OK"
    };
    let mut detail=Vec::new();
    if fallen{detail.push("fallen".to_owned())}
    if limp{detail.push("limp".to_owned())}
    if picked_up{detail.push("picked_up".to_owned())}
    if st.policy=="held"{detail.push("policy=held".to_owned())}
    for reason in st.movement.limited_by.iter().take(8){detail.push(format!("limited_by={}",reason.chars().take(80).collect::<String>()))}
    SafetyState {
        picked_up,detail,
        level,
        source: "MICRODUCK_SELF",
        observed_ms: now_ms(),
        fallen,
        limp,
        battery_percent,
        loop_hz: Some(st.control_loop.hz),
        loop_missed: Some(st.control_loop.missed),
    }
}

/// SK-5 (public skill contract, L18): the safe states this adapter can EXECUTE when a permit
/// is revoked. `stop_zero_twist` is `robot.stop` (contract ④). A registry row may
/// only name a safe state the serving adapter declares (`ADAPTERS.tsv`), and the
/// declaration is checked here against what the code can do — a declared state
/// nobody executes would be a promise with no motion behind it.
pub const EXECUTABLE_SAFE_STATES: &[&str] = &["stop_zero_twist"];

/// The one safe state this adapter declares. Refused at start (every profile) when
/// it is not one the adapter executes — "configured" and "executable" must be the
/// same word here, or the registry's `safe_state` column is fiction.
pub fn check_safe_state(declared: &str) -> Result<&'static str, String> {
    for s in EXECUTABLE_SAFE_STATES {
        if *s == declared {
            return Ok(s);
        }
    }
    Err(format!(
        "safe_state {declared:?} is not one this adapter executes ({})",
        EXECUTABLE_SAFE_STATES.join(",")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // PAIL-CASE: safe_state_declaration_checked
    /// G-ADP-14 (SK-5): the declared safe state must be executable; an unknown or
    /// empty declaration is refused by name, not defaulted.
    #[test]
    fn safe_state_declaration_checked() {
        assert_eq!(check_safe_state("stop_zero_twist"), Ok("stop_zero_twist"));
        assert!(check_safe_state("hold_position").is_err());
        assert!(check_safe_state("").is_err());
        assert!(check_safe_state("stop_zero_twist ").is_err());
    }

    /// A `robot.state` frame shaped like the fake robotd's, with timestamp, movement,
    /// head, policy, safety, loop, joint, target and odometry fields. Built through serde so a field upstream adds or
    /// renames turns this fixture red instead of drifting silently.
    fn frame(fallen: bool, limp: bool) -> proto::RobotState {
        serde_json::from_value(serde_json::json!({
            "t": 0.0,
            "move": {"requested": [0.0, 0.0, 0.0], "applied": [0.0, 0.0, 0.0], "limited_by": []},
            "head": [0.0, 0.0, 0.0, 0.0],
            "policy": "stand",
            "safety": {"fallen": fallen, "limp": limp, "gravity": [0.0, 0.0, -1.0]},
            "loop": {"hz": 50.0, "missed": 0},
            "joints": [],
            "targets": [],
            "odom": {"position": [0.0, 0.0, 0.0], "yaw": 0.0}
        }))
        .unwrap_or_else(|e| panic!("RobotState fixture: {e}"))
    }

    /// LLD D6 ladder: UNSAFE wins over battery; a low battery is WARN; absent is not WARN.
    #[test]
    fn battery_floor_ladder() {
        assert_eq!(map(&frame(false, false), 15.0, None).level, "OK");
        assert_eq!(map(&frame(false, false), 15.0, Some(14.9)).level, "WARN");
        assert_eq!(map(&frame(false, false), 15.0, Some(15.0)).level, "OK");
        assert_eq!(map(&frame(true, false), 15.0, Some(90.0)).level, "UNSAFE");
        assert_eq!(map(&frame(false, true), 15.0, Some(5.0)).level, "UNSAFE");
        assert_eq!(map(&frame(false, false), 15.0, Some(50.0)).battery_percent, Some(50.0));
        assert_eq!(map(&frame(false, false), 15.0, None).battery_percent, None);
    }
    #[test]
    fn pickup_is_unsafe_and_detail_is_bounded(){
        let mut f=frame(false,false);f.safety.picked_up=true;f.policy="held".into();
        f.movement.limited_by=vec!["x".repeat(200);20];
        let s=map(&f,15.,Some(90.));assert_eq!(s.level,"UNSAFE");
        assert!(s.detail.contains(&"picked_up".to_string()));assert!(s.detail.contains(&"policy=held".to_string()));
        assert!(s.detail.len()<=12);assert!(s.detail.iter().all(|x|x.len()<=100));
        f.safety.picked_up=false;assert_eq!(map(&f,15.,Some(90.)).level,"OK");
        // Input recovery only; GateSession's old fatal chain must remain revoked.
    }

}
