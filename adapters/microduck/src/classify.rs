// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

//! Method → treatment table (LLD §3). The single place where "what does this message mean to
//! PAIL" is decided.
//!
//! The match on [`proto::Call`] is **exhaustive on purpose** — no `_ =>` arm. When upstream adds
//! a method, this file stops compiling, which is the bidirectional check of LLD D3 done by the
//! compiler rather than by a test that could go stale. Anything not on this socket (update.*,
//! policy.*, account.*, net.*, system.*, pad.* except the two robotd serves, tof.*, the chorale
//! peer notifications) is `Reject`: robotd itself answers those with METHOD_NOT_FOUND
//! ("… is not served by robotd", `robotd/src/main.rs` dispatch @942e58e), and the adapter must
//! never forward more than robotd would accept.

use duck_ipc_proto as proto;

/// PAIL action class the intent maps to (`pail.v1.ActionType` names).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionClass {
    Move,
    /// Reached only through the skill-name table (MD-2); no upstream method maps to it directly.
    #[allow(dead_code)]
    Manipulate,
    Actuate,
    /// Posture / expression — not locomotion, not manipulation, not a state change. A token
    /// must still cover it (LLD §3: "표현은 자유" would let a tokenless session touch the robot).
    None,
}

/// What the adapter does with one client → robotd message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// Forward unjudged, record. Queries, subscriptions, the handshake, and `robot.stop`.
    Pass,
    /// Metadata note: local audit only, not a blackbox authorization verdict.
    PassRecorded,
    /// `robot.stop` — always forwarded, but reported as a decision so the ledger says who stopped.
    Stop,
    /// Judge against the active token before forwarding.
    Judge(ActionClass),
    /// `robot.do { skill }` — the skill is a *name* (upstream `Skill = String`, not an enum), so
    /// its class comes from a per-deployment name table at judgment time. An unnamed skill is
    /// refused there, never defaulted.
    JudgeSkill(String),
    /// Not this socket. Answered with METHOD_NOT_FOUND on the client side, never forwarded.
    Reject,
}

pub fn classify(call: &proto::Call) -> Kind {
    use proto::Call as C;
    match call {
        // ── handshake · queries · subscriptions (served by robotd, no robot state changed) ──
        C::Hello(_)
        | C::RobotHealth
        | C::RobotModelApi
        | C::RobotMode
        | C::RobotPolicies
        | C::RobotSafeToRestart
        | C::RobotRemoteSessionActive
        | C::RobotSubscribe(_)
        | C::RobotSkills
        | C::PadBindings
        | C::ChoraleSubscribe
        | C::RobotModel | C::RobotVetbook | C::RobotVetbookTally(_) => Kind::Pass,

        C::RobotVetbookNote(_) => Kind::PassRecorded,

        // ── stop is the safe direction; still a decision on the record ──
        C::RobotStop => Kind::Stop,

        // ── locomotion ──
        C::RobotMove(_) => Kind::Judge(ActionClass::Move),

        // ── posture / expression ──
        C::RobotHead(_)
        | C::RobotLook(_)
        | C::RobotPose(_)
        | C::RobotMouth(_)
        | C::RobotSound(_)
        | C::RobotTheremin(_)
        | C::RobotChorale(_) | C::RobotFlashlight(_) => Kind::Judge(ActionClass::None),

        // ── named skill network ──
        C::RobotDo(p) => Kind::JudgeSkill(p.skill.clone()),

        // ── power · posture state · policy (gait network) · skill list · pad binding ──
        C::RobotRest | C::RobotRebootMotors(_) | C::RobotEnable(_)
        | C::RobotInit
        | C::RobotRelax
        | C::RobotSetMode(_)
        | C::RobotLoadPolicy(_)
        | C::RobotReloadPolicies
        | C::RobotShutdown
        | C::RobotSetSkill(_)
        | C::RobotRemoveSkill(_)
        | C::PadBind(_) => Kind::Judge(ActionClass::Actuate),

        // ── unsupported adapter routes (includes intentionally excluded head IMU stream) ──
        C::Check(_)
        | C::Apply(_)
        | C::Rollback(_)
        | C::ResetToGolden(_)
        | C::Select(_)
        | C::Pin(_)
        | C::Status
        | C::ListInstalled(_)
        | C::Log(_)
        | C::Show(_)
        | C::Subscribe
        | C::ChoraleBeaconSet(_)
        | C::ChoraleHeard(_)
        | C::PolicyCheck
        | C::PolicyInstall(_)
        | C::PolicyFetch(_)
        | C::PolicySearch(_)
        | C::AccountLogin(_)
        | C::AccountStatus
        | C::AccountLogout
        | C::NetStatus
        | C::NetScan
        | C::NetConnect(_)
        | C::NetForget(_)
        | C::SystemInfo
        | C::SystemServices
        | C::SystemSetName(_)
        | C::SystemReboot
        | C::SystemPairingPin
        | C::SystemSetPairingPin(_)
        | C::SystemAuthenticate(_)
        | C::PadStatus
        | C::PadPair(_)
        | C::PadForget(_)
        | C::PadInput
        | C::TofStream | C::HeadImuStream | C::DetectorCheck | C::DetectorInstall(_)
        | C::SystemLogs(_) | C::VetbookShare => Kind::Reject,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Pinned robotd service vocabulary, including pre-dispatch streaming.
    /// head_imu.stream is served upstream but deliberately outside adapter-v2
    /// support. This exception must remain explicit, not mistaken for a daemon
    /// method-not-found response.
    const ROBOTD_SERVED: &[&str] = &[
        "head_imu.stream",
        "robot.model", "robot.vetbook", "robot.vetbookTally", "robot.vetbookNote",
        "robot.flashlight", "robot.rest", "robot.rebootMotors",
        "hello",
        "chorale.subscribe",
        "pad.bind",
        "pad.bindings",
        "robot.chorale",
        "robot.do",
        "robot.enable",
        "robot.head",
        "robot.health",
        "robot.init",
        "robot.loadPolicy",
        "robot.look",
        "robot.mode",
        "robot.modelApi",
        "robot.mouth",
        "robot.move",
        "robot.policies",
        "robot.pose",
        "robot.relax",
        "robot.reloadPolicies",
        "robot.remoteSessionActive",
        "robot.removeSkill",
        "robot.safeToRestart",
        "robot.setMode",
        "robot.setSkill",
        "robot.shutdown",
        "robot.skills",
        "robot.sound",
        "robot.stop",
        "robot.subscribe",
        "robot.theremin",
    ];

    fn call(method: &str, params: serde_json::Value) -> proto::Call {
        let req = proto::Request {
            jsonrpc: proto::JSONRPC_VERSION.to_owned(),
            id: Some(proto::Id::Number(1)),
            method: method.to_owned(),
            params: Some(params),
        };
        req.as_call().unwrap_or_else(|e| panic!("{method}: {e:?}"))
    }

    #[test]
    fn served_methods_are_never_rejected() {
        assert!(!ROBOTD_SERVED.is_empty());
        for m in ROBOTD_SERVED {
            let params = match *m {
                "robot.vetbookTally" => json!({"tallies":{},"highs":{},"lows":{}}),
                "robot.vetbookNote" => json!({"text":"fixture note"}),
                "robot.flashlight" => json!({"on":true}),
                "robot.rebootMotors" => json!({"ids":[]}),
                "hello" => json!({"api_version": proto::API_VERSION}),
                "robot.move" => json!({"vx": 0.0, "vy": 0.0, "vyaw": 0.0}),
                "robot.do" => json!({"skill": "dance"}),
                "robot.enable" => json!({"on": true}),
                "robot.setMode" => json!({"mode": "walk"}),
                "robot.setSkill" => json!({"name": "x", "path": "/tmp/x.onnx"}),
                "robot.removeSkill" => json!({"name": "x"}),
                "pad.bind" => json!({"button": "a"}),
                "robot.sound" => json!({"tag": "greet"}),
                "robot.chorale" => json!({"active": true}),
                "robot.theremin" => json!({"active": true}),
                "robot.mouth" => json!({"open": 0.0}),
                "robot.look" => json!({"x": 1.0, "y": 0.0, "z": 0.0, "neck_pitch": 0.0}),
                _ => json!({}),
            };
            let c = match (proto::Request {
                jsonrpc: proto::JSONRPC_VERSION.to_owned(),
                id: Some(proto::Id::Number(1)),
                method: (*m).to_owned(),
                params: Some(params),
            })
            .as_call()
            {
                Ok(c) => c,
                // Parameter shapes are upstream's business; what this test pins is the
                // *method* row, so a params mismatch is reported, not silently skipped.
                Err(e) => panic!("{m}: params fixture no longer matches upstream: {e:?}"),
            };
            if *m == "head_imu.stream" {
                assert_eq!(classify(&c),Kind::Reject,"new sensor streaming is explicitly unsupported in adapter v2");
            } else {
                assert_ne!(classify(&c), Kind::Reject, "{m} is served by robotd but rejected here");
            }
        }
    }

    #[test]
    fn move_is_move_and_stop_is_stop() {
        assert_eq!(
            classify(&call("robot.move", json!({"vx": 0.1, "vy": 0.0, "vyaw": 0.0}))),
            Kind::Judge(ActionClass::Move)
        );
        assert_eq!(classify(&call("robot.stop", json!({}))), Kind::Stop);
        assert_eq!(
            classify(&call("robot.do", json!({"skill": "wave"}))),
            Kind::JudgeSkill("wave".into())
        );
    }

    #[test]
    fn other_sockets_are_rejected() {
        for m in ["update.status", "net.status", "system.info", "account.status", "pad.status"] {
            assert_eq!(classify(&call(m, json!({}))), Kind::Reject, "{m}");
        }
    }
    #[test]
    fn new_0178_treatments_are_explicit() {
        assert_eq!(ROBOTD_SERVED.len(),39);
        assert_eq!(classify(&call("robot.rest",json!({}))),Kind::Judge(ActionClass::Actuate));
        assert_eq!(classify(&call("robot.rebootMotors",json!({"ids":[]}))),Kind::Judge(ActionClass::Actuate));
        assert_eq!(classify(&call("robot.flashlight",json!({"on":true}))),Kind::Judge(ActionClass::None));
        assert_eq!(classify(&call("robot.vetbookNote",json!({"text":"private note"}))),Kind::PassRecorded);
        for method in ["head_imu.stream","detector.check","vetbook.share"]{
            assert_eq!(classify(&call(method,json!({}))),Kind::Reject);
        }
    }

}
