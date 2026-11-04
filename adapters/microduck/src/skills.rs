// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

//! Skill name table (LLD §3.1). Upstream `Skill` is a `String` and the list arrives at run time
//! (`robot.skills`, `.onnx` networks added with `setSkill`), so an enum comparison cannot exist.
//! A per-deployment table maps `name → MOVE | MANIPULATE | NONE`; a skill the table does not
//! name is refused at judgment (`ERR_ACTION_UNMAPPED`, `gate_ffi.rs`) — there is no default
//! class. The table is sealed configuration: an empty table is a refusal (`∅` would make every
//! skill unmapped and read as "nothing to judge"), and in production a missing table is S29.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use duck_ipc_proto as proto;

use crate::classify::ActionClass;

/// SK-2 (public skill contract): a skill's declared envelope, learned from the robot's own
/// `robot.skills` answer at connect. `duration` and `command` are the daemon's numbers for
/// that skill; the twist it feeds the network is what the gate compares against the token
/// (sls.linear_mps / sls.angular_rps), and the duration rides as step.max_duration_s.
/// A built-in (no row in the answer's table) is driven by the daemon itself with no twist —
/// measured as zero speed, which is its declared truth, not an unmeasured blank.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct SkillEnvelope {
    pub duration_s: Option<f64>,
    pub linear_mps: f64,
    pub angular_rps: f64,
}

impl SkillEnvelope {
    pub fn from_params(p: &proto::SkillParams) -> SkillEnvelope {
        let (lin, ang) = match p.command {
            Some([vx, vy, vyaw]) => ((vx * vx + vy * vy).sqrt(), vyaw.abs()),
            None => (0.0, 0.0),
        };
        SkillEnvelope { duration_s: p.duration, linear_mps: lin, angular_rps: ang }
    }
    /// The measured map the gate compares (GUARDRAILS.tsv names).
    pub fn measured(&self) -> BTreeMap<String, f64> {
        let mut m = BTreeMap::new();
        m.insert("sls.linear_mps".to_owned(), self.linear_mps);
        m.insert("sls.angular_rps".to_owned(), self.angular_rps);
        if let Some(d) = self.duration_s {
            m.insert("step.max_duration_s".to_owned(), d);
        }
        m
    }
}

#[derive(Debug, Clone, Default)]
pub struct SkillTable {
    classes: BTreeMap<String, ActionClass>,
    /// Learned at connect (`learn`), shared across clones — the safety task learns, the relay
    /// judges. Empty until the robot answered: a skill judged before that carries no measured
    /// map and the library derives zero speed from the norms (same as before SK-2).
    envelopes: Arc<Mutex<BTreeMap<String, SkillEnvelope>>>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileShape {
    version: u32,
    skills: BTreeMap<String, String>,
}

impl SkillTable {
    /// Parse the YAML text. Strict: version 1, known fields only, a closed class vocabulary,
    /// at least one entry.
    pub fn parse(text: &str) -> Result<SkillTable, String> {
        let f: FileShape = serde_yaml::from_str(text).map_err(|e| format!("duck_skills: {e}"))?;
        if f.version != 1 {
            return Err(format!("duck_skills: unsupported version {} (want 1)", f.version));
        }
        if f.skills.is_empty() {
            return Err("duck_skills: no entries — an empty table makes every skill unmapped; delete the file instead if that is the intent".into());
        }
        let mut classes = BTreeMap::new();
        for (name, class) in f.skills {
            if name.trim().is_empty() {
                return Err("duck_skills: empty skill name".into());
            }
            let c = match class.as_str() {
                "MOVE" => ActionClass::Move,
                "MANIPULATE" => ActionClass::Manipulate,
                "NONE" => ActionClass::None,
                other => return Err(format!("duck_skills[{name}]: unknown class {other:?} (want MOVE|MANIPULATE|NONE)")),
            };
            classes.insert(name, c);
        }
        Ok(SkillTable { classes, envelopes: Arc::default() })
    }

    pub fn load(path: &Path) -> Result<SkillTable, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("duck_skills: {}: {e}", path.display()))?;
        SkillTable::parse(&text)
    }

    pub fn class_of(&self, skill: &str) -> Option<ActionClass> {
        self.classes.get(skill).copied()
    }
    /// SK-2: record what the robot answered. Table rows come from the answer's `skills`
    /// (with their numbers) and `built_in` (zero twist, no duration).
    pub fn learn(&self, answer: &proto::SkillsResult) {
        let mut env = self.envelopes.lock().expect("envelopes lock");
        env.clear();
        for p in &answer.skills {
            env.insert(p.name.clone(), SkillEnvelope::from_params(p));
        }
        for b in &answer.built_in {
            env.entry(b.clone()).or_default();
        }
    }
    pub fn envelope_of(&self, skill: &str) -> Option<SkillEnvelope> {
        self.envelopes.lock().expect("envelopes lock").get(skill).copied()
    }
    pub fn learned(&self) -> usize {
        self.envelopes.lock().expect("envelopes lock").len()
    }
    /// SK-2 (S33, the Microduck side): names this table maps that the robot does not answer
    /// to. A token could then carry an envelope for a skill this robot cannot run — refused at
    /// start in production, a banner in dev.
    pub fn not_on_robot<'a>(&self, robot_skills: impl IntoIterator<Item = &'a str>) -> Vec<String> {
        let have: std::collections::BTreeSet<&str> = robot_skills.into_iter().collect();
        self.classes.keys().filter(|n| !have.contains(n.as_str())).cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.classes.len()
    }

    /// LLD §3.1: the names the robot actually answers to (`robot.skills`, built-ins included)
    /// that the table does not map. Reported as a banner — not a refusal, the refusal happens
    /// per intent — so an operator sees the gap before the first `robot.do`.
    pub fn unmapped<'a>(&self, robot_skills: impl IntoIterator<Item = &'a str>) -> Vec<String> {
        robot_skills.into_iter().filter(|s| !self.classes.contains_key(*s)).map(str::to_owned).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_closed_vocabulary_and_maps() {
        let t = SkillTable::parse("version: 1\nskills:\n  wave: NONE\n  walk: MOVE\n  ground_pick: MANIPULATE\n").unwrap();
        assert_eq!(t.len(), 3);
        assert_eq!(t.class_of("walk"), Some(ActionClass::Move));
        assert_eq!(t.class_of("ground_pick"), Some(ActionClass::Manipulate));
        assert_eq!(t.class_of("wave"), Some(ActionClass::None));
        assert_eq!(t.class_of("dance"), None);
        assert_eq!(t.unmapped(["wave", "dance", "sit_toggle"]), vec!["dance".to_string(), "sit_toggle".to_string()]);
    }

    #[test]
    fn learns_envelopes_and_measures_by_name() {
        let t = SkillTable::parse("version: 1\nskills:\n  dash: MOVE\n  roulade: MOVE\n  ground_pick: MANIPULATE\n  ghost: NONE\n").unwrap();
        assert!(t.envelope_of("dash").is_none(), "nothing learned yet");
        let answer = proto::SkillsResult {
            skills: vec![
                proto::SkillParams { name: "dash".into(), duration: Some(2.0), command: Some([1.5, 0.0, 0.3]), ..Default::default() },
                proto::SkillParams { name: "roulade".into(), duration: Some(4.0), command: None, ..Default::default() },
            ],
            built_in: vec!["ground_pick".into()],
        };
        t.learn(&answer);
        let m = t.envelope_of("dash").unwrap().measured();
        assert_eq!(m["sls.linear_mps"], 1.5);
        assert_eq!(m["sls.angular_rps"], 0.3);
        assert_eq!(m["step.max_duration_s"], 2.0);
        let r = t.envelope_of("roulade").unwrap().measured();
        assert_eq!(r["sls.linear_mps"], 0.0);
        let g = t.envelope_of("ground_pick").unwrap();
        assert_eq!(g, SkillEnvelope::default(), "a built-in is zero twist, no duration");
        assert_eq!(t.not_on_robot(["dash", "roulade", "ground_pick"]), vec!["ghost".to_string()]);
        // a clone shares what was learned (the relay judges on the safety task's answer)
        let c = t.clone();
        assert!(c.envelope_of("dash").is_some());
    }

    #[test]
    fn empty_table_is_refused_not_quiet() {
        let e = SkillTable::parse("version: 1\nskills: {}\n").unwrap_err();
        assert!(e.contains("no entries"), "{e}");
    }

    #[test]
    fn unknown_class_word_and_field_are_refused() {
        assert!(SkillTable::parse("version: 1\nskills:\n  walk: RUN\n").unwrap_err().contains("unknown class"));
        assert!(SkillTable::parse("version: 1\nskills:\n  walk: MOVE\nextra: 1\n").is_err());
        assert!(SkillTable::parse("version: 2\nskills:\n  walk: MOVE\n").unwrap_err().contains("version"));
    }
}
