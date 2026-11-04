// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

//! `pail-duckd` — PAIL reference adapter for Microduck (LLD `public adapter contract`).
//!
//! Sits on the public robot socket, relays each client to the raw robotd socket 1:1, hands
//! every intent to the gate seam (`gate.rs`) and obeys the verdict. MD-1 landed the relay;
//! MD-2a wires the robot agent (token poll, reports, attestation), the safety and evidence
//! feeds, the stop-on-transition rule and the profile gate. The only gate in MD-2a is
//! `NoGate`, which is refused outside `PAIL_PROFILE=dev`.

mod agent;
mod core_report;
mod classify;
mod evidence;
mod gate;
#[cfg(feature = "libgate")]
mod gate_ffi;
mod relay;
mod safety;
mod skills;
mod state;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use clap::Parser;
use tokio::net::UnixListener;
use tokio::sync::{mpsc, watch};

/// Same exit code the ROS gate's preflight uses for "refused to start" (AS-7: exit 78).
const EX_REFUSED: u8 = 78;

#[derive(Parser, Debug)]
#[command(name = "pail-duckd", version, about = "PAIL adapter: interposer in front of Microduck robotd")]
struct Args {
    /// Public socket the adapter serves — where robotd used to listen (`/run/robotd.sock`).
    #[arg(long, default_value = "/run/robotd.sock")]
    public: PathBuf,

    /// Raw robotd socket the adapter forwards to (robotd is restarted with `--socket` here).
    #[arg(long, default_value = "/run/robotd/raw.sock")]
    raw: PathBuf,

    /// Numeric gid the public socket is handed to (the `robot` group on a board).
    #[arg(long, conflicts_with = "public_group")]
    public_gid: Option<u32>,
    /// Group NAME the public socket is handed to (`robot` on a board) — resolved through
    /// `getgrnam` at start, so the unit file never carries a gid that `systemd-sysusers`
    /// allocated differently on another board (MD-3). Exactly one of --public-gid/--public-group.
    #[arg(long, env = "PAIL_DUCK_PUBLIC_GROUP", conflicts_with = "public_gid")]
    public_group: Option<String>,

    /// Mode for the public socket (octal). robotd uses 0660; so do we.
    #[arg(long, default_value = "0660")]
    public_mode: String,

    /// Deployment profile. `production` is the default and the refusing one (AS-7 pattern):
    /// a non-enforcing gate or a failed S27 self-check does not start.
    #[arg(long, env = "PAIL_PROFILE", default_value = "production")]
    profile: String,

    /// PAIL robot agent endpoint: `unix:/run/pail/agent.sock` or `http://host:port` (dev).
    /// Absent = no agent (dev only): no token view, no reports, no attestation.
    #[arg(long, env = "PAIL_AGENT_ADDR")]
    agent: Option<String>,

    #[arg(long, env = "PAIL_ROBOT_ID", default_value = "robot-1")]
    robot_id: String,

    /// GetActiveToken period — the gate's `permit_recheck_ms`.
    #[arg(long, default_value_t = 100)]
    permit_recheck_ms: u64,

    #[arg(long, default_value_t = 300)]
    attest_interval_s: u64,

    /// ATTESTATION component name (EC-2 vocabulary; the adapter *is* the PEP).
    #[arg(long, default_value = "pep_gate")]
    attest_component: String,

    /// `pail-build:v1:…` string (EC-2). `-` = unknown, honestly.
    #[arg(long, env = "PAIL_BUILD_INFO", default_value = "-")]
    build_info: String,

    /// robot.state subscription rate for the safety feed.
    #[arg(long, default_value_t = 20)]
    safety_hz: u32,

    /// Battery WARN floor (percent). Not fed in MD-2a — see safety.rs.
    #[arg(long, default_value_t = 15.0)]
    battery_floor: f64,

    /// `robot.health` poll period in seconds: the battery lives there, not in
    /// `robot.state`. 0 disables the poll (battery stays absent — reported as absent).
    #[arg(long, default_value_t = 5)]
    health_poll_s: u64,

    /// Skill name table: `name → MOVE|MANIPULATE|NONE`, sealed configuration.
    /// See adapters/microduck/deploy/INSTALL.md, section 3.
    /// Production refuses to start without it (S29); dev starts with an empty table and a
    /// banner, and every named skill is then refused at judgment.
    #[arg(long, env = "PAIL_DUCK_SKILLS", default_value = "/etc/pail/duck_skills.yaml")]
    skills: PathBuf,

    /// Evidence ingress socket (NDJSON). Absent = no evidence ingress.
    #[arg(long, env = "PAIL_EVIDENCE_SOCK")]
    evidence: Option<PathBuf>,

    /// SK-5 (public skill contract): the safe state this adapter declares and executes on permit
    /// revocation (`ADAPTERS.tsv` safe_state). Must be one of `safety::EXECUTABLE_SAFE_STATES`;
    /// anything else refuses to start in every profile.
    #[arg(long, env = "PAIL_SAFE_STATE", default_value = "stop_zero_twist")]
    safe_state: String,

    /// Which gate to link: `libpail` (libpail_gate over its C ABI — the enforcing one) or
    /// `none` (MD-2a plumbing only, dev). Default `libpail` when built with `--features
    /// libgate`, otherwise `none`.
    #[arg(long, env = "PAIL_GATE")]
    gate: Option<String>,

    /// policy.yaml the gate enforces (public policy contract); refused when absent or incomplete.
    #[arg(long, env = "PAIL_POLICY", default_value = "/etc/pail/policy.yaml")]
    policy: PathBuf,

    /// Legacy keyring.json path; the trust mode comes from PAIL_KEYRING_MODE (KM2-1).
    #[arg(long, env = "PAIL_KEYRING", default_value = "/etc/pail/keys/keyring.json")]
    keyring: PathBuf,

    #[arg(long, default_value_t = 3)]
    permit_grace_n: i32,

    #[arg(long, default_value_t = 500)]
    clock_skew_ms: i64,

    /// NDJSON decision log (append). The adapter's `/pail/gate_state`: every gate outcome and
    /// every stop request, for operators and the conformance harness. Absent = no log.
    #[arg(long, env = "PAIL_GATE_LOG")]
    gate_log: Option<PathBuf>,
}

#[cfg(test)]
mod cli_help_tests {
    use super::Args;
    use clap::CommandFactory;

    #[test]
    fn generated_help_uses_public_references() {
        let mut command = Args::command();
        for help in [command.render_help().to_string(), command.render_long_help().to_string()] {
            assert!(!help.contains("LLD"), "CLI help must not refer to an unavailable design document");
            assert!(help.contains("adapters/microduck/deploy/INSTALL.md"));
        }
        let guide = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("deploy/INSTALL.md");
        let contents = std::fs::read_to_string(guide).expect("The referenced public installation guide must ship");
        assert!(contents.lines().any(|line| line.starts_with("## 3. ")));
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        // RUST_LOG wins when set; "info" is only the fallback (an added directive would
        // cap RUST_LOG=debug at info — measured in MD-1, the debug lines never appeared).
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();
    let args = Args::parse();
    let production = match args.profile.as_str() {
        "production" => true,
        "dev" => false,
        other => {
            tracing::error!(profile = other, "PAIL_PROFILE must be production|dev");
            return ExitCode::from(2);
        }
    };
    let mode = match u32::from_str_radix(args.public_mode.trim_start_matches("0o"), 8) {
        Ok(m) => m,
        Err(_) => {
            tracing::error!(mode = args.public_mode, "--public-mode is not octal");
            return ExitCode::from(2);
        }
    };

    // ---- safe state declaration (SK-5, public skill contract; G-ADP-14) --------------------------------
    match safety::check_safe_state(&args.safe_state) {
        Ok(s) => tracing::info!(safe_state = s, executes_as = "robot.stop", "PAIL PREFLIGHT: safe_state declared"),
        Err(why) => {
            tracing::error!(%why, "STARTUP REFUSED: safe_state declaration is not executable by this adapter");
            return ExitCode::from(78);
        }
    }

    // ---- skill name table (LLD §3.1; S29) --------------------------------------------------
    let skill_table = match skills::SkillTable::load(&args.skills) {
        Ok(t) => {
            tracing::info!(path = %args.skills.display(), entries = t.len(), "skill table loaded");
            t
        }
        Err(e) if e.contains("No such file") || e.contains("os error 2") => {
            if production {
                tracing::error!(path = %args.skills.display(), "STARTUP REFUSED: S29 skill name table missing — every robot.do would be unmapped");
                return ExitCode::from(78);
            }
            tracing::warn!(path = %args.skills.display(), "S29 skill name table missing (dev: every named skill is refused at judgment)");
            skills::SkillTable::default()
        }
        Err(e) => {
            // An invalid table is a refusal in every profile (like the requester registry):
            // "could not read" must not become "nothing mapped" silently.
            tracing::error!(error = %e, "STARTUP REFUSED: S29 skill name table invalid");
            return ExitCode::from(78);
        }
    };

    // ---- gate ---------------------------------------------------------------------------
    let gate_choice = args.gate.clone().unwrap_or_else(|| if cfg!(feature = "libgate") { "libpail".to_owned() } else { "none".to_owned() });
    let gate_impl: Arc<dyn gate::Gate> = match gate_choice.as_str() {
        "none" => Arc::new(gate::NoGate),
        "libpail" => {
            #[cfg(feature = "libgate")]
            {
                match gate_ffi::LibGate::new(&args.robot_id, &args.policy.to_string_lossy(), &args.keyring.to_string_lossy(), args.permit_grace_n, args.clock_skew_ms, "") {
                    Ok(g) => Arc::new(g),
                    Err(e) => {
                        // The library's refusals are the gate node's preflight vocabulary
                        // (POLICY_ABSENT, POLICY_INCOMPLETE, …); same exit code as the node.
                        tracing::error!(error = %e, "STARTUP REFUSED: libpail_gate did not open a session");
                        return ExitCode::from(EX_REFUSED);
                    }
                }
            }
            #[cfg(not(feature = "libgate"))]
            {
                tracing::error!("STARTUP REFUSED: --gate libpail requires a build with --features libgate");
                return ExitCode::from(EX_REFUSED);
            }
        }
        other => {
            tracing::error!(gate = other, "--gate must be libpail|none");
            return ExitCode::from(2);
        }
    };
    if gate_impl.enforces() {
        tracing::info!(gate = gate_impl.name(), mode = gate_impl.effective_mode(), "GATE");
        if gate_impl.effective_mode() == "observe" {
            tracing::warn!("gate_mode=observe: decisions are verified and recorded but NOT enforced; motion is not gated (observe-mode contract)");
        }
    } else {
        tracing::warn!(gate = gate_impl.name(), "GATE");
    }
    if production && !gate_impl.enforces() {
        tracing::error!("STARTUP REFUSED: S28 no enforcing gate linked — production may not front a robot without one");
        return ExitCode::from(EX_REFUSED);
    }

    // ---- S27 (contract I-1) ---------------------------------------------------------------
    match self_check_raw(&args.raw) {
        RawCheck::Verified { gid, mode } => tracing::info!(gid, mode = format!("{mode:o}"), "S27 verified: raw socket closed to others"),
        RawCheck::Unverified(why) => tracing::warn!(%why, "S27 unverified"),
        RawCheck::Failed(why) => {
            if production {
                tracing::error!(%why, "STARTUP REFUSED: S27 raw ingress reachable by others");
                return ExitCode::from(EX_REFUSED);
            }
            tracing::warn!(%why, "S27 FAILED (dev: reported only)");
        }
    }

    // ---- agent (contract ⑤) ---------------------------------------------------------------
    let (agent_opt, feeds_token, report_healthy) = match &args.agent {
        Some(ep) => match agent::Agent::new(ep, &args.robot_id).await {
            Ok((a, h)) => {
                tracing::info!(endpoint = a.endpoint(), robot_id = args.robot_id, "agent connected");
                tokio::spawn(a.clone().token_loop(Duration::from_millis(args.permit_recheck_ms)));
                tokio::spawn(a.clone().attest_loop(
                    args.attest_component.clone(),
                    args.build_info.clone(),
                    Duration::from_secs(args.attest_interval_s),
                ));
                (Some(a), h.token_rx, h.report_healthy)
            }
            Err(e) => {
                // No agent = no tokens = nothing can be permitted by an enforcing gate. The
                // relay would forward nothing; better to say so and exit than to sit deaf.
                tracing::error!(error = %e, endpoint = ep, "STARTUP REFUSED: agent unreachable");
                return ExitCode::from(EX_REFUSED);
            }
        },
        None => {
            if production {
                tracing::error!("STARTUP REFUSED: no --agent in production");
                return ExitCode::from(EX_REFUSED);
            }
            tracing::warn!("no agent configured (dev): no token view, no reports, no attestation");
            let (tx, rx) = watch::channel(agent::TokenView::default());
            // Keep the sender alive for the process lifetime so the receiver never errors.
            std::mem::forget(tx);
            (None, rx, Arc::new(AtomicBool::new(true)))
        }
    };

    // ---- safety feed + stop channel (contract ③/④, LLD D5·§6.1) ----------------------------
    let (safety_tx, safety_rx) = watch::channel(None);
    let (stop_tx, stop_rx) = mpsc::channel(8);
    tokio::spawn(safety::run(
        safety::SafetyConfig {
            raw: args.raw.clone(),
            hz: args.safety_hz,
            battery_floor: args.battery_floor,
            health_poll: Duration::from_secs(args.health_poll_s),
            skills: skill_table.clone(),
            production,
        },
        safety_tx,
        stop_rx,
    ));

    // ---- evidence feed (LLD §6.2) ----------------------------------------------------------
    let (evidence_tx, evidence_rx) = watch::channel(None);
    if let Some(p) = &args.evidence {
        tokio::spawn(evidence::run(p.clone(), evidence_tx));
    } else {
        tracing::warn!("no evidence ingress configured");
        std::mem::forget(evidence_tx);
    }

    // ---- public socket takeover -------------------------------------------------------------
    if args.public.exists() {
        if let Err(e) = std::fs::remove_file(&args.public) {
            tracing::error!(error = %e, path = %args.public.display(), "cannot remove stale public socket");
            return ExitCode::from(1);
        }
    }
    let listener = match UnixListener::bind(&args.public) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, path = %args.public.display(), "bind failed");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = std::fs::set_permissions(&args.public, std::fs::Permissions::from_mode(mode)) {
        tracing::error!(error = %e, "chmod public socket failed");
        return ExitCode::from(1);
    }
    let public_gid = match (&args.public_gid, &args.public_group) {
        (Some(g), _) => Some(*g),
        (None, Some(name)) => match resolve_group(name) {
            Some(g) => {
                tracing::info!(group = name, gid = g, "public socket group resolved");
                Some(g)
            }
            None => {
                tracing::error!(group = name, "STARTUP REFUSED: --public-group names no group on this host (systemd-sysusers robot.conf not applied?)");
                return ExitCode::from(78);
            }
        },
        (None, None) => None,
    };
    if let Some(gid) = public_gid {
        let c = std::ffi::CString::new(args.public.to_string_lossy().as_bytes()).expect("path has no NUL");
        // SAFETY: plain libc call with a valid NUL-terminated path; -1 uid = unchanged.
        let rc = unsafe { libc::chown(c.as_ptr(), u32::MAX, gid) };
        if rc != 0 {
            tracing::error!(gid, error = %std::io::Error::last_os_error(), "chown public socket failed");
            return ExitCode::from(1);
        }
    }
    tracing::info!(public = %args.public.display(), raw = %args.raw.display(), mode = format!("{mode:o}"), profile = args.profile, "serving");

    let gate_log = match &args.gate_log {
        Some(p) => match std::fs::OpenOptions::new().create(true).append(true).open(p) {
            Ok(f) => {
                tracing::info!(path = %p.display(), "gate log open");
                Some(f)
            }
            Err(e) => {
                tracing::error!(error = %e, path = %p.display(), "cannot open gate log");
                return ExitCode::from(1);
            }
        },
        None => None,
    };
    let shared = Arc::new(state::Shared::new(
        gate_impl,
        agent_opt,
        state::Feeds { token: feeds_token, safety: safety_rx, evidence: evidence_rx, report_healthy },
        stop_tx,
        args.robot_id.clone(),
        gate_log,
        skill_table,
    ));
    tokio::spawn(state::tick_loop(shared.clone(), Duration::from_millis(args.permit_recheck_ms)));
    tokio::spawn(state::feed_loop(shared.clone()));
    let raw = Arc::new(args.raw.clone());
    let accept = async {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let raw = raw.clone();
                    let shared = shared.clone();
                    tokio::spawn(async move { relay::serve(stream, &raw, shared).await });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    };

    // Periodic one-line status so a log reader can tell "idle" from "dead" and see the feeds.
    let status = {
        let shared = shared.clone();
        async move {
            let mut tick = tokio::time::interval(Duration::from_secs(10));
            loop {
                tick.tick().await;
                let tok = shared.feeds.token.borrow().clone();
                let saf = shared.feeds.safety.borrow().clone();
                let ev = shared.feeds.evidence.borrow().clone();
                tracing::info!(
                    token = tok.status_name(),
                    token_age_ms = if tok.fetched_ms > 0 { agent::now_ms() - tok.fetched_ms } else { -1 },
                    safety = saf.as_ref().map(|s| s.level).unwrap_or("ABSENT"),
                    safety_age_ms = saf.as_ref().map(|s| agent::now_ms() - s.observed_ms).unwrap_or(-1),
                    evidence = ev.as_ref().map(|e| e.source.as_str()).unwrap_or("ABSENT"),
                    judged = shared.judged_total(),
                    dropped = shared.dropped_total(),
                    reported = shared.reported_total(),
                    stops = shared.stops_sent(),
                    "status"
                );
            }
        }
    };

    tokio::select! {
        _ = accept => {}
        _ = status => {}
        _ = tokio::signal::ctrl_c() => tracing::info!("SIGINT"),
        _ = sigterm() => tracing::info!("SIGTERM"),
    }
    let _ = std::fs::remove_file(&args.public);
    tracing::info!(judged_total = shared.judged_total(), dropped = shared.dropped_total(), reported = shared.reported_total(), stops = shared.stops_sent(), release = ?shared.release(), "stopped");
    ExitCode::SUCCESS
}

async fn sigterm() {
    use tokio::signal::unix::{SignalKind, signal};
    match signal(SignalKind::terminate()) {
        Ok(mut s) => {
            s.recv().await;
        }
        Err(_) => std::future::pending::<()>().await,
    }
}

/// `getgrnam(3)`: the gid of a group name, `None` when the host has no such group. Not
/// thread-safe by contract, called once at start before any task is spawned.
fn resolve_group(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: valid NUL-terminated name; the returned pointer is read immediately and not kept.
    let g = unsafe { libc::getgrnam(c.as_ptr()) };
    if g.is_null() {
        None
    } else {
        Some(unsafe { (*g).gr_gid })
    }
}

enum RawCheck {
    Verified { gid: u32, mode: u32 },
    Unverified(String),
    Failed(String),
}

/// LLD §5: the raw socket must be closed to "others" (mode & 0o007 == 0) and its directory too;
/// the group is whatever the drop-in set (`pail`). What we can *see* from here is mode and gid;
/// membership of the requester's uid in that gid is the harness's CB-1 probe, not ours.
fn self_check_raw(raw: &std::path::Path) -> RawCheck {
    use std::os::unix::fs::MetadataExt;
    let meta = match std::fs::metadata(raw) {
        Ok(m) => m,
        Err(e) => return RawCheck::Unverified(format!("raw socket not present yet: {e}")),
    };
    let mode = meta.mode() & 0o777;
    if mode & 0o007 != 0 {
        return RawCheck::Failed(format!("raw socket mode {mode:o} is open to others"));
    }
    if let Some(dir) = raw.parent() {
        match std::fs::metadata(dir) {
            Ok(d) if d.mode() & 0o007 != 0 => {
                return RawCheck::Failed(format!("raw socket directory mode {:o} is open to others", d.mode() & 0o777));
            }
            Ok(_) => {}
            Err(e) => return RawCheck::Unverified(format!("raw socket directory unreadable: {e}")),
        }
    }
    RawCheck::Verified { gid: meta.gid(), mode }
}

/// G-ADP-08 (contract I-1, `S27`): the self-check has three values, and each has exactly one
/// shape that produces it — closed to others = verified, absent/unreadable = unverified (a
/// report, never a pass), open to others = failed (production refuses to start).
#[cfg(test)]
mod s27_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn rig(dir_mode: u32, sock_mode: u32) -> (tempfile_dir::Dir, std::path::PathBuf) {
        let d = tempfile_dir::Dir::new();
        let raw = d.path().join("raw.sock");
        std::os::unix::net::UnixListener::bind(&raw).unwrap();
        std::fs::set_permissions(&raw, std::fs::Permissions::from_mode(sock_mode)).unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(dir_mode)).unwrap();
        (d, raw)
    }

    #[test]
    fn s27_three_values() {
        let (_d, raw) = rig(0o750, 0o660);
        assert!(matches!(self_check_raw(&raw), RawCheck::Verified { mode: 0o660, .. }));

        let (_d, raw) = rig(0o750, 0o666);
        assert!(matches!(self_check_raw(&raw), RawCheck::Failed(ref why) if why.contains("socket mode")));

        let (_d, raw) = rig(0o755, 0o660);
        assert!(matches!(self_check_raw(&raw), RawCheck::Failed(ref why) if why.contains("directory mode")));

        let d = tempfile_dir::Dir::new();
        let missing = d.path().join("raw.sock");
        assert!(matches!(self_check_raw(&missing), RawCheck::Unverified(ref why) if why.contains("not present")));
    }

    /// A tiny unique temp dir without a crate: removed on drop, so a failed assertion does not
    /// leave world-readable sockets around for the next run to "verify".
    mod tempfile_dir {
        pub struct Dir(std::path::PathBuf);
        impl Dir {
            pub fn new() -> Dir {
                let p = std::env::temp_dir().join(format!(
                    "pail-s27-{}-{}",
                    std::process::id(),
                    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
                ));
                std::fs::create_dir_all(&p).unwrap();
                Dir(p)
            }
            pub fn path(&self) -> &std::path::Path {
                &self.0
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        use std::os::unix::fs::PermissionsExt;
    }
}
