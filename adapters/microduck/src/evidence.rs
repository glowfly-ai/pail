// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

//! Evidence ingress (contract ③, LLD §6.2): one local NDJSON socket that any of the three
//! sources (upstream NFC event, a separate daemon, our own reader) can write to:
//!
//!     {"source":"NFC","object_id":"04:a3:…","confidence":1.0,"t":1757100000000}
//!
//! The adapter keeps the source string and the value as given. Trust rank is the policy's
//! business (SDK), never assigned here.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::watch;

use crate::agent::now_ms;

#[derive(Debug, Clone, PartialEq)]
pub struct EvidenceSnapshot {
    pub source: String,
    pub object_id: String,
    pub confidence: f64,
    /// Sender's timestamp, kept for the record; `received_ms` is what freshness is judged on.
    pub t: Option<i64>,
    pub received_ms: i64,
}

#[derive(serde::Deserialize)]
struct Wire {
    source: String,
    object_id: String,
    confidence: f64,
    #[serde(default)]
    t: Option<i64>,
}

pub async fn run(path: PathBuf, tx: watch::Sender<Option<EvidenceSnapshot>>) {
    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }
    let listener = match UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, path = %path.display(), "evidence socket bind failed; no evidence ingress");
            return;
        }
    };
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660));
    tracing::info!(path = %path.display(), "evidence ingress listening");
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "evidence accept failed");
                continue;
            }
        };
        let tx = tx.clone();
        tokio::spawn(async move {
            let peer = stream.peer_cred().ok().map(|c| c.uid());
            let mut rd = BufReader::new(stream);
            let mut line = String::new();
            loop {
                line.clear();
                match rd.read_line(&mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
                match serde_json::from_str::<Wire>(line.trim()) {
                    Ok(w) => {
                        let snap = EvidenceSnapshot {
                            source: w.source,
                            object_id: w.object_id,
                            confidence: w.confidence,
                            t: w.t,
                            received_ms: now_ms(),
                        };
                        tracing::info!(?peer, source = snap.source, object_id = snap.object_id, confidence = snap.confidence, "evidence");
                        let _ = tx.send(Some(snap));
                    }
                    Err(e) => tracing::warn!(?peer, error = %e, "evidence line did not parse; ignored"),
                }
            }
        });
    }
}
