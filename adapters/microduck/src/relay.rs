// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

//! One client connection ↔ one upstream connection (LLD D4). Lines are NDJSON; a forwarded
//! line is written **byte for byte** (contract I-3) — the adapter never re-serialises what it
//! lets through.

use std::path::Path;
use std::sync::Arc;

use duck_ipc_proto as proto;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::OwnedWriteHalf;
use tokio::sync::Mutex;

use crate::classify::{Kind, classify};
use crate::state::{Peer, Shared};

/// Serve one accepted client until either side closes. Never returns an error to the caller:
/// a connection's failure is logged and the client is closed — fail-closed, nothing falls
/// through to robotd.
pub async fn serve(client: UnixStream, raw: &Path, shared: Arc<Shared>) {
    let peer = match client.peer_cred() {
        Ok(c) => Peer { uid: c.uid(), gid: c.gid(), pid: c.pid() },
        Err(e) => {
            // No identity, no service. An unidentified requester is not "requester unknown",
            // it is a socket we cannot vouch for (LLD D7).
            tracing::warn!(error = %e, "SO_PEERCRED failed; closing client");
            return;
        }
    };
    let conn = shared.next_conn();
    tracing::info!(conn, uid = peer.uid, gid = peer.gid, pid = ?peer.pid, "client connected");

    let upstream = match UnixStream::connect(raw).await {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(conn, error = %e, raw = %raw.display(), "upstream connect failed; closing client");
            return;
        }
    };

    let (c_rd, c_wr) = client.into_split();
    let (u_rd, u_wr) = upstream.into_split();
    let c_wr = Arc::new(Mutex::new(c_wr));
    let pending_hello: Arc<Mutex<Option<proto::Id>>> = Arc::new(Mutex::new(None));

    let mut up = tokio::spawn(client_to_upstream(
        conn,
        peer,
        c_rd,
        u_wr,
        c_wr.clone(),
        pending_hello.clone(),
        shared.clone(),
    ));
    let mut down = tokio::spawn(upstream_to_client(conn, u_rd, c_wr, pending_hello, shared.clone()));

    // Whichever side ends first ends the pair: a half-open relay would let the client keep
    // sending into nothing while believing it is driving. Dropping a JoinHandle does NOT stop a
    // tokio task, so the surviving half must be aborted explicitly: before 2026-10-09 the
    // client->upstream task outlived an upstream that had gone away (robotd restarted), kept the
    // client socket open, judged the client's next command (PERMIT — the token's step clock
    // started) and only then failed the forward with EPIPE. The client saw EOF a second late,
    // reconnected, and its move was cut by the deadline it never knew had started.
    tokio::select! {
        _ = &mut up => { down.abort(); }
        _ = &mut down => { up.abort(); }
    }
    tracing::info!(conn, "client closed");
}

async fn client_to_upstream(
    conn: u64,
    peer: Peer,
    c_rd: tokio::net::unix::OwnedReadHalf,
    mut u_wr: OwnedWriteHalf,
    c_wr: Arc<Mutex<OwnedWriteHalf>>,
    pending_hello: Arc<Mutex<Option<proto::Id>>>,
    shared: Arc<Shared>,
) {
    let mut rd = BufReader::new(c_rd);
    let mut line: Vec<u8> = Vec::with_capacity(512);
    loop {
        line.clear();
        match rd.read_until(b'\n', &mut line).await {
            Ok(0) => return,
            Ok(_) => {}
            Err(e) => {
                tracing::debug!(conn, error = %e, "client read error");
                return;
            }
        }
        // Blank lines are not messages; robotd would answer PARSE_ERROR to one. Drop silently.
        if line.iter().all(|b| b.is_ascii_whitespace()) {
            continue;
        }

        let req: proto::Request = match serde_json::from_slice(&line) {
            Ok(r) => r,
            Err(e) => {
                // Not forwarded: the adapter only relays what it could read. robotd would say
                // PARSE_ERROR too, so the client sees the same shape either way.
                reply_err(&c_wr, None, proto::code::PARSE_ERROR, &format!("pail-duckd: {e}")).await;
                continue;
            }
        };
        let call = match req.as_call() {
            Ok(c) => c,
            Err(e) => {
                reply_err(&c_wr, req.id.clone(), e.code, &format!("pail-duckd: {}", e.message)).await;
                continue;
            }
        };

        match classify(&call) {
            Kind::Reject => {
                tracing::info!(conn, uid = peer.uid, method = req.method, "reject: method outside adapter support");
                reply_err(
                    &c_wr,
                    req.id.clone(),
                    proto::code::METHOD_NOT_FOUND,
                    &format!("{} is not supported by this PAIL adapter (pail-duckd)", req.method),
                )
                .await;
                continue;
            }
            Kind::PassRecorded => {
                let n=match &call {proto::Call::RobotVetbookNote(p)=>p.text.len(),_=>0};
                if let Err(e)=shared.record_note(conn,&peer,n) {
                    tracing::warn!(conn,error=%e,"local note audit unavailable; not forwarded");
                    reply_err(&c_wr,req.id.clone(),-32603,"local note audit unavailable").await;
                    continue;
                }
            }
            Kind::Pass => {
                if matches!(call, proto::Call::Hello(_)) {
                    if let Some(id) = req.id.clone() {
                        *pending_hello.lock().await = Some(id);
                    }
                }
                tracing::debug!(conn, method = req.method, "pass");
            }
            Kind::Stop => {
                // Always forwarded; MD-2 reports it as a PERMIT decision (who stopped the robot).
                tracing::info!(conn, uid = peer.uid, "robot.stop (pass, recorded)");
            }
            Kind::Judge(class) => {
                // Contract ①: the intent's norms come from the parsed params; the bytes that
                // get forwarded are still the original line.
                let (lin, ang) = match &call {
                    proto::Call::RobotMove(m) => ((m.vx * m.vx + m.vy * m.vy).sqrt(), m.vyaw.abs()),
                    _ => (0.0, 0.0),
                };
                if !shared.judge(conn, &peer, &req.method, Some(class), None, lin, ang) {
                    reply_blocked(&c_wr,req.id.clone()).await;
                    continue;
                }
            }
            Kind::JudgeSkill(skill) => {
                if !shared.judge(conn, &peer, &req.method, None, Some(&skill), 0.0, 0.0) {
                    reply_blocked(&c_wr,req.id.clone()).await;
                    continue;
                }
            }
        }

        // Forward the original bytes, newline included, untouched (I-3).
        if let Err(e) = u_wr.write_all(&line).await {
            tracing::warn!(conn, error = %e, "upstream write failed; closing");
            return;
        }
    }
}

async fn upstream_to_client(
    conn: u64,
    u_rd: tokio::net::unix::OwnedReadHalf,
    c_wr: Arc<Mutex<OwnedWriteHalf>>,
    pending_hello: Arc<Mutex<Option<proto::Id>>>,
    shared: Arc<Shared>,
) {
    let mut rd = BufReader::new(u_rd);
    let mut line: Vec<u8> = Vec::with_capacity(4096);
    loop {
        line.clear();
        match rd.read_until(b'\n', &mut line).await {
            Ok(0) => return,
            Ok(_) => {}
            Err(e) => {
                tracing::debug!(conn, error = %e, "upstream read error");
                return;
            }
        }
        // Capture the hello answer for the robot-release record (LLD D8) — read, not rewritten.
        let want = pending_hello.lock().await.clone();
        if let Some(id) = want {
            if let Ok(resp) = serde_json::from_slice::<proto::Response>(&line) {
                if resp.id.as_ref() == Some(&id) {
                    *pending_hello.lock().await = None;
                    if let Some(result) = resp.result {
                        match serde_json::from_value::<proto::HelloResult>(result) {
                            Ok(h) => shared.record_hello(conn, &h),
                            Err(e) => tracing::warn!(conn, error = %e, "hello result did not parse as HelloResult"),
                        }
                    }
                }
            }
        }
        if let Err(e) = c_wr.lock().await.write_all(&line).await {
            tracing::debug!(conn, error = %e, "client write failed; closing");
            return;
        }
    }
}

// JSON-RPC calls need an explicit refusal. Notifications have no reply; in
// either case the original command is never forwarded after a gate refusal.
async fn reply_blocked(c_wr: &Arc<Mutex<OwnedWriteHalf>>, id: Option<proto::Id>) {
    if id.is_some() {
        reply_err(c_wr,id,-32001,"PAIL_COMMAND_BLOCKED").await;
    }
}

async fn reply_err(c_wr: &Arc<Mutex<OwnedWriteHalf>>, id: Option<proto::Id>, code: i32, message: &str) {
    let resp = proto::Response::err(id, proto::Error { code, message: message.to_owned(), data: None });
    let mut bytes = match serde_json::to_vec(&resp) {
        Ok(b) => b,
        Err(_) => return,
    };
    bytes.push(b'\n');
    let _ = c_wr.lock().await.write_all(&bytes).await;
}

#[cfg(test)]
mod refusal_tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    #[tokio::test]
    async fn a_blocked_call_gets_a_correlated_error() {
        let (server,mut client)=tokio::net::UnixStream::pair().unwrap();
        let (_rd,wr)=server.into_split();let writer=Arc::new(Mutex::new(wr));
        reply_blocked(&writer,Some(proto::Id::Number(17))).await;
        let mut buf=[0u8;512];
        let n=tokio::time::timeout(std::time::Duration::from_millis(250),client.read(&mut buf)).await.unwrap().unwrap();
        let row:serde_json::Value=serde_json::from_slice(&buf[..n]).unwrap();
        assert_eq!(row["id"],17);assert_eq!(row["error"]["code"],-32001);
        assert_eq!(row["error"]["message"],"PAIL_COMMAND_BLOCKED");
    }
    #[tokio::test]
    async fn a_blocked_notification_does_not_invent_a_response() {
        let (server,mut client)=tokio::net::UnixStream::pair().unwrap();
        let (_rd,wr)=server.into_split();let writer=Arc::new(Mutex::new(wr));
        reply_blocked(&writer,None).await;
        let mut buf=[0u8;512];
        assert!(tokio::time::timeout(std::time::Duration::from_millis(40),client.read(&mut buf)).await.is_err());
    }
}
