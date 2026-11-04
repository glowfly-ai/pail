// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
// Robot operations list (LLD §13.2): polls /v1/telemetry/robotops with
// If-None-Match, merges rows by robot_id, keeps the previous list on any
// error (marked stale with a reason), never replaces it with an empty list
// unless the server returned a complete empty snapshot, and preserves the
// selected robot across refreshes. All rows are read-only diagnostics; nothing
// here approves, applies or moves anything.
"use strict";
const PAIL_ROBOTOPS = (function () {
  const BASE_MS = 5000, MAX_MS = 60000, HIDDEN_MS = 60000;
  const state = { rows: new Map(), etag: "", revision: null, stale: false, staleReason: "", selected: null, supported: true, backoff: BASE_MS, timer: null, lastOk: null, capabilities: [] };
  const listeners = [];

  function readinessClass(row) {
    if (!row) return "gray";
    if (row.apply_readiness === "VERIFIED_PENDING_APPLIED_HELD") return "green";
    if (row.apply_readiness === "VERIFICATION_INCOMPLETE" || row.job_state === "VERIFYING") return "amber";
    if (row.job_state === "RECOVERY_REQUIRED" || row.job_state === "ABORTED") return "red";
    return "gray";
  }

  function mergeRows(rows, complete) {
    const next = new Map();
    rows.forEach(function (r) { next.set(r.robot_id, r); });
    if (complete) {
      state.rows = next;
    } else {
      next.forEach(function (v, k) { state.rows.set(k, v); });
    }
    if (state.selected && !state.rows.has(state.selected.robot_id)) {
      state.selected = Object.assign({}, state.selected, { missing: true });
    } else if (state.selected) {
      state.selected = Object.assign({}, state.rows.get(state.selected.robot_id), { missing: false });
    }
  }

  async function fetchAll() {
    // Every page must come from the same snapshot revision; a 409 restarts.
    let cursor = "", rows = [], first = null;
    for (let guard = 0; guard < 20; guard++) {
      const url = new URL("/v1/telemetry/robotops", location.origin);
      url.searchParams.set("view", "diagnostics");
      url.searchParams.set("limit", "200");
      if (cursor) url.searchParams.set("cursor", cursor);
      const headers = {};
      if (!cursor && state.etag) headers["If-None-Match"] = state.etag;
      const resp = await fetch(url, { headers: headers, cache: "no-store" });
      if (resp.status === 304) return { unchanged: true, etag: state.etag };
      if (resp.status === 404) return { unsupported: true };
      if (resp.status === 409) return { changed: true };
      if (!resp.ok) return { error: "HTTP " + resp.status };
      const body = await resp.json();
      if (!body || body.schema_version !== 1 || !Array.isArray(body.rows)) return { error: "schema" };
      if (first === null) first = body; else if (body.snapshot_revision !== first.snapshot_revision) return { changed: true };
      rows = rows.concat(body.rows);
      if (!body.next_cursor) return { body: first, rows: rows, etag: resp.headers.get("ETag") || "" };
      cursor = body.next_cursor;
    }
    return { error: "too many pages" };
  }

  function schedule(ms) {
    clearTimeout(state.timer);
    state.timer = setTimeout(tick, document.hidden ? Math.max(ms, HIDDEN_MS) : ms);
  }

  async function tick() {
    let result;
    try { result = await fetchAll(); } catch (e) { result = { error: String(e && e.message || e) }; }
    if (result.unsupported) {
      state.supported = false; state.stale = true; state.staleReason = "endpoint unsupported by this collector (404)";
      notify(); return; // no polling for an unsupported feature
    }
    if (result.unchanged) {
      state.stale = false; state.staleReason = ""; state.lastOk = Date.now(); state.backoff = BASE_MS;
    } else if (result.changed) {
      state.stale = true; state.staleReason = "snapshot changed while reading; keeping the previous list"; state.backoff = BASE_MS;
    } else if (result.error) {
      state.stale = true; state.staleReason = result.error + " — previous list kept"; state.backoff = Math.min(state.backoff * 2, MAX_MS);
    } else {
      mergeRows(result.rows, true);
      state.etag = result.etag; state.revision = result.body.snapshot_revision; state.capabilities = result.body.capabilities || [];
      state.stale = !!result.body.stale; state.staleReason = result.body.stale ? (result.body.stale_reason || "producer reports stale") : "";
      state.lastOk = Date.now(); state.backoff = BASE_MS;
    }
    notify();
    schedule(state.backoff);
  }

  function notify() { listeners.forEach(function (fn) { try { fn(snapshot()); } catch (e) { /* listener errors never stop polling */ } }); }
  function snapshot() {
    return { rows: Array.from(state.rows.values()).sort(function (a, b) { return a.robot_id < b.robot_id ? -1 : 1; }), stale: state.stale, staleReason: state.staleReason, revision: state.revision, selected: state.selected, supported: state.supported, lastOk: state.lastOk, capabilities: state.capabilities };
  }
  function select(robotId) {
    state.selected = robotId ? Object.assign({ robot_id: robotId, missing: !state.rows.has(robotId) }, state.rows.get(robotId) || {}) : null;
    notify();
  }
  function start() {
    // The served page states whether this collector has a projection endpoint; when it says off, no request
    // is made (a probe that can only answer 404 is noise in the browser console — P22-N4).
    const meta = document.querySelector('meta[name="pail-robotops"]');
    if (meta && meta.getAttribute("content") === "off") {
      state.supported = false; state.stale = true; state.staleReason = "no projection endpoint on this collector (page capability off)";
      notify(); return;
    }
    document.addEventListener("visibilitychange", function () { if (!document.hidden) { clearTimeout(state.timer); tick(); } });
    tick();
  }
  return { start: start, onChange: function (fn) { listeners.push(fn); }, select: select, snapshot: snapshot, readinessClass: readinessClass, _mergeRows: mergeRows, _state: state };
})();

// Panel rendering: a table with one row per robot and a freshness line.
(function () {
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }
  function render(snap) {
    const root = document.getElementById("robotops");
    if (!root) return;
    if (!snap.supported) {
      root.innerHTML = '<div class="unv">Robot operations view: unsupported by this collector (no projection endpoint)</div>';
      return;
    }
    let html = "";
    html += '<div class="note" id="robotops-fresh">' + (snap.stale ? "STALE — " + esc(snap.staleReason) : "fresh") + (snap.revision != null ? " · snapshot " + esc(snap.revision) : "") + (snap.lastOk ? " · last ok " + new Date(snap.lastOk).toLocaleTimeString() : "") + "</div>";
    if (snap.rows.length === 0) {
      html += '<div class="unv">No robots in the projection</div>';
    } else {
      html += '<table id="robotops-table"><thead><tr><th>robot</th><th>lifecycle</th><th>job</th><th>readiness</th><th>generation</th><th>components</th></tr></thead><tbody>';
      snap.rows.forEach(function (r) {
        // agent-probe and agent-binding share a component ref: label the binding so the two never read as a duplicate.
        const comps = (r.loaded_config || []).map(function (c) { return esc(c.component_ref) + (c.kind === "agent-binding" ? "/binding" : "") + ":" + esc(c.status); }).join(" ");
        const sel = snap.selected && snap.selected.robot_id === r.robot_id ? ' class="on"' : "";
        html += "<tr" + sel + ' data-robot="' + esc(r.robot_id) + '"><td>' + esc(r.display_name || r.robot_id) + ' <span class="note">' + esc(r.robot_id) + "</span></td><td>" + esc(r.lifecycle) + "</td><td>" + esc(r.job_state) + '</td><td class="' + PAIL_ROBOTOPS.readinessClass(r) + '">' + esc(r.apply_readiness) + "</td><td>" + esc((r.desired_generation || "").slice(0, 12)) + "</td><td>" + comps + "</td></tr>";
      });
      html += "</tbody></table>";
    }
    if (snap.selected) {
      html += '<div class="note">selected: ' + esc(snap.selected.robot_id) + (snap.selected.missing ? " — not in the current projection (retired, unresolved or removed); selection kept" : "") + "</div>";
    }
    root.innerHTML = html;
    root.querySelectorAll("tr[data-robot]").forEach(function (tr) {
      tr.addEventListener("click", function () { PAIL_ROBOTOPS.select(tr.getAttribute("data-robot")); });
    });
  }
  if (typeof document !== "undefined") {
    document.addEventListener("DOMContentLoaded", function () {
      if (!document.getElementById("robotops")) return;
      PAIL_ROBOTOPS.onChange(render);
      PAIL_ROBOTOPS.start();
    });
  }
})();
