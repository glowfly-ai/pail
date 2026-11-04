// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
/* Status tab: decision history of the verified ledger, and where each permit row comes from.
   The ledger holds what the issuer wrote. It is not a record of what happened on the robot. */
(function (root) {
  'use strict';
  const esc = v => String(v == null ? '' : v).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const t = k => (typeof root.pailT === 'function' ? root.pailT(k) : k);
  const KINDS = ['GATE_DECISION','SAFE_STOP','CHAIN_REVOKED','CHAIN_CANCELLED','OPERATOR_EVENT'];
  const DECISIONS = ['PERMIT','BLOCK','ESTOP','UNKNOWN'];
  const ENDPOINT = '/v2/observation/decisions';

  // What this deployment lets the page draw. A collector that does not say
  // (RC22 and older, or no source map) is drawn the way it always was.
  function feeds(capabilities) {
    const c = capabilities || {}, f = c.feeds || {};
    const ledger = f.ledger_decisions === true && Array.isArray(c.endpoints) && c.endpoints.includes(ENDPOINT);
    return {ledger:ledger, signed:ledger ? f.signed_events === true : true};
  }
  function time(ms) {
    if (typeof ms !== 'number' || !Number.isFinite(ms) || ms <= 0) return t('sl.unknown');
    return new Date(ms).toISOString().replace('T',' ').replace('Z',' UTC');
  }
  function valid(doc) {
    return !!doc && doc.schema_version === 1 && doc.document_kind === 'LedgerDecisionHistory' && Array.isArray(doc.robots) &&
      doc.time_basis === 'issuer_ledger_record_time' && typeof doc.chain_state === 'string';
  }
  // "Ledger verified" is said only when the collector said so in this answer.
  function verified(doc, stale) { return valid(doc) && doc.ledger_verified === true && doc.chain_state === 'CHAIN_OK' && !stale; }
  function headHTML(doc, o) {
    const s = o || {};
    if (!valid(doc)) return '<span class="unv">'+esc(t('sl.unavailable'))+esc(s.error || 'INVALID_DOCUMENT')+'</span>';
    const mark = verified(doc, s.stale)
      ? '<span class="ok" data-ledger-verified="true">'+esc(t('sl.verified'))+'</span>'
      : '<span class="bad" data-ledger-verified="false">'+esc(t('sl.not_verified'))+'</span>';
    const age = typeof doc.verification_age_ms === 'number' ? (doc.verification_age_ms/1000).toFixed(1)+' s' : t('sl.unknown');
    return mark+' · '+esc(t('sl.state'))+' '+esc(doc.chain_state)+(doc.error_code ? ' ('+esc(doc.error_code)+')' : '')+
      ' · '+esc(t('sl.through'))+' '+esc(doc.verified_through_seq)+' · '+esc(t('sl.age'))+' '+esc(age)+
      (s.stale ? ' · <span class="bad">'+esc(t('sl.stale'))+esc(s.error || '')+'</span>' : '')+
      '<div class="note">'+esc(t('sl.prefix_only'))+'</div>';
  }
  function rowsOf(doc) {
    const out = [];
    const take = (list, robot) => { for (const d of (list && list.decisions) || []) out.push({robot:robot, d:d}); };
    for (const r of doc.robots) take(r, (r.robot_key || {}).robot_id || '');
    take(doc.deployment, null);
    // newest first; the ledger position orders records, never the clock
    out.sort((a, b) => Number(b.d.record_seq) - Number(a.d.record_seq));
    return out;
  }
  function rowsHTML(doc, o) {
    if (!valid(doc)) return '<tr><td colspan="7" class="unv">'+esc(t('sl.unavailable'))+esc((o || {}).error || 'INVALID_DOCUMENT')+'</td></tr>';
    const rows = rowsOf(doc), source = verified(doc, (o || {}).stale) ? t('sl.source.ledger') : t('sl.source.ledger_unverified');
    if (!rows.length) return '<tr><td colspan="7" class="unv">'+esc(t('sl.none'))+'</td></tr>';
    return rows.map(function (x) {
      const d = x.d, kind = KINDS.includes(d.kind) ? t('sl.kind.'+d.kind) : t('sl.kind.OTHER');
      const decision = d.kind === 'GATE_DECISION' ? t('sl.decision.'+(DECISIONS.includes(d.decision) ? d.decision : 'UNKNOWN')) : '';
      const notes = [];
      if (d.fatal === true) notes.push(t('sl.fatal'));
      if (d.step_complete === true) {
        const key = d.completion_result === 'accepted' ? 'sl.completion_accepted' :
          d.completion_result === 'rejected' ? 'sl.completion_rejected' : 'sl.completion_unknown';
        notes.push(t(key));
      }
      if (d.chain_attributed === false) notes.push(t('sl.unattributed'));
      if (d.accepted === false) notes.push(t('sl.refused'));
      const many = Number.isInteger(d.repeats) && d.repeats > 1 && d.first_record_seq;
      if (many) notes.push(String(d.repeats)+t('sl.repeats')+time(d.first_ledger_record_ms));
      return '<tr data-seq="'+esc(d.record_seq)+'" data-robot="'+esc(x.robot === null ? '' : x.robot)+'" data-kind="'+esc(d.kind)+'">'+
        '<td>'+esc(time(d.ledger_record_ms))+'</td>'+
        '<td>'+esc(d.decided_unix_ms ? time(d.decided_unix_ms) : '—')+'</td>'+
        '<td>'+esc(d.delivery ? t('sl.delivery.'+d.delivery) : '—')+'</td>'+
        '<td>'+(x.robot === null ? '<span class="note">'+esc(t('sl.deployment'))+'</span>' : esc(x.robot))+'</td>'+
        '<td>'+esc(kind)+(d.trigger ? '<div class="note mono">'+esc(d.trigger)+'</div>' : '')+'</td>'+
        '<td>'+esc(decision)+(notes.length ? '<div class="note">'+esc(notes.join(' · '))+'</div>' : '')+'</td>'+
        '<td class="mono">'+esc(d.reason_code || '')+'</td>'+
        '<td class="mono">'+(many ? esc(d.first_record_seq)+'–' : '')+esc(d.record_seq)+'</td>'+
        '<td>'+esc(source)+'</td></tr>';
    }).join('');
  }
  function droppedHTML(doc) {
    if (!valid(doc)) return '';
    let n = 0;
    for (const r of doc.robots.concat([doc.deployment || {}])) n += Number(r.dropped_older) || 0;
    return n ? esc(String(n)+t('sl.dropped')) : '';
  }

  // Permit table. A signed statement and a robot's own report are different
  // evidence, so every row says which it is. A self report is never drawn as
  // evidence of a permit.
  function selfReports(snapshot, state, facet) {
    const out = [], s = state || {};
    for (const r of (snapshot && snapshot.robots) || []) {
      for (const p of r.sources || []) {
        const raw = (p.facets || {}).permit;
        if (!raw || raw.trust !== 'local_self_report' || raw.quality === 'UNSUPPORTED') continue;
        const f = facet(raw, 'permit', s.elapsed || 0, !!s.disconnected, r.quality === 'CONFLICT');
        const value = f.active || f.last;
        out.push({robot_id:(r.robot_key || {}).robot_id || '', provider:p.provider_id, quality:f.quality, reason:raw.reason || '', age:f.age,
          state:value && value.state || ''});
      }
    }
    return out;
  }
  function permitHTML(signed, reports, h) {
    const rows = [], named = {};
    for (const r of signed || []) {
      const who = h.resolver ? h.resolver.resolve(r.robot || '') : null;
      if (who && who.resolved) named[who.robot_id] = true;
      rows.push('<tr data-source="signed">'+
        '<td>'+h.robotCell(r.robot || '', h.resolver)+'</td>'+
        '<td>'+h.stateCell(r)+'</td>'+
        '<td class="note">'+esc(t(r.why || ''))+'</td>'+
        '<td>'+esc(h.observedMs(r.mirror_age_ms))+'</td>'+
        '<td>'+esc(h.ageText(r.permit_age_ms))+'</td>'+
        '<td>'+esc(h.observedMs(r.deadman_window_ms))+'</td>'+
        '<td>'+esc(r.mode || t('미관찰'))+'</td>'+
        '<td><button class="unlock-btn" data-robot="'+esc(r.robot || '')+t('">잠금 해제 요청</button></td>')+
        '<td>'+esc(r.key_role ? t('sl.source.signed') : t('sl.source.unsigned'))+'</td></tr>');
    }
    for (const r of reports || []) {
      if (named[r.robot_id]) continue; // the signed statement of this robot is shown
      rows.push('<tr data-source="self" data-robot-id="'+esc(r.robot_id)+'">'+
        '<td>'+esc(r.robot_id)+'<div class="note mono">'+esc(r.provider)+'</div></td>'+
        '<td><span class="unv">'+esc(r.state || t('sl.unknown'))+' · '+esc(r.quality)+'</span></td>'+
        '<td class="note">'+esc(r.reason)+'</td>'+
        '<td>—</td>'+
        '<td>'+esc(r.age === null ? t('sl.unknown') : String(Math.round(r.age))+'ms')+'</td>'+
        '<td>—</td><td>—</td><td></td>'+
        '<td><strong>'+esc(t('sl.source.self'))+'</strong></td></tr>');
    }
    if (!rows.length) return '<tr><td colspan="9" class="unv">'+esc(t('sl.permit.none'))+'</td></tr>';
    return rows.join('');
  }

  function createClient(options) {
    const o = options, request = o.fetch || root.fetch.bind(root);
    let doc = null, error = '', stale = false, pending = false, stopped = true, timer = null, controller = null;
    const update = () => { if (!stopped) o.onUpdate(doc, {error:error, stale:stale}); };
    async function load() {
      if (stopped || pending || !feeds(o.capabilities()).ledger) return;
      pending = true;
      controller = new AbortController();
      const timeout = setTimeout(() => controller && controller.abort(), 4000);
      try {
        const response = await request(ENDPOINT, {signal:controller.signal, cache:'no-store', credentials:'same-origin'});
        if (!response.ok) throw new Error('HTTP '+response.status);
        const body = await response.json();
        if (!valid(body)) throw new Error('INVALID_DOCUMENT');
        doc = body; error = ''; stale = false;
      } catch (e) {
        // the last answer stays on screen, but it is no longer called verified
        error = e.message; stale = true;
      } finally { clearTimeout(timeout); controller = null; pending = false; }
      update();
    }
    return {load:load,
      start:() => { if (!stopped) return; stopped = false; load(); timer = setInterval(load, 2000); },
      stop:() => { stopped = true; if (controller) controller.abort(); clearInterval(timer); },
      state:() => doc};
  }
  root.PAIL_STATUS_LEDGER = {feeds, valid, verified, headHTML, rowsHTML, droppedHTML, selfReports, permitHTML, createClient, ENDPOINT};
  if (typeof module !== 'undefined') module.exports = root.PAIL_STATUS_LEDGER;
})(typeof window !== 'undefined' ? window : globalThis);
