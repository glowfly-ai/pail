// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
/* Read-only observation view. A facet never supplies another facet's verdict.
   Every sentence on the screen comes from the dictionary (i18n.js); codes are
   shown as they are recorded, with their explanation in front. */
(function (root) {
  'use strict';
  const TTL = {plan:3000, gate:3000, permit:3000, motion:1000, pose:1000, ledger:30000, management:300000, liveness:3000};
  const COLUMNS = ['plan','gate','permit','motion','ledger'];
  const STALE_BANNER_MS = 10000, CLOCK_GAP_MS = 2000, SLOW_MS = 500;
  const ROBOTS = '/v2/observation/robots', STATE_BASIS = 'verified_frontier';
  const qualities = new Set(['FRESH','STALE','UNKNOWN','UNSUPPORTED','INVALID','CONFLICT']);
  const esc = v => String(v == null ? '' : v).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const finite = v => typeof v === 'number' && Number.isFinite(v);
  // the dictionary is a global of the page; where the files are loaded as one script it is a name in scope
  const t = k => (typeof root.pailT === 'function' ? root.pailT(k) : (typeof pailT === 'function' ? pailT(k) : k));
  // A code with its explanation in front: "Ready, idle (IDLE_READY)". A code the
  // dictionary does not know is shown alone: nothing is said that is not known.
  function coded(prefix, code) {
    if (code == null || code === '') return esc(t('fl.none'));
    const key = prefix + code, text = t(key);
    return text === key ? esc(code) : esc(text)+' ('+esc(code)+')';
  }
  const two = n => String(n).padStart(2,'0');
  function clock(ms) {
    if (!finite(ms) || ms <= 0) return t('fl.unknown');
    const d = new Date(ms);
    return two(d.getHours())+':'+two(d.getMinutes())+':'+two(d.getSeconds());
  }
  const seconds = ms => finite(ms) ? String(Math.max(0, Math.floor(ms/1000))) : t('fl.unknown');

  function facet(raw, kind, elapsed, disconnected, conflict) {
    const f = raw || {};
    let quality = qualities.has(f.quality) ? f.quality : 'UNKNOWN';
    const age = finite(f.age_ms) && f.age_ms >= 0 ? f.age_ms + Math.max(0, elapsed) : null;
    // What is read from the verified ledger is a state, not an event: a plan accepted ten
    // minutes ago is still the plan. Its age is the age of the collector's verification and
    // its limit is the limit of the ledger, whichever column shows it (design D03).
    const state = f.freshness_basis === STATE_BASIS;
    if (conflict) quality = 'CONFLICT';
    else if ((disconnected || (age !== null && (state ? age >= TTL.ledger : age >= TTL[kind]))) && (quality === 'FRESH' || quality === 'UNKNOWN')) quality = 'STALE';
    if (quality === 'FRESH' && age === null) quality = 'UNKNOWN';
    const active = quality === 'FRESH' ? (f.active_observation || (state ? f.last_observation : null)) : null;
    return {quality, age, active, last:f.last_observation || null, raw:f};
  }
  // One row per robot. Of the sources of a robot, the one that supplies a kind
  // is shown; a source that was not configured for the kind is not.
  function pick(sources, kind) {
    let best = null, others = 0;
    for (const p of sources) {
      const raw = (p.facets || {})[kind];
      if (!raw) continue;
      const supplied = raw.quality !== 'UNSUPPORTED';
      const rank = (supplied ? 2 : 0) + (p.role === 'primary' ? 1 : 0);
      if (supplied) others++;
      if (!best || rank > best.rank) best = {raw, provider:p.provider_id, rank};
    }
    return best ? {raw:best.raw, provider:best.provider, others:Math.max(0, others-1)} : {raw:null, provider:'', others:0};
  }
  function value(kind, f) {
    const v = f.active || f.last, raw = f.raw || {};
    if (!v) return esc(t('fl.not_observed'));
    if (kind === 'plan' && raw.plan_detail) {
      const d = raw.plan_detail;
      return coded('fl.state.', v.state)+' '+esc(d.steps_completed)+'/'+esc(d.steps_total == null ? t('fl.unknown') : d.steps_total);
    }
    if (kind === 'ledger' && raw.ledger_detail && raw.ledger_detail.robot_last_record) {
      const r = raw.ledger_detail.robot_last_record;
      return '#'+esc(r.seq)+' '+esc(r.kind);
    }
    if (kind === 'permit' && finite(v.step_index) && finite(v.step_count)) return coded('fl.state.', v.state)+' '+esc(v.step_index)+'/'+esc(v.step_count);
    return coded('fl.state.', v.state);
  }
  function evidence(kind, f, picked) {
    const raw = f.raw || {}, unknown = t('fl.unknown'), or = v => esc(v == null || v === '' ? unknown : v);
    const lines = [
      esc(t('fl.ev.reason'))+' '+coded('fl.reason.', raw.reason || 'NO_FEED'),
      esc(t('fl.ev.age'))+' '+(f.age === null ? esc(unknown) : esc((f.age/1000).toFixed(1))+' s'),
      esc(t('fl.ev.source'))+' '+or(raw.source_ref || picked.provider),
      esc(t('fl.ev.trust'))+' '+coded('fl.trust.', raw.trust || 'unverifiable'),
      esc(t('fl.ev.basis'))+' '+coded('fl.basis.', raw.freshness_basis || 'unknown'),
      esc(t('fl.ev.producer'))+' '+or(raw.producer_instance_id)+' · '+esc(t('fl.ev.seq'))+' '+or(raw.producer_seq),
      esc(t('fl.ev.observed'))+' '+or(raw.observed_at_ms)+' · '+esc(t('fl.ev.received'))+' '+or(raw.received_at_ms),
      esc(t('fl.ev.clock'))+' '+or(raw.clock_id)];
    if (kind === 'ledger' && raw.ledger_detail) lines.push(esc(t('fl.ev.chain'))+' '+coded('fl.state.', raw.ledger_detail.chain_state)+' · '+esc(t('fl.ev.through'))+' '+or(raw.ledger_detail.verified_through_seq));
    if (picked.others) lines.push(esc(t('fl.ev.others'))+' '+esc(picked.others));
    return lines.join('<br>');
  }
  // A cell is two lines: the value, and how good the observation is. The rest
  // is behind "Evidence".
  function facetHTML(kind, f, picked, key) {
    return '<div class="mobs-facet '+f.quality.toLowerCase()+'"><div class="mobs-value">'+value(kind,f)+'</div>'+
      '<div class="mobs-small">'+coded('fl.quality.', f.quality)+(f.active || !f.last ? '' : ' · '+esc(t('fl.last_only')))+'</div>'+
      '<details data-key="'+esc(key)+'"><summary>'+esc(t('fl.evidence'))+'</summary>'+evidence(kind,f,picked||{provider:'',others:0})+'</details></div>';
  }
  function poseHTML(f, robot) {
    const v = f.active || f.last;
    if (!v) return '<div class="mobs-pose unknown">'+esc(t('fl.pose.none'))+'</div>';
    const kind = v.source_kind || 'unknown';
    const supported = ['simulation_applied_velocity','wheel_odometry','map_localization'].includes(kind);
    const coordinates = supported && v.frame_id && finite(v.x_m) && finite(v.y_m);
    // One point, no accumulated trace: frame/producer/clock changes cannot join paths.
    const point = coordinates ? '<svg viewBox="0 0 160 90" role="img" aria-label="'+esc(robot)+'"><path d="M10 45H150M80 5V85" stroke="#596477"/><circle cx="'+(80+Math.tanh(v.x_m/5)*65)+'" cy="'+(45-Math.tanh(v.y_m/5)*35)+'" r="5" fill="#aab7cc"/></svg>' : '';
    return '<div class="mobs-pose '+f.quality.toLowerCase()+'"><strong>'+esc(robot)+' · '+coded('fl.quality.', f.quality)+'</strong><br>'+coded('fl.pose.kind.', kind)+
      '<br>'+esc(t('fl.pose.frame'))+' '+esc(v.frame_id || t('fl.unknown'))+'<br>'+(coordinates ? 'x '+esc(v.x_m)+' m · y '+esc(v.y_m)+' m · yaw '+esc(finite(v.yaw_rad) ? v.yaw_rad+' rad' : t('fl.unknown')) : esc(t('fl.pose.no_coordinates')))+
      point+'<div class="mobs-small">'+esc(t(f.active ? 'fl.pose.current' : 'fl.pose.last'))+' · '+esc(t('fl.pose.note'))+'</div></div>';
  }
  function summaryHTML(r, o) {
    const s = r.summary;
    if (!s) return '<div class="mobs-summary unknown">'+esc(t('fl.summary.none'))+'</div>';
    // what the collector judged is a reading of a moment: once the page cannot
    // reach the collector, that reading is no longer said in the present tense
    const state = o.disconnected ? 'UNKNOWN' : s.state, inputs = s.inputs || {};
    const names = ['source','liveness','ledger','plan','gate','gate_state','motion','motion_state','permit','progress_wait'];
    const read = names.filter(n => inputs[n] != null && inputs[n] !== '').map(n => esc(t('fl.input.'+n))+' '+esc(inputs[n])).join('<br>');
    return '<div class="mobs-summary '+esc(String(state).toLowerCase())+'" data-summary="'+esc(state)+'"><div class="mobs-value">'+coded('fl.summary.', state)+'</div>'+
      '<div class="mobs-small">'+(o.disconnected ? esc(t('fl.summary.last'))+' '+coded('fl.summary.', s.state) : (s.reason ? coded('fl.why.', s.reason) : esc(t('fl.summary.no_reason'))))+'</div>'+
      '<details data-key="'+esc((r.robot_key || {}).robot_id)+'|summary"><summary>'+esc(t('fl.evidence'))+'</summary>'+esc(t('fl.summary.rule'))+' '+esc(s.decided_by_rule)+'<br>'+read+'</details></div>';
  }
  function ledgerLine(robots) {
    for (const r of robots) for (const p of r.sources || []) {
      const d = p.facets && p.facets.ledger && p.facets.ledger.ledger_detail;
      if (d) return esc(t('fl.scope.ledger'))+' '+coded('fl.state.', d.chain_state)+' ('+esc(t('fl.scope.through'))+' '+esc(d.verified_through_seq)+')';
    }
    return esc(t('fl.scope.ledger'))+' '+esc(t('fl.scope.no_ledger'));
  }
  // The refresh line. Two times are kept apart: when the page last got an
  // answer, and the moment the collector's data is of.
  function headHTML(snapshot, options) {
    const o = options || {}, parts = [];
    if (o.refreshing) parts.push('<span class="mobs-refreshing">'+esc(t('fl.refreshing'))+'</span>');
    if (finite(o.lastSuccessWall)) parts.push(esc(t('fl.last_refresh'))+' '+esc(clock(o.lastSuccessWall))+' ('+esc(seconds(o.sinceSuccess))+esc(t('fl.seconds_ago'))+')');
    else parts.push(esc(t('fl.never_refreshed')));
    if (snapshot) {
      const gap = finite(o.dataMs) && finite(o.receivedWall) && Math.abs(o.receivedWall - o.dataMs) > CLOCK_GAP_MS;
      parts.push('<span class="'+(gap ? 'mobs-gap' : 'mobs-data-time')+'">'+esc(t('fl.data_time'))+' '+esc(clock(o.dataMs))+(gap ? ' · '+esc(t('fl.data_gap')) : '')+'</span>');
    }
    if (o.error) parts.push('<span class="mobs-failed">'+esc(t('fl.refresh_failed'))+' '+coded('fl.error.', o.error)+'</span>');
    return parts.join(' · ');
  }
  function bannerHTML(options) {
    const o = options || {};
    if (!o.error || o.error === 'CAPABILITY_UNSUPPORTED' || !finite(o.failedFor) || o.failedFor <= STALE_BANNER_MS) return '';
    return esc(t('fl.banner.stale'))+' '+(finite(o.lastSuccessWall) ? esc(t('fl.banner.last'))+' '+esc(seconds(o.sinceSuccess))+esc(t('fl.seconds_ago')) : esc(t('fl.banner.never')));
  }
  function render(snapshot, options) {
    const o = options || {}, elapsed = o.elapsed || 0, caps = o.capabilities || {};
    if (!snapshot) return '<div class="mobs-message unknown">'+(o.error ? coded('fl.error.', o.error) : esc(t('fl.waiting')))+' — '+esc(t('fl.no_inference'))+'</div>';
    const robots = snapshot.robots || [], management = caps.management_observation === true;
    const kinds = management ? COLUMNS.concat(['management']) : COLUMNS;
    const scope = '<div class="mobs-scope'+(o.disconnected ? ' stale' : '')+'"><strong>'+esc(t('fl.scope.deployment'))+' '+esc(snapshot.deployment_id || t('fl.scope.legacy'))+'</strong> · '+
      esc(t('fl.scope.robots'))+' '+esc(robots.length)+'/'+esc(snapshot.total)+' · '+ledgerLine(robots)+
      '<details data-key="scope"><summary>'+esc(t('fl.evidence'))+'</summary>'+esc(t('fl.scope.source'))+' '+esc(snapshot.source_id)+'<br>'+esc(t('fl.scope.revision'))+' '+esc(snapshot.revision)+
      '<br>'+esc(t(snapshot.complete ? 'fl.scope.complete' : 'fl.scope.incomplete'))+' · '+esc(t(snapshot.next_cursor ? 'fl.scope.more' : 'fl.scope.end'))+
      '<br>'+esc(t('fl.scope.unresolved'))+' '+esc((snapshot.unresolved || []).length)+' · '+esc(t('fl.scope.overflow'))+' '+esc(snapshot.unresolved_overflow || 0)+'<br>'+esc(t('fl.scope.registration'))+'</details></div>';
    let rows = '', poses = '';
    for (const r of robots) {
      const key = r.robot_key || {}, sources = r.sources && r.sources.length ? r.sources : [{provider_id:'',facets:{}}];
      const conflict = r.quality === 'CONFLICT', merged = {}, read = [];
      for (const p of sources) {
        const fs = p.facets || {}, role = p.role;
        read.push({provider_id:p.provider_id, role, facets:fs});
      }
      for (const k of kinds.concat(['pose'])) merged[k] = pick(read, k);
      const cells = kinds.map(k => {
        const m = merged[k] || {raw:null, provider:'', others:0};
        return '<td data-facet="'+k+'">'+facetHTML(k, facet(m.raw,k,elapsed,o.disconnected,conflict), m, key.robot_id+'|'+k)+'</td>';
      }).join('');
      const list = sources.map(p => esc(p.provider_id || t('fl.no_provider'))+' · '+coded('fl.role.', p.role)+' · '+coded('fl.health.', o.disconnected ? 'DISCONNECTED' : p.health)+(p.last_error ? ' · '+esc(p.last_error) : '')).join('<br>');
      rows += '<tr data-robot="'+esc(key.robot_id)+'" data-deployment="'+esc(key.deployment_id)+'"><th scope="row">'+esc(key.robot_id)+
        '<details data-key="'+esc(key.robot_id)+'|robot"><summary>'+esc(t('fl.evidence'))+'</summary>'+esc(key.deployment_id)+'<br>'+coded('fl.registration.', r.registration)+'<br>'+coded('fl.quality.', r.quality)+'<br>'+list+'</details></th>'+
        '<td data-facet="summary">'+summaryHTML(r,o)+'</td>'+cells+'</tr>';
      const pose = merged.pose || {raw:null, provider:''};
      poses += poseHTML(facet(pose.raw,'pose',elapsed,o.disconnected,conflict), key.robot_id);
    }
    const head = '<th>'+esc(t('fl.col.robot'))+'</th><th>'+esc(t('fl.col.summary'))+'</th>'+kinds.map(k => '<th>'+esc(t('fl.col.'+k))+'</th>').join('');
    const unresolved = (snapshot.unresolved || []).map(r => '<li>'+esc(r.provider_id)+' · '+esc(r.robot_hash)+' · '+esc(r.reason)+'</li>').join('');
    return scope+'<div class="mobs-scroll'+(o.disconnected ? ' stale' : '')+'"><table class="mobs-table"><thead><tr>'+head+'</tr></thead><tbody>'+rows+'</tbody></table></div>'+
      '<p class="mobs-notes">'+esc(t('fl.note.zero'))+' '+esc(t('fl.note.missing'))+(management ? '' : ' <span data-note="management">'+esc(t('fl.note.no_management'))+'</span>')+'</p>'+
      '<div class="mobs-poses">'+poses+'</div><details data-key="unresolved"><summary>'+esc(t('fl.unresolved'))+' ('+(snapshot.unresolved || []).length+')</summary><ul>'+unresolved+'</ul></details>';
  }
  // Which tabs are drawn, by what the collector says it has (design 8.3). A
  // collector that does not say is drawn the way it always was.
  function tabs(capabilities, error) {
    const c = capabilities || {};
    const observation = c.observation === true || (Array.isArray(c.endpoints) && c.endpoints.includes(ROBOTS));
    // A collector that SAID it has no observation source (capabilities
    // without the robots endpoint, or the 503 SOURCE_MAP_UNCONFIGURED of an older collector)
    // gets neither the observation tab nor the operations tab; an unreachable one keeps them.
    const unsupported = error === 'CAPABILITY_UNSUPPORTED';
    return {fleet:capabilities ? observation : !unsupported, status:true, timeline:true,
      robotops:capabilities ? c.management_projection !== false : !unsupported};
  }
  function firstTab(requested, snapshot, visible) {
    const v = visible || {fleet:true, status:true, timeline:true, robotops:true};
    if (requested && v[requested]) return requested;
    const many = !!snapshot && finite(snapshot.total) && snapshot.total >= 2;
    return many && v.fleet ? 'fleet' : 'status';
  }
  function createClient(options) {
    const o = options || {}, request = o.fetch || root.fetch.bind(root), now = o.now || (() => performance.now()), wall = o.wall || (() => Date.now());
    let snapshot = null, loaded = 0, error = '', disconnected = false, stopped = false, pending = false, generation = 0, capabilities = null;
    let controller = null, timer = null, paged = false, asked = false, began = 0, known = null, unsupported = false;
    let success = null, successWall = null, dataMs = null, receivedWall = null, first = null, notModified = false;
    const state = () => {
      const at = now(), since = success === null ? null : Math.max(0, at - success);
      return {elapsed:snapshot ? Math.max(0,at-loaded) : 0, error, disconnected, capabilities:known, notModified,
        refreshing:pending && (asked || at - began >= SLOW_MS), lastSuccessWall:successWall, sinceSuccess:since, dataMs, receivedWall,
        failedFor:error ? (success === null ? (first === null ? 0 : Math.max(0, at - first)) : since) : 0};
    };
    const update = () => { if (!stopped) o.onUpdate(snapshot,state()); };
    async function json(url) {
      controller = new AbortController();
      const timeout = setTimeout(() => controller && controller.abort(), 4000);
      try {
        const response = await request(url,{signal:controller.signal,cache:'no-store',credentials:'same-origin'});
        if (response.status === 304) return null;
        if (!response.ok) {
          const e = new Error('HTTP_'+response.status); e.status = response.status;
          // the collector says WHY in a short plain body (http.Error); read it, bounded
          try { const why = String(await response.text()).trim(); if (/^[A-Z][A-Z0-9_]{0,63}$/.test(why)) e.code = why; } catch (_) {}
          throw e;
        }
        let body;
        if (response.body && response.body.getReader) {
          const reader = response.body.getReader(), chunks = []; let size = 0;
          for (;;) {
            const chunk = await reader.read(); if (chunk.done) break;
            size += chunk.value.byteLength;
            if (size > 1048576) {await reader.cancel();throw new Error('PAGE_OVERSIZE');}
            chunks.push(chunk.value);
          }
          const bytes = new Uint8Array(size);let offset = 0;
          for (const chunk of chunks) {bytes.set(chunk,offset);offset += chunk.byteLength;}
          body = new TextDecoder().decode(bytes);
        } else body = await response.text();
        if (new TextEncoder().encode(body).byteLength > 1048576) throw new Error('PAGE_OVERSIZE');
        return JSON.parse(body);
      } finally {clearTimeout(timeout);controller = null;}
    }
    async function load(next, byUser) {
      if (stopped || pending) return;
      pending = true; asked = !!byUser; began = now(); if (first === null) first = began;
      const gen = generation;
      try {
        if (!capabilities) {
          capabilities = await json('/v2/observation/capabilities');
          if (!capabilities || capabilities.schema_version !== 1) throw new Error('SCHEMA_UNSUPPORTED');
          if (!Array.isArray(capabilities.endpoints) || !capabilities.endpoints.includes(ROBOTS)) {
            // what this collector has is known; observation is not among it
            known = capabilities; const e = new Error('CAPABILITY_UNSUPPORTED'); e.unsupported = true; throw e;
          }
          known = capabilities;
        }
        let cursor = next && snapshot ? snapshot.next_cursor : '';
        if (next && !cursor) return;
        let result;
        // An expired immutable cursor restarts at page one, never joins live pages.
        for (let retries = 0; ; retries++) {
          try {result = await json(ROBOTS+'?limit=200'+(cursor ? '&cursor='+encodeURIComponent(cursor) : ''));break;}
          catch (e) {if (e.status !== 409 || retries >= 2) throw e;cursor = '';}
        }
        if (gen !== generation || stopped) return;
        if (result === null) {
          // not modified: the collector answered, and what the page holds is still its answer
          if (!snapshot) throw new Error('NOT_MODIFIED_WITHOUT_SNAPSHOT');
          success = now(); successWall = wall(); error = ''; disconnected = false; notModified = true;
          return;
        }
        if (result.schema_version !== 1 || result.document_kind !== 'RobotObservationSnapshot' || !Array.isArray(result.robots) || result.robots.length > 200 || result.source_id !== capabilities.source_id || result.deployment_id !== capabilities.deployment_id) throw new Error('INVALID_SNAPSHOT_SCOPE');
        paged = !!cursor; snapshot = result; loaded = now(); success = loaded; successWall = wall(); receivedWall = successWall;
        dataMs = finite(result.as_of_ms) ? result.as_of_ms : (finite(result.generated_at_ms) ? result.generated_at_ms : null);
        error = ''; disconnected = false; notModified = false;
      } catch (e) {
        if (gen !== generation || stopped) return;
        const absent = e.status === 404 || (e.status === 503 && e.code === 'SOURCE_MAP_UNCONFIGURED');
        error = absent || e.unsupported ? 'CAPABILITY_UNSUPPORTED' : (e.name === 'AbortError' ? 'TIMEOUT' : (/^[A-Z][A-Z0-9_]*$/.test(e.message) ? e.message : 'UNREACHABLE'));
        // asked again next time: a collector that was replaced says so in its capabilities.
        // What is drawn keeps the last capabilities that were read, except from a collector that has none.
        // A collector that said it has no observation is not asked again on the timer (F1); the
        // reader's refresh button still asks.
        disconnected = true; capabilities = null; if (absent) known = null;
        unsupported = error === 'CAPABILITY_UNSUPPORTED';
      } finally {
        pending = false; asked = false;
        if (gen === generation && !stopped) update();
      }
    }
    return {first:() => load(false,true), next:() => load(true,true), tick:update,
      start:() => {stopped=false;load(false,false);timer=setInterval(()=>{update();if (!paged && !unsupported) load(false,false);},1000);},
      stop:() => {stopped=true;generation++;if (controller) controller.abort();clearInterval(timer);},
      state:() => snapshot, status:state, capabilities:() => capabilities, known:() => known};
  }
  root.PAIL_FLEET = {facet, render, poseHTML, headHTML, bannerHTML, tabs, firstTab, createClient};
  if (typeof module !== 'undefined') module.exports = root.PAIL_FLEET;
})(typeof window !== 'undefined' ? window : globalThis);
