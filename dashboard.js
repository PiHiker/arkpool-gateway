'use strict';
// Same-origin, read-only, bounded polling. No cookies/keys in JS or local storage.
(() => {
  const showClientIps = document.body.dataset.clientIps === '1';
  const el = id => document.getElementById(id);
  const text = (id, value, state = '') => {
    el(id).textContent = value;
    el(id).className = state;
  };
  const overview = (label, detail, state = 'neutral') => {
    text('status', label, `status-pill ${state}`);
    text('status-detail', detail, `status-detail${state === 'warn' ? ' warn' : ''}`);
  };
  let lastProcess = null;
  let resetObserved = false;
  let deadline = 0;
  const work = value => typeof value === 'number' ? new Intl.NumberFormat('en', {
    notation: 'compact', maximumFractionDigits: 2
  }).format(value) : '—';
  const counts = ['sessions', 'accepted', 'rejected', 'submitted'];
  const rowMessage = message => {
    if (!el('session-rows')) return;
    const cell = document.createElement('td');
    cell.colSpan = showClientIps ? 10 : 9;
    cell.textContent = message;
    const row = document.createElement('tr');
    row.append(cell);
    el('session-rows').replaceChildren(row);
  };
  const unknown = message => {
    for (const id of counts) text(id, '—');
    overview('Unavailable', message, 'warn');
    text('tor-1', 'unknown');
    text('tor-2', 'unknown');
    text('isolation', 'unknown');
    for (const id of ['tor-1', 'tor-2']) el(id).removeAttribute('title');
    text('route-choice', 'New connections: unknown.');
    text('unanswered', 'Pending and uncertain outcomes are not rejections.');
    rowMessage(message);
  };
  const render = status => {
    if (status.schema_version !== 1) throw new Error('schema');
    const g = status.gateway;
    if (g.state !== 'current') {
      unknown(`Gateway status ${g.state}; previous values hidden.`);
    } else {
      const data = g.data;
      const translated=data.counter_basis==='aggregate_pool_acknowledgments';
      const encryptedOnly=data.counter_basis==='encrypted_unavailable';
      const hasNative=data.sessions.some(s=>s.miner_protocol==='SV2');
      text('live-title',translated?'Translator · pool-confirmed totals':encryptedOnly?'Native V2 connections':'V1 gateway history');
      if(el('compat-path-title'))text('compat-path-title',translated?'V1 → V2':'V1');
      if (lastProcess !== null && lastProcess !== g.process) resetObserved = true;
      lastProcess = g.process;
      text('scope', `${resetObserved ? 'Process restart observed. ' : ''}Counters since ${new Date(g.started_at * 1000).toLocaleString()}; not lifetime history.`);
      text('sessions', data.active_sessions);
      for (const id of counts.slice(1)) text(id, data.mining[id]??'—');
      const m = data.mining;
      const pending = Number.isInteger(m.pending_submissions) ? `${m.pending_submissions} pending` : 'Pending unavailable';
      text('unanswered', encryptedOnly?'Share counters are encrypted. Check your miner for accepted shares.':`${pending} · ${m.unanswered} unanswered · ${m.untracked} untracked · ${m.unknown_responses ?? 0} unclear. Not rejections.`);
      const stale = data.sessions.some(s => s.job_state === 'stale');
      const awaiting = data.sessions.some(s => s.job_state === 'awaiting_jobs');
      const admission = data.admission;
      if (admission?.state === 'cooldown')
        overview('Attention', 'New miner connections are paused while Tor paths cool down.', 'warn');
      else if (admission?.state === 'tor_unready')
        overview('Attention', 'New miner connections are blocked because no Tor path is ready.', 'warn');
      else if (stale)
        overview('Attention', 'At least one active session has stale jobs.', 'warn');
      else if (data.translation_enabled && data.translation_ready === false)
        overview('Connecting', 'V1 translation is reconnecting to V2. Native V2 remains available.');
      else if (!data.active_sessions)
        overview('Idle', 'Gateway is ready and waiting for a miner connection.');
      else if (awaiting)
        overview('Connecting', 'Miner connected; waiting for fresh pool jobs.');
      else if (hasNative) overview('Connected', 'Native V2 traffic is encrypted; verify authenticated jobs and shares on your miner.', 'good');
      else overview('Healthy', 'Fresh pool jobs are reaching every active session.', 'good');
      for (const r of data.routes) {
        const latency = r.probe?.median_ms;
        const failed = r.probe?.last_success === false;
        const timing = failed ? ' · test failed' : typeof latency === 'number' ? ` · ${Math.round(latency)} ms` : '';
        const states = {tor_unready: 'Tor unavailable', cooldown: 'connection cooldown',
          stale_jobs: 'stale jobs', fresh_jobs: 'fresh pool jobs',
          subscription_verified: 'pool subscription verified', unverified: 'Tor ready'};
        text(r.route, el('compat-path-title')?(r.work_state==='tor_unready'?'Unavailable':r.work_state==='cooldown'?'Retrying':r.active_sessions?`${r.active_sessions} active`:'Idle'):`${states[r.work_state] || 'Tor status only'} · ${r.active_sessions} active${timing}${r.cooldown_seconds ? ` · retry ${Math.ceil(r.cooldown_seconds)}s` : ''}`, ['fresh_jobs', 'subscription_verified'].includes(r.work_state) ? 'good' : r.work_state === 'unverified' ? '' : 'warn');
        const routeWork = encryptedOnly?'Native mining counters are encrypted.':`${r.mining.accepted} accepted · ${r.mining.rejected} rejected · ${r.mining.jobs} ${translated?'translator ':''}jobs since gateway start.`;
        el(r.route).title = (r.probe?.samples ? `Median connection + subscription time from ${r.probe.successes} successful tests. Last test ${Math.round(r.probe.last_sample_age_seconds)}s ago. ` : 'Tor bootstrap status; no recent subscription timing. ') + routeWork;
      }
      const selection = data.route_selection || {policy: 'round-robin', reason: 'round_robin'};
      const isolation = {miner: 'per miner', session: 'per session', shared: 'shared'};
      text('isolation', isolation[data.tor_isolation] || 'unknown',
        data.tor_isolation && data.tor_isolation !== 'shared' ? 'good' : data.tor_isolation === 'shared' ? 'warn' : '');
      el('isolation').title = 'Configured SOCKS stream policy. Tor clients must also enable IsolateSOCKSAuth.';
      const reasons = {round_robin: 'alternating paths', warming_up: 'measuring paths',
        no_ready: 'no ready path', single_ready: 'only ready path', similar: 'similar results; alternating',
        insufficient_successes: 'not enough successful tests; alternating',
        more_reliable: 'more reliable', faster: 'faster response'};
      const preferred = selection.preferred_route === 'tor-1' ? 'Tor A' : selection.preferred_route === 'tor-2' ? 'Tor B' : null;
      text('route-choice', encryptedOnly?'Native V2 keeps authentication and share contents between each miner and ArkPool.':translated?'V1 miners share an authenticated V2 upstream channel. Per-session pool share counts are unavailable; confirmed totals are shown above.':`New connections: ${preferred ? preferred + ' · ' : ''}${reasons[selection.reason] || 'unknown'}.`);
      const rows = data.sessions.map((s, index) => {
        const row = document.createElement('tr');
        const values = [index + 1, ...(showClientIps ? [s.client_ip] : []), s.miner_protocol==='SV2'?'V2':'V1', data.upstream_protocol==='SV2'?'V2':'V1', s.route === 'tor-1' ? 'Tor A' : 'Tor B',
          s.job_state.replaceAll('_', ' '), s.job_state==='encrypted'?'Encrypted':s.last_job_age_seconds === null ? 'Not yet' : `${Math.round(s.last_job_age_seconds)}s ago`,
          s.accepted??'—', work(s.accepted_work), s.rejected??'—'];
        for (const [column, value] of values.entries()) {
          const cell = document.createElement('td');
          if (column === (showClientIps ? 2 : 1) || column === (showClientIps ? 3 : 2)) {
            const badge = document.createElement('span');
            badge.className = 'protocol-badge '+(value==='V2'?'v2':'v1');
            badge.textContent = value;
            cell.append(badge);
          } else if (column === (showClientIps ? 5 : 4)) {
            const badge = document.createElement('span');
            badge.className = `job-chip ${['fresh','encrypted'].includes(s.job_state) ? 'good' : 'warn'}`;
            badge.textContent = value;
            cell.append(badge);
          } else cell.textContent = value;
          row.append(cell);
        }
        return row;
      });
      if (rows.length && el('session-rows')) el('session-rows').replaceChildren(...rows);
      else rowMessage('No connected sessions. Open Miner connection & setup below to get started.');
    }
    const i = status.ingress;
    if (i.state !== 'current') {
      text('listener', i.state, 'warn');
      text('tls', 'unknown');
      text('tls-detail', '');
    } else {
      const d = i.data;
      text('listener', d.listener_ready ? 'listening' : 'not ready', d.listener_ready ? 'good' : 'warn');
      text('tls', !d.tls_enabled ? 'disabled' : !d.accepting_new_tls ? 'handshakes blocked' :
        d.ca_maintenance_due ? 'CA maintenance due' : 'accepting',
        d.tls_enabled && d.accepting_new_tls && !d.ca_maintenance_due ? 'good' : 'warn');
      text('tls-detail', d.tls_enabled ? `Mining certificate expires ${new Date(d.server_expires_at * 1000).toLocaleDateString()}.` : 'Local mining traffic is not encrypted.');
    }
    const ages = [g, i].filter(r => r.state === 'current').map(r => r.age_seconds);
    deadline = performance.now() + Math.max(0, 30 - Math.max(0, ...ages)) * 1000;
    text('updated', `Updated ${new Date().toLocaleTimeString()}. Polls every 10s; snapshots expire after 30s.`);
  };
  const poll = async () => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3000);
    try {
      const result = await fetch('/api/status', {cache: 'no-store', credentials: 'same-origin', signal: controller.signal});
      if (!result.ok) throw new Error('unavailable');
      render(await result.json());
    } catch (_) {
      unknown('Status unavailable. Check your platform login and service.');
      text('listener', 'unknown');
      text('tls', 'unknown');
      text('tls-detail', '');
      text('updated', 'Last request failed; old values hidden. Retrying in 10 seconds.');
    } finally {
      clearTimeout(timer);
      setTimeout(poll, 10000);
    }
  };
  // Expire a background/suspended tab's old green state before its next poll.
  const expire = () => {
    if (deadline && performance.now() >= deadline) {
      unknown('Status stale; waiting for a fresh snapshot.');
      text('listener', 'unknown');
      text('tls', 'unknown');
      text('tls-detail', '');
      deadline = 0;
    }
  };
  setInterval(expire, 1000);
  document.addEventListener('visibilitychange', expire);
  poll();
})();
