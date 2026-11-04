// EmailShield dashboard. Email-derived text is added only as DOM text nodes, never parsed as markup.
const $ = s => document.querySelector(s);
let KEY = sessionStorage.getItem('es_key') || '', TIMER = null, CFG = null;
function el(tag, props = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') e.className = v; else if (k.startsWith('on')) e.addEventListener(k.slice(2), v); else e.setAttribute(k, v);
  }
  for (const kid of kids.flat()) { if (kid == null || kid === false) continue; e.append(kid.nodeType ? kid : document.createTextNode(String(kid))); }
  return e;
}
const toast = t => { const x = $('#toast'); x.textContent = t; x.style.display = 'block'; setTimeout(() => x.style.display = 'none', 3500); };
const state = (text, err) => el('div', { class: 'state' + (err ? ' err' : '') }, text);
async function api(path, opts = {}) {
  if (!KEY) throw new Error('Enter your API key above and press Connect.');
  opts.headers = { ...(opts.headers || {}), 'X-API-Key': KEY };
  const r = await fetch(path, opts);
  if (r.status === 401) throw new Error('Invalid API key.');
  if (r.status === 429) throw new Error('Too many failed attempts. Wait a minute.');
  if (!r.ok) { let m = r.statusText; try { m = (await r.json()).detail || m; } catch (e) {} throw new Error(m); }
  return r;
}
const J = async p => (await api(p)).json();
const badge = c => el('span', { class: 'badge ' + c.split(' ')[0] }, c);
const pill = s => el('span', { class: 'pill ' + s }, s.replace('_', ' '));
const card = (l, n) => el('div', { class: 'card' }, el('b', {}, n), el('small', {}, l));
const kv = pairs => el('dl', { class: 'kv' }, ...pairs.flatMap(([k, v]) => [el('dt', {}, k), el('dd', {}, v ?? '-')]));
const when = s => s ? new Date(s).toLocaleString() : 'never';

function msgTable(rows, empty) {
  if (!rows.length) return state(empty);
  return el('table', {}, el('thead', {}, el('tr', {}, ...['Case', 'Risk', 'Score', 'Subject', 'Sender', 'Status', 'Analyzed'].map(h => el('th', {}, h)))),
    el('tbody', {}, ...rows.map(m => el('tr', { onclick: () => showDetail(m.id) }, el('td', {}, m.case_ref), el('td', {}, badge(m.category)), el('td', {}, m.score),
      el('td', { class: 'sub' }, m.subject || '(no subject)'), el('td', {}, m.sender || '-'), el('td', {}, m.status), el('td', {}, when(m.analyzed_at))))));
}

// ---------- pages ----------
async function pDashboard(v) {
  const [st, mon, rows, ev] = await Promise.all([J('/api/stats'), J('/api/monitoring'), J('/api/messages'), J('/api/events')]);
  const alerts = rows.filter(m => m.category !== 'Low risk').slice(0, 8);
  v.replaceChildren(
    el('section', { class: 'cards' }, card('Emails processed', st.total), card('High risk', st.high), card('Suspicious', st.suspicious), card('Low risk', st.low), card('Processing failures', st.errors)),
    el('section', { class: 'panel' }, el('h2', {}, 'Monitoring'), el('div', { class: 'row' }, sp(mon.overall.level, mon.overall.level === 'ok' ? 'Active' : mon.overall.level === 'off' ? 'Off' : 'Needs attention'), mon.overall.label), el('p', { class: 'muted' }, `Worker: ${mon.indicators.worker.replace('_', ' ')} · last sync ${when(mon.indicators.last_sync)} · last scan ${when(mon.indicators.last_scan)}`)),
    el('section', { class: 'panel' }, el('h2', {}, 'Recent alerts (suspicious and high risk)'), msgTable(alerts, 'No alerts yet. Analyze an email to get started.')),
    el('section', { class: 'panel' }, el('h2', {}, 'Latest activity'), ev.length ? el('ul', { class: 'events' }, ...ev.slice(0, 10).map(e => el('li', { class: e.type }, `${when(e.ts)} [${e.type}] ${e.detail}`))) : state('No activity yet.')));
}
async function pAnalysis(v) {
  const files = el('input', { type: 'file', accept: '.eml', multiple: 'multiple' }), log = el('div', { class: 'muted' }), results = el('div', {});
  const go = el('button', { onclick: async () => {
    const list = [...files.files]; if (!list.length) return toast('Choose .eml files first');
    log.replaceChildren(); const done = [];
    for (const f of list) {
      try {
        const r = await fetch('/api/analyze?filename=' + encodeURIComponent(f.name), { method: 'POST', headers: { 'X-API-Key': KEY }, body: await f.arrayBuffer() });
        const j = await r.json();
        if (j.ok) done.push(j); log.append(el('div', {}, j.ok ? `${f.name}: ${j.category} (${j.score})${j.duplicate ? ' - duplicate, not re-added' : ''}` : `${f.name}: ERROR ${j.error || j.detail}`));
      } catch (e) { log.append(el('div', {}, `${f.name}: failed (${e.message})`)); }
    }
    if (done.length) { results.replaceChildren(el('h2', {}, 'Results'), msgTable(await Promise.all([...new Set(done.map(d => d.id))].map(id => J('/api/messages/' + id))), '')); showDetail(done[done.length - 1].id); }
  } }, 'Analyze selected files');
  v.replaceChildren(el('section', { class: 'panel' }, el('h2', {}, 'Upload .eml files'), el('div', { class: 'dropzone' }, files, ' ', go), log,
    el('p', { class: 'muted' }, `Limit ${CFG.max_upload_mb} MB per file. Files are parsed only; attachments are hashed, never opened. Threat-intel lookups: ${CFG.ti_enabled ? 'enabled (' + (CFG.ti_providers.join(', ') || 'no keys') + ')' : 'off (local-only)'}.`)), results);
}
async function pInvestigation(v) {
  const accts = await J('/api/accounts');
  const acct = el('select', { 'aria-label': 'mailbox' }, el('option', { value: '__all__' }, 'All mailboxes'), el('option', { value: '' }, 'Uploads / no mailbox'), ...accts.map(a => el('option', { value: a.id }, a.display || a.id)));
  const q = el('input', { placeholder: 'Search subject / sender / file' }), cat = el('select', {}, ...['', 'High risk', 'Suspicious', 'Low risk'].map(x => el('option', { value: x }, x || 'All risk'))),
    sts = el('select', {}, ...['', ...CFG.statuses].map(x => el('option', { value: x }, x || 'All status'))), out = el('div', {});
  const load = async () => {
    out.replaceChildren(state('Loading...'));
    try { const p = new URLSearchParams({ q: q.value, category: cat.value, status: sts.value }); if (acct.value !== '__all__') p.set('account', acct.value); out.replaceChildren(msgTable(await J('/api/messages?' + p), 'No messages match these filters.')); }
    catch (e) { out.replaceChildren(state(e.message, true)); }
  };
  [q, cat, sts, acct].forEach(x => x.addEventListener('input', load));
  v.replaceChildren(el('section', { class: 'panel' }, el('h2', {}, 'Investigation queue'), el('div', { class: 'filters' }, q, cat, sts, acct), out)); load();
}
async function pReports(v) {
  const rows = await J('/api/messages');
  const dl = (id, f) => el('button', { class: 'sec', onclick: () => download(id, f) }, f.toUpperCase());
  v.replaceChildren(el('section', { class: 'panel' }, el('h2', {}, 'Download reports'), el('p', { class: 'muted' }, 'Reports contain findings, evidence, indicators, notes and history. They omit the message body and recipient list.'),
    rows.length ? el('table', {}, el('thead', {}, el('tr', {}, ...['Case', 'Risk', 'Subject', 'Download'].map(h => el('th', {}, h)))),
      el('tbody', {}, ...rows.map(m => el('tr', {}, el('td', {}, m.case_ref), el('td', {}, badge(m.category)), el('td', { class: 'sub' }, m.subject || '(no subject)'), el('td', {}, dl(m.id, 'json'), ' ', dl(m.id, 'html'), ' ', dl(m.id, 'txt')))))) : state('Nothing to report yet.')));
}
const SYM = { ok: '✔', warn: '▲', error: '✖', off: '○' };
const STATE_LEVEL = { monitoring: 'ok', synchronizing: 'warn', connecting: 'warn', degraded: 'warn', stopping: 'warn', disabled: 'off', authentication_required: 'error', error: 'error' };
const sp = (level, text) => el('span', { class: 'pill ' + level, role: 'status' }, `${SYM[level] || ''} ${text}`);
function confirmBtn(label, action, cls = 'sec') {          // two-step confirmation without relying on browser dialogs
  const b = el('button', { class: cls });
  let armed = null; b.textContent = label;
  b.addEventListener('click', async () => {
    if (!armed) { b.textContent = 'Click again to confirm'; armed = setTimeout(() => { armed = null; b.textContent = label; }, 5000); return; }
    clearTimeout(armed); armed = null; b.textContent = label; b.disabled = true;
    try { await action(); } catch (e) { toast(e.message); } finally { b.disabled = false; }
  });
  return b;
}
const post = (p, body) => api(p, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
const ALERT_FILTER = { severity: '', status: '' };
async function pMonitoring(v) {
  const live = el('div', {}), wizard = el('div', {}), cfgBox = el('div', {});
  v.replaceChildren(live, wizard, cfgBox);
  async function refresh() {
    let m; try { m = await J('/api/monitoring'); } catch (e) { live.replaceChildren(state(e.message, true)); return; }
    const ind = m.indicators, o = m.overall, jc = m.jobs;
    const qs = new URLSearchParams(Object.entries(ALERT_FILTER).filter(([, x]) => x));
    const failed = await J('/api/jobs?state=failed'), al = await J('/api/alerts?' + qs), eng = await J('/api/engine'), hl = await J('/api/health/detail');
    live.replaceChildren(
      el('section', { class: 'panel' }, el('h2', {}, 'Engine'), kv([['Process', `pid ${eng.pid}, ${eng.mode} mode`], ['Running since', `${when(eng.started_at)}${eng.uptime_seconds != null ? ' (' + Math.round(eng.uptime_seconds / 60) + ' min)' : ''}`], ['Version', eng.version]]),
        el('p', { class: 'muted' }, eng.note), confirmBtn('Stop engine (monitoring stops)', async () => { await post('/api/engine/stop', { confirm: true }); toast('Engine stopping. Reopen EmailShield to start it again.'); })),
      el('section', { class: 'panel' }, el('h2', {}, 'System health'), sp(hl.overall === 'ok' ? 'ok' : hl.overall === 'warn' ? 'warn' : 'error', hl.overall === 'ok' ? 'All checks passed' : hl.overall === 'warn' ? 'Warnings' : 'Problems found'),
        el('ul', { class: 'events' }, ...hl.checks.map(c => el('li', {}, sp(c.status === 'ok' ? 'ok' : c.status === 'warn' ? 'warn' : 'error', c.status.toUpperCase()), ` ${c.name}: ${c.detail}`)))),
      el('section', { class: 'panel', 'aria-live': 'polite' }, el('h2', {}, 'Monitoring status'), el('div', { class: 'row' }, sp(o.level, o.level === 'ok' ? 'Active' : o.level === 'off' ? 'Off' : o.level === 'warn' ? 'Needs attention' : 'Problem'), o.label),
        el('p', { class: 'muted' }, 'Monitoring runs only while EmailShield is running. It stops when the app is closed, you sign out, the PC sleeps or shuts down, or the network is lost, and resumes where it left off when the app is running again.'),
        kv([['EmailShield window', 'open (you are looking at it)'], ['Backend', 'operational (answering this page)'], ['Scanning worker', sp(ind.worker === 'healthy' ? 'ok' : ind.worker === 'stopping' ? 'warn' : 'error', ind.worker.replace('_', ' '))],
          ['Mailboxes connected', ind.mailboxes_connected], ['Monitoring switched on', ind.monitoring_enabled], ['Last successful sync', when(ind.last_sync)], ['Last successful scan', when(ind.last_scan)], ['Emails processed', m.total_processed]])),
      el('section', { class: 'panel' }, el('h2', {}, 'Mailboxes'), m.accounts.length ? el('table', {}, el('thead', {}, el('tr', {}, ...['Mailbox', 'Provider', 'Connection', 'Monitoring state', 'Last sync', 'Last scan', 'Queue', 'Actions'].map(h => el('th', {}, h)))),
        el('tbody', {}, ...m.accounts.map(a => el('tr', {}, el('td', {}, a.display || a.id), el('td', {}, a.provider), el('td', {}, a.status.replace('_', ' ')), el('td', {}, sp(STATE_LEVEL[a.state] || 'off', a.state_label)),
          el('td', {}, when(a.last_sync_at)), el('td', {}, when(a.last_scan_at)), el('td', {}, `pending ${a.jobs.pending + a.jobs.retry_scheduled} · processing ${a.jobs.processing} · failed ${a.jobs.failed}`),
          el('td', {}, el('div', { class: 'row' },
            a.monitoring_enabled ? confirmBtn('Turn monitoring off', async () => { await post(`/api/accounts/${encodeURIComponent(a.id)}/monitoring`, { enabled: false }); refresh(); })
              : (a.status === 'disconnected' || a.status === 'auth_required' ? el('span', { class: 'muted' }, 'Reconnect first') : confirmBtn('Turn monitoring on', async () => { await post(`/api/accounts/${encodeURIComponent(a.id)}/monitoring`, { enabled: true }); toast('Monitoring on: first sync starts shortly'); refresh(); }, '')),
            a.monitoring_enabled ? el('button', { class: 'sec', onclick: async () => { try { await post(`/api/accounts/${encodeURIComponent(a.id)}/sync`); toast('Sync requested'); } catch (e) { toast(e.message); } } }, 'Sync now') : null,
            a.provider === 'gmail' && a.status !== 'disconnected' ? el('button', { class: 'sec', onclick: async () => { try { const r = await (await post(`/api/accounts/${encodeURIComponent(a.id)}/validate`)).json(); toast(r.ok ? r.detail : `${r.detail}${r.needs_reconnect ? ' Reconnect the mailbox.' : ''}`); refresh(); } catch (e) { toast(e.message); } } }, 'Test connection') : null,
            a.status !== 'disconnected' ? confirmBtn('Disconnect', async () => { const r = await (await post(`/api/accounts/${encodeURIComponent(a.id)}/disconnect`, { confirm: true })).json(); toast(r.token_revoked_at_provider ? 'Disconnected and access revoked' : 'Disconnected'); refresh(); }) : null)),
        ))), ...m.accounts.filter(a => a.last_error).map(a => el('p', { class: 'muted' }, `${a.display || a.id}: last problem (${a.last_error_category || 'error'}) ${when(a.last_error_at)}: ${a.last_error}`))) : state('No mailbox connected yet. Use the steps below.')),
      el('section', { class: 'panel' }, el('h2', {}, 'Queue'), kv([['Pending', jc.pending], ['Retry scheduled', jc.retry_scheduled], ['Processing', jc.processing], ['Completed', jc.completed], ['Failed (kept for investigation)', jc.failed], ['Cancelled', jc.cancelled]]),
        failed.length ? el('div', {}, el('h2', {}, 'Failed jobs'), el('table', {}, el('thead', {}, el('tr', {}, ...['Job', 'Mailbox', 'Category', 'Attempts', 'Details', ''].map(h => el('th', {}, h)))),
          el('tbody', {}, ...failed.map(f => el('tr', {}, el('td', {}, '#' + f.id), el('td', {}, f.account_id || f.provider), el('td', {}, f.error_category || '-'), el('td', {}, f.attempts), el('td', { class: 'sub' }, f.last_error || '-'),
            el('td', {}, el('button', { class: 'sec', onclick: async () => { const r = await (await post('/api/jobs/retry', { ids: [f.id] })).json(); toast(r.retried.length ? 'Queued again' : 'Not retryable (e.g. malformed email)'); refresh(); } }, 'Retry'))))),
          confirmBtn('Retry all eligible', async () => { const r = await (await post('/api/jobs/retry', {})).json(); toast(`${r.retried.length} job(s) queued again`); refresh(); }))) : el('p', { class: 'muted' }, 'No failed jobs.')),
      el('section', { class: 'panel' }, el('h2', {}, 'Alerts'), kv([['High', al.counts.high], ['Medium', al.counts.medium]]),
        el('div', { class: 'filters' }, ...[['severity', ['', 'high', 'medium', 'low']], ['status', ['', 'open', 'acknowledged', 'closed']]].map(([k, opts]) => { const sel = el('select', { 'aria-label': 'alert ' + k }, ...opts.map(o => { const op = el('option', { value: o }, o || 'any ' + k); if (ALERT_FILTER[k] === o) op.selected = true; return op; })); sel.addEventListener('change', () => { ALERT_FILTER[k] = sel.value; refresh(); }); return sel; })),
        al.alerts.length ? el('table', {}, el('tbody', {}, ...al.alerts.slice(0, 15).map(x => el('tr', {}, el('td', { class: 'clickable', onclick: () => showDetail(x.message_id) }, `${x.alert_ref} [${x.severity.toUpperCase()}] score ${x.score}: ${x.subject || '(no subject)'}`), el('td', {}, x.status),
          el('td', {}, ['acknowledged', 'closed'].filter(t => t !== x.status).map(t => el('button', { class: 'sec', onclick: async () => { try { await api('/api/alerts/' + x.id, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status: t }) }); refresh(); } catch (e) { toast(e.message); } } }, t === 'acknowledged' ? 'Acknowledge' : 'Close'))))))) : el('p', { class: 'muted' }, 'No alerts match.')),
      el('section', { class: 'panel' }, el('h2', {}, 'Recent monitoring errors'), m.recent_errors.length ? el('ul', { class: 'events' }, ...m.recent_errors.map(e => el('li', { class: 'error' }, `${when(e.ts)} [${e.type}] ${e.detail}`))) : el('p', { class: 'muted' }, 'None.')),
      el('section', { class: 'panel' }, el('h2', {}, 'Splunk export'), kv([['Status', m.splunk.enabled ? 'enabled' : 'off (nothing is exported)'], ['Token', m.splunk.token_configured ? 'configured' : 'not set'],
        ['Outbox', `pending ${m.splunk.outbox.pending} · retry ${m.splunk.outbox.retry_scheduled} · sent ${m.splunk.outbox.sent} · failed ${m.splunk.outbox.failed}`], ['Last confirmed delivery', when(m.splunk.last_success)], ['Delivery latency', m.splunk.last_latency_ms != null ? `${m.splunk.last_latency_ms} ms last, ${m.splunk.avg_latency_ms} ms average` : 'n/a'], ['Oldest waiting event', m.splunk.oldest_pending_age_seconds != null ? Math.round(m.splunk.oldest_pending_age_seconds) + ' s' : 'none'], ['Last error', m.splunk.last_error || 'none']]),
        m.splunk.dropped ? el('p', { class: 'muted' }, `${m.splunk.dropped} alert(s) were NOT queued because the export queue was full.`) : null,
        m.splunk.outbox.failed ? confirmBtn('Retry failed exports', async () => { const r = await (await post('/api/exports/retry')).json(); toast(`${r.requeued} event(s) queued again`); refresh(); }) : null));
  }
  const credBox = el('textarea', { placeholder: 'Paste the contents of the Google OAuth client JSON (Desktop app). It is stored securely and never shown again.', 'aria-label': 'Google OAuth client JSON' });
  const g = await J('/api/connectors/gmail');
  wizard.replaceChildren(el('section', { class: 'panel' }, el('h2', {}, 'Connect a mailbox'),
    el('p', { class: 'muted' }, 'Read-only access (Gmail scope gmail.readonly). EmailShield never asks for your Gmail password, never sends, deletes or changes mail. Use a dedicated test mailbox. Push notifications are not implemented; EmailShield checks for changes at the interval you set.'),
    el('h2', {}, `Step 1: Google OAuth client ${g.credentials_configured ? '✔ saved' : ''}`), credBox,
    el('p', { class: 'muted' }, 'Redirect URI to register in Google Cloud (Desktop app clients allow it automatically): ' + g.redirect_uri),
    el('div', { class: 'row' }, el('button', { onclick: async () => { try { await api('/api/connectors/gmail/credentials', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ client_secret_json: credBox.value }) }); credBox.value = ''; toast('Saved'); route(); } catch (e) { toast(e.message); } } }, 'Save credentials')),
    el('h2', {}, 'Step 2: Authorize in your browser'),
    el('div', { class: 'row' }, el('button', { onclick: async () => { try { const r = await (await post('/api/connectors/gmail/connect', { open_browser: true })).json(); toast(r.browser_opened ? 'Finish in the browser window, then come back here' : 'Open the link shown below'); wizard.append(el('p', {}, 'If no browser opened, copy this link into one: ', el('code', {}, r.auth_url))); } catch (e) { toast(e.message); } } }, 'Connect Gmail'),
      el('button', { class: 'sec', onclick: refresh }, 'Refresh status')),
    el('h2', {}, 'Step 3: Switch monitoring on'), el('p', { class: 'muted' }, 'Use the Mailboxes table above. The first synchronization reads recent messages (the window is set below), then only new ones.'),
    el('h2', {}, 'Or try it without an account'), el('button', { class: 'sec', onclick: async () => { const r = await (await post('/api/connectors/folder', {})).json(); toast('Local folder mailbox added: drop .eml files into ' + (r.config.path || 'the inbox folder')); refresh(); } }, 'Add local folder mailbox (demo)')));
  const s = await J('/api/settings'), mon = s.monitoring, at = await J('/api/autostart');
  const num = (k, lo, hi) => el('input', { type: 'number', value: mon[k], min: lo, max: hi, 'aria-label': k });
  const f = { poll_seconds: num('poll_seconds', 15, 3600), batch_size: num('batch_size', 1, 50), initial_days: num('initial_days', 1, 30), reconcile_minutes: num('reconcile_minutes', 5, 1440), max_attempts: num('max_attempts', 1, 10) };
  const lab = { poll_seconds: 'Check for new mail every (seconds)', batch_size: 'Messages processed per cycle', initial_days: 'First sync looks back (days)', reconcile_minutes: 'Full re-check every (minutes)', max_attempts: 'Attempts before a job is set aside' };
  cfgBox.replaceChildren(el('section', { class: 'panel' }, el('h2', {}, 'Monitoring settings (apply the next time the service starts)'),
    ...Object.keys(f).map(k => el('label', { class: 'field' }, el('span', {}, lab[k]), f[k])),
    el('div', { class: 'row' }, el('button', { onclick: async () => { try { const body = {}; for (const k in f) body[k] = parseInt(f[k].value, 10); await api('/api/settings/monitoring', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }); toast('Saved'); } catch (e) { toast(e.message); } } }, 'Save'),
      el('button', { class: 'sec', onclick: async () => { try { const r = await (await post('/api/backups')).json(); toast('Backup created: ' + r.file); } catch (e) { toast(e.message); } } }, 'Back up now'),
      confirmBtn('Re-scan old messages with the current rules', async () => { const r = await (await post('/api/rescan', { confirm: true })).json(); toast(`${r.queued} message(s) queued for re-scan`); })),
    at.supported ? el('div', {}, el('h2', {}, 'Start with Windows'), el('p', { class: 'muted' }, 'Adds a visible entry for your account only (Task Manager > Startup apps). Nothing runs when you are signed out. Off by default.'),
      confirmBtn(at.enabled ? 'Turn off start with Windows' : 'Turn on start with Windows', async () => { await api('/api/autostart', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled: !at.enabled }) }); toast('Updated'); route(); })) : el('p', { class: 'muted' }, 'Start-with-sign-in is available in the Windows app.')));
  await refresh();
  TIMER = setInterval(() => refresh().catch(() => {}), 15000);
}
async function pSettings(v) {
  const s = await J('/api/settings'), sp = s.splunk, st = await J('/api/integrations/splunk'), wk = s.worker;
  const field = (label, input) => el('label', { class: 'field' }, el('span', {}, label), input);
  const chk = (v) => { const c = el('input', { type: 'checkbox' }); c.checked = !!v; return c; };
  const en = chk(sp.enabled), url = el('input', { value: sp.url, placeholder: 'https://splunk.example.org:8088' }), idx = el('input', { value: sp.index, placeholder: '(default index)' }),
    stype = el('input', { value: sp.sourcetype }), tls = chk(sp.verify_tls), minc = el('select', {}, ...['Suspicious', 'High risk'].map(x => { const o = el('option', {}, x); if (x === sp.min_category) o.selected = true; return o; })),
    iu = chk(sp.include_urls), isub = chk(sp.include_subject), tok = el('input', { type: 'password', placeholder: sp.token_configured ? 'token saved (leave blank to keep)' : 'HEC token', autocomplete: 'off' }), out = el('div', { class: 'muted' });
  const saveSplunk = async () => {
    const body = { enabled: en.checked, url: url.value.trim(), index: idx.value.trim(), sourcetype: stype.value.trim() || 'emailshield:alert', verify_tls: tls.checked, min_category: minc.value, include_urls: iu.checked, include_subject: isub.checked };
    if (tok.value) body.token = tok.value;
    await api('/api/settings/splunk', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }); tok.value = ''; toast('Splunk settings saved');
  };
  const wen = chk(wk.enabled), wprov = el('select', {}, ...['folder', 'gmail'].map(x => { const o = el('option', {}, x); if (x === wk.provider) o.selected = true; return o; })), wint = el('input', { type: 'number', value: wk.interval, min: 5, max: 3600 });
  v.replaceChildren(
    el('section', { class: 'panel' }, el('h2', {}, 'Splunk HTTP Event Collector (optional)'), el('p', { class: 'muted' }, 'Off by default. Alerts contain verdict, score, findings, ATT&CK ids, sender/URL domains and hashes. Bodies, recipients, subjects and full URLs are NOT sent unless you tick the boxes. Token storage: ' + st.token_storage),
      field('Enable forwarding', en), field('HEC URL', url), field('Index', idx), field('Sourcetype', stype), field('Verify TLS certificate', tls), field('Forward at or above', minc), field('Include full URLs', iu), field('Include subject', isub), field('HEC token', tok),
      el('div', { class: 'row' }, el('button', { onclick: async () => { try { await saveSplunk(); } catch (e) { toast(e.message); } } }, 'Save'),
        el('button', { class: 'sec', onclick: async () => { out.textContent = 'Testing...'; try { await saveSplunk(); const r = await (await api('/api/integrations/splunk/test', { method: 'POST' })).json(); out.textContent = (r.ok ? 'OK: ' : 'FAILED: ') + r.detail; } catch (e) { out.textContent = e.message; } } }, 'Save and test connection')), out,
      kv([['Events sent', st.sent], ['Failed', st.failed], ['Last success', when(st.last_success)], ['Last error', st.last_error || 'none']])),
    el('section', { class: 'panel' }, el('h2', {}, 'Local inbox folder (demo/testing, applies the next time the app starts)'), field('Watch the local inbox folder', wen), field('Provider', wprov), field('Poll interval (s)', wint),
      el('p', {}, el('button', { onclick: async () => { try { await api('/api/settings/worker', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled: wen.checked, provider: wprov.value, interval: parseInt(wint.value, 10) }) }); toast('Worker settings saved'); } catch (e) { toast(e.message); } } }, 'Save'))),
    el('section', { class: 'panel' }, el('h2', {}, 'Security and privacy (read-only)'), kv([['Network binding', CFG.bind + (CFG.remote_access ? ' (REMOTE ACCESS ENABLED)' : ' (this computer only)')], ['Threat intelligence', CFG.ti_enabled ? 'enabled' : 'off (local-only)'], ['Retention', CFG.retention_days + ' days'], ['Upload limit', CFG.max_upload_mb + ' MB'], ['Risk thresholds', `Suspicious >= ${CFG.thresholds.suspicious}, High >= ${CFG.thresholds.high}`]])));
}
function pHelp(v) {
  const q = (t, a) => el('details', {}, el('summary', {}, t), el('p', {}, a));
  v.replaceChildren(el('section', { class: 'panel' }, el('h2', {}, 'Help and troubleshooting'),
    q('The dashboard says "Invalid API key"', 'Use the key shown when EmailShield started (desktop app: it signs in automatically). It is stored in the data folder as api_key.txt.'),
    q('"Too many failed attempts"', 'The server locks a client for one minute after 10 wrong keys. Wait a minute and enter the correct key.'),
    q('Port already in use', 'EmailShield picks the next free port automatically (default start 8731). It never stops other programs. Check the URL shown at startup.'),
    q('"EmailShield is already running"', 'Only one instance may run per computer. Close the other window or end EmailShield in Task Manager.'),
    q('A low score', 'A low score is NOT proof an email is safe. The score is a heuristic; investigate using the evidence.'),
    q('Worker shows "not running"', 'Enable the worker in Settings and restart, or run run_worker.bat. "stale" means the heartbeat stopped.'),
    q('Gmail says not authorized', 'Run scripts/gmail_auth.py with a TEST account and a Desktop OAuth client file in the data folder. Never share the token files.'),
    q('Splunk test fails', '401/403: wrong token or HEC disabled. Connection problem: check URL/port (default 8088) and TLS. Self-signed certificate: untick "Verify TLS certificate" only for a lab Splunk.'),
    q('Where is my data?', 'Settings > Security shows nothing sensitive; About shows the data folder. Back it up by copying that folder while the app is closed.')));
}
function pAbout(v) {
  v.replaceChildren(el('section', { class: 'panel' }, el('h2', {}, 'About EmailShield'), kv([['Version', CFG.version], ['Platform', CFG.platform], ['Python', CFG.python], ['Data folder', CFG.data_dir], ['Listening on', CFG.bind]]),
    el('p', { class: 'muted' }, 'Defensive email threat analysis for education and authorized investigations. Heuristic results are not proof of malice or safety. Use synthetic data for demonstrations.')));
}
async function download(id, fmt) {
  try { const b = await (await api(`/api/messages/${id}/report?format=${fmt}`)).blob(); const a = el('a', { href: URL.createObjectURL(b), download: `emailshield-INV-${id}.${fmt}` }); a.click(); }
  catch (e) { toast(e.message); }
}

// ---------- detail panel ----------
async function showDetail(id, cross = false) {
  const d = $('#detail'); d.hidden = false; d.replaceChildren(state('Loading...'));
  try {
    const [m, rel] = await Promise.all([J('/api/messages/' + id), J(`/api/messages/${id}/related?cross_account=${cross}`)]);
    const a = m.analysis, p = m.parsed;
    const status = el('select', {}, ...CFG.statuses.map(s => { const o = el('option', {}, s); if (s === m.status) o.selected = true; return o; }));
    const notes = el('textarea', {}); notes.value = m.notes || '';
    d.replaceChildren(
      el('h2', {}, `${m.case_ref}  ${p.subject || '(no subject)'}`),
      el('p', {}, badge(a.category), ` heuristic score ${a.score}/100. `, el('span', { class: 'muted' }, a.note)),
      el('div', { class: 'grid2' },
        el('div', {}, el('h2', {}, 'Detection reasons'), ...(a.findings.length ? a.findings.map(f => el('div', { class: 'finding ' + f.severity }, el('b', {}, `${f.title} (+${f.points})`), el('div', {}, f.reason),
          ...f.evidence.map(x => el('div', {}, el('code', {}, x))), el('div', { class: 'muted' }, 'Next: ' + f.step))) : [state('No indicators fired. This does not prove the email is safe.')])),
        el('div', {}, el('h2', {}, 'Sender and authentication'), kv([['From', `${p.from_name} <${p.from_addr}>`], ['Reply-To', p.reply_to_addr || '-'], ['Return-Path', p.return_path_addr || '-'],
          ['SPF / DKIM / DMARC', ['spf', 'dkim', 'dmarc'].map(k => `${k}=${p.auth[k] || 'n/a'}`).join('  ')], ['Message SHA-256', p.raw_sha256]]),
          el('h2', {}, 'URLs'), ...(p.urls.length ? p.urls.map(u => el('div', {}, el('code', {}, u.url), u.text ? ` (text: ${u.text})` : '')) : [el('p', { class: 'muted' }, 'none')]),
          el('h2', {}, 'Attachments (never opened)'), ...(p.attachments.length ? p.attachments.map(x => el('div', {}, el('code', {}, x.filename), ` ${x.size} B, detected ${x.detected_type || '?'}, `, el('code', {}, x.sha256))) : [el('p', { class: 'muted' }, 'none')]))),
      el('h2', {}, 'MITRE ATT&CK mapping'), el('p', { class: 'muted' }, 'Observed facts vs. engine inference. Not proof of attacker intent.'),
      ...(m.attack.length ? m.attack.map(t => el('div', { class: 'finding' }, el('b', {}, `${t.technique_id} ${t.name} (${t.tactic})`), el('div', {}, 'Observed: ' + t.observed.join('; ')), el('div', {}, 'Engine inference: ' + t.inference), el('div', { class: 'muted' }, 'Analyst interpretation: ' + t.analyst_interpretation))) : [el('p', { class: 'muted' }, 'No techniques mapped.')]),
      el('h2', {}, 'Threat intelligence'), ...(m.intel.length ? m.intel.map(t => el('div', {}, `${when(t.fetched_at)} ${t.provider} ${t.indicator_type}: `, el('b', {}, t.verdict), ` - ${t.detail}`)) : [el('p', { class: 'muted' }, CFG.ti_enabled ? 'No lookups recorded yet.' : 'Not performed (local-only mode).')]),
      CFG.ti_enabled ? el('button', { class: 'sec', onclick: async () => { await api(`/api/messages/${id}/enrich`, { method: 'POST' }); showDetail(id); } }, 'Run threat-intel lookup') : null,
      el('h2', {}, 'Related emails'), el('p', { class: 'muted' }, `${rel.caveat} Scope: ${rel.scope}.`), cross ? null : el('button', { class: 'sec', onclick: () => showDetail(id, true) }, 'Also search other mailboxes'),
      ...(rel.related.length ? rel.related.map(r => el('div', { class: 'finding', onclick: () => showDetail(r.id, cross) }, el('b', {}, `${r.case_ref} ${r.subject || ''}`), ...r.reasons.map(x => el('div', {}, x)), cross && r.account_id ? el('div', { class: 'muted' }, 'mailbox: ' + r.account_id) : null)) : [el('p', { class: 'muted' }, 'none found')]),
      el('h2', {}, 'Recommended steps'), el('ol', {}, ...a.recommended_steps.map(s => el('li', {}, s))),
      el('h2', {}, 'Investigation'), el('div', { class: 'row' }, status), notes,
      el('p', {}, el('button', { onclick: async () => { try { await api('/api/messages/' + id, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status: status.value, notes: notes.value }) }); toast('Saved'); showDetail(id); } catch (e) { toast(e.message); } } }, 'Save'),
        ' ', ['json', 'html', 'txt'].map(f => el('button', { class: 'sec', onclick: () => download(id, f) }, 'Report ' + f.toUpperCase())), ' '),
      el('h2', {}, 'History'), el('ul', { class: 'events' }, ...m.history.map(h => el('li', {}, `${when(h.ts)} ${h.actor}: ${h.action} ${h.detail || ''}`))),
      el('h2', {}, 'Limitations'), el('ul', {}, ...a.limitations.map(s => el('li', { class: 'muted' }, s))));
    d.scrollIntoView({ behavior: 'smooth' });
  } catch (e) { d.replaceChildren(state(e.message, true)); }
}

// ---------- router ----------
const PAGES = { dashboard: pDashboard, analysis: pAnalysis, investigation: pInvestigation, reports: pReports, monitoring: pMonitoring, settings: pSettings, help: pHelp, about: pAbout };
async function route() {
  const name = (location.hash || '#dashboard').slice(1), page = PAGES[name] || pDashboard, v = $('#view');
  document.querySelectorAll('#nav a').forEach(a => a.classList.toggle('on', a.getAttribute('href') === '#' + name));
  clearInterval(TIMER); $('#detail').hidden = true;
  v.replaceChildren(state('Loading...'));
  try {
    if (!CFG) CFG = await J('/api/config');
    await page(v);
    if (name === 'dashboard') TIMER = setInterval(() => page(v).catch(() => {}), 15000);
  } catch (e) { v.replaceChildren(state(e.message, true)); }
}
$('#savekey').onclick = () => { KEY = $('#key').value.trim(); sessionStorage.setItem('es_key', KEY); CFG = null; route(); };
if (KEY) $('#key').value = KEY;
window.addEventListener('hashchange', route);
route();
