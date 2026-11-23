'use strict';

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const state = { accounts: [], transactions: [], cases: [], user: '', page: 'overview', selected: null, account: null };
const money = (minor) => new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD', minimumFractionDigits: 0, maximumFractionDigits: 2 }).format(minor / 100);
const date = (value) => new Date(value).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
const escapeHTML = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
let toastTimer;

function toast(message, error = false) {
  const element = $('#toast');
  element.textContent = message;
  element.classList.toggle('error', error);
  element.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { element.hidden = true; }, error ? 9000 : 4500);
}

async function api(path, options = {}) {
  const response = await fetch(`/api${path}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', 'X-Sentinel-Request': '1', ...options.headers },
  });
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    if (response.status === 401 && !['/login', '/session'].includes(path)) await initialize();
    const detail = body?.detail;
    const message = Array.isArray(detail) ? detail.map((item) => `${item.loc.slice(1).join('.')}: ${item.msg}`).join('; ') : detail;
    throw new Error(message || `Request failed (${response.status})`);
  }
  return body;
}

async function busy(button, task) {
  const previous = button.innerHTML;
  button.disabled = true;
  button.textContent = 'Working…';
  try { await task(); } catch (error) { toast(error.message, true); }
  finally { button.disabled = false; button.innerHTML = previous; }
}

function download(name, content) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(content, null, 2)], { type: 'application/json' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function initialize() {
  try {
    const session = await api('/session');
    state.user = session.user;
    $('#auth').hidden = Boolean(session.user);
    $('#workspace').hidden = !session.user;
    if (!session.user) {
      if ($('#case-dialog').open) $('#case-dialog').close();
      $('#auth-title').textContent = session.configured ? 'Welcome back' : 'Create your workspace';
      $('#auth-description').textContent = session.configured ? 'Sign in to your investigation workspace.' : 'Choose your investigator credentials to get started.';
      $('#auth-submit').textContent = session.configured ? 'Sign in' : 'Create workspace';
      $('#auth-form').dataset.endpoint = session.configured ? '/login' : '/setup';
      $('#password').autocomplete = session.configured ? 'current-password' : 'new-password';
      return;
    }
    $('#user-label').textContent = session.user;
    $('#avatar').textContent = session.user[0].toUpperCase();
    $('#today').textContent = new Date().toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
    await refresh();
  } catch (error) { toast(error.message, true); }
}

$('#auth-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  $('#auth-error').textContent = '';
  await busy($('#auth-submit'), async () => {
    try {
      await api($('#auth-form').dataset.endpoint, { method: 'POST', body: JSON.stringify({ name: $('#username').value, password: $('#password').value }) });
      $('#password').value = '';
      await initialize();
    } catch (error) { $('#auth-error').textContent = error.message; }
  });
});
$('#logout').addEventListener('click', () => busy($('#logout'), async () => {
  await api('/logout', { method: 'POST' });
  location.reload();
}));

function page(name) {
  state.page = name;
  $$('.page').forEach((element) => { element.hidden = element.id !== `page-${name}`; });
  $$('.nav-item').forEach((element) => element.classList.toggle('active', element.dataset.page === name));
  $('#breadcrumb').textContent = { overview: 'Overview', cases: 'Case queue', network: 'Network explorer', data: 'Data & integrations', audit: 'Audit trail' }[name];
  if (name === 'network') requestAnimationFrame(drawGraphs);
  if (name === 'overview') requestAnimationFrame(drawGraphs);
  if (name === 'audit') loadAudit().catch((error) => toast(error.message, true));
}
$$('[data-page]').forEach((button) => button.addEventListener('click', () => page(button.dataset.page)));
$$('[data-goto]').forEach((button) => button.addEventListener('click', () => page(button.dataset.goto)));

async function refresh() {
  Object.assign(state, await api('/workspace'));
  const active = state.cases.filter((item) => item.status !== 'Closed');
  $('#metric-cases').textContent = active.length;
  $('#metric-high').textContent = active.filter((item) => item.score >= 90).length;
  const evidenceIds = new Set(active.flatMap((item) => item.transactions));
  $('#metric-volume').textContent = money(state.transactions.filter((t) => evidenceIds.has(t.id)).reduce((sum, t) => sum + t.amount_minor, 0));
  $('#metric-accounts').textContent = state.accounts.length;
  $('#metric-transfers').textContent = `${state.transactions.length} transactions indexed`;
  $('#nav-count').textContent = active.length;
  $('#empty-banner').hidden = state.accounts.length > 0;
  const cycleCount = state.cases.filter((item) => item.rule === 'circular_flow').length;
  const faninCount = state.cases.filter((item) => item.rule === 'fan_in').length;
  $('#cycle-count').textContent = `${cycleCount} finding${cycleCount === 1 ? '' : 's'}`;
  $('#fanin-count').textContent = `${faninCount} finding${faninCount === 1 ? '' : 's'}`;
  $('#overview-cases').innerHTML = caseTable(active.sort((a, b) => b.score - a.score).slice(0, 5));
  renderCases();
  $('#account-select').innerHTML = '<option value="">Choose an account</option>' + state.accounts.map((a) => `<option value="${escapeHTML(a.id)}">${escapeHTML(a.id)} · ${escapeHTML(a.name)}</option>`).join('');
  $('#account-select').value = state.account || '';
  $('#neo4j-status').textContent = state.integrations.neo4j ? 'Connection configured' : 'Not configured';
  $('#neo4j-engine').textContent = state.integrations.graph_backend === 'neo4j'
    ? 'Native Cypher detection is enabled. Detection runs mirror the current workspace before querying the graph.'
    : 'The local detector runs using NetworkX. Set SENTINEL_GRAPH_BACKEND=neo4j on the server to use native Cypher detection.';
  $('#ollama-status').textContent = state.integrations.ollama ? 'Model configured' : 'Not configured';
  renderAccount();
  renderLedger();
  requestAnimationFrame(drawGraphs);
}

function statusBadge(status) {
  const css = { Open: 'open', 'In review': 'review', Escalated: 'escalated', Closed: 'closed' }[status];
  return `<span class="badge ${css}">${escapeHTML(status)}</span>`;
}

function caseTable(cases) {
  if (!cases.length) return '<div class="empty">No cases to display. Import a network and run detection to get started.</div>';
  return `<div class="table-scroll"><table><thead><tr><th>Case / pattern</th><th>Priority</th><th>Accounts</th><th>Transfer volume</th><th>Status</th><th>Review</th></tr></thead><tbody>${cases.map((item) => `<tr><td><strong>${escapeHTML(item.title)}</strong><span class="subcell mono">${escapeHTML(item.id.slice(0, 10).toUpperCase())}</span></td><td><span class="badge ${item.score >= 90 ? 'high' : 'medium'}">${item.score >= 90 ? 'High' : 'Medium'} · ${item.score}</span></td><td>${item.accounts.length} connected</td><td><strong>${money(item.amount_minor)}</strong><span class="subcell">${item.transactions.length} evidence transfers</span></td><td>${statusBadge(item.status)}</td><td><button class="text-button open-case" data-id="${escapeHTML(item.id)}">Open case</button></td></tr>`).join('')}</tbody></table></div>`;
}

function renderCases() {
  const query = $('#case-search').value.toLowerCase();
  const status = $('#case-filter').value;
  const filtered = state.cases.filter((item) => (!status || item.status === status) &&
    [item.id, item.title, item.assignee, ...item.accounts].join(' ').toLowerCase().includes(query));
  $('#case-list').innerHTML = caseTable(filtered.sort((a, b) => b.score - a.score));
  $('#filtered-count').textContent = `${filtered.length} cases`;
}
$('#case-search').addEventListener('input', renderCases);
$('#case-filter').addEventListener('change', renderCases);
document.addEventListener('click', (event) => {
  const button = event.target.closest('.open-case');
  if (button) busy(button, () => openCase(button.dataset.id));
});

async function openCase(id) {
  const item = await api(`/cases/${id}`);
  state.selected = item;
  $('#detail-id').textContent = `CASE ${item.id.toUpperCase()}`;
  $('#detail-title').textContent = item.title;
  $('#detail-summary').innerHTML = `<div class="detail-badges">${statusBadge(item.status)}<span class="badge high">Rule score ${item.score}/100</span><span class="badge neutral">Anomaly context ${item.anomaly_score}/100</span></div><p class="evidence-reason">${escapeHTML(item.reason)}</p><p class="small muted">${item.entities.map((a) => `${escapeHTML(a.name)} (${escapeHTML(a.id)})`).join(' · ')}</p>`;
  $('#detail-evidence').innerHTML = transferTable(item.evidence);
  $('#detail-status').value = item.status;
  $('#detail-assignee').value = item.assignee;
  $('#detail-rationale').value = '';
  $('#detail-notes').innerHTML = item.notes.length ? item.notes.map((note) => `<article class="note"><div class="note-meta">${escapeHTML(note.author)} · ${date(note.created)}</div><p>${escapeHTML(note.text)}</p></article>`).join('') : '<p class="small muted">No notes yet. Record your first observation.</p>';
  $('#note-text').value = '';
  $('#draft-area').hidden = true;
  if (!$('#case-dialog').open) $('#case-dialog').showModal();
}
$('#close-case').addEventListener('click', () => $('#case-dialog').close());
$('#case-dialog').addEventListener('click', (event) => { if (event.target === $('#case-dialog')) { const rect = event.target.getBoundingClientRect(); if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) event.target.close(); } });
$('#case-form').addEventListener('submit', (event) => {
  event.preventDefault();
  busy(event.submitter, async () => {
    const id = state.selected.id;
    await api(`/cases/${id}`, { method: 'PATCH', body: JSON.stringify({ status: $('#detail-status').value, assignee: $('#detail-assignee').value, rationale: $('#detail-rationale').value, version: state.selected.version }) });
    await openCase(id);
    await refresh();
    toast('Decision saved to the audit trail.');
  });
});
$('#note-form').addEventListener('submit', (event) => {
  event.preventDefault();
  busy(event.submitter, async () => {
    await api(`/cases/${state.selected.id}/notes`, { method: 'POST', body: JSON.stringify({ text: $('#note-text').value }) });
    await openCase(state.selected.id);
    toast('Encrypted note saved.');
  });
});
$('#draft-button').addEventListener('click', () => busy($('#draft-button'), async () => {
  const result = await api(`/cases/${state.selected.id}/draft`, { method: 'POST' });
  $('#draft-text').value = result.draft;
  $('#draft-area').hidden = false;
}));
$('#save-draft').addEventListener('click', () => busy($('#save-draft'), async () => {
  await api(`/cases/${state.selected.id}/notes`, { method: 'POST', body: JSON.stringify({ text: `AI-assisted summary, reviewed by ${state.user}\n\n${$('#draft-text').value}` }) });
  await openCase(state.selected.id);
  toast('Reviewed draft saved.');
}));
$('#export-case').addEventListener('click', () => busy($('#export-case'), async () => {
  const result = await api(`/cases/${state.selected.id}`);
  download(`sentinel-case-${result.id}.json`, { exported_at: new Date().toISOString(), ...result });
  toast('Case report downloaded. It includes decrypted investigation notes.');
}));

$$('.run-detection').forEach((button) => button.addEventListener('click', () => busy(button, async () => {
  const result = await api('/detect', { method: 'POST' });
  await refresh();
  toast(result.warning || `Detection complete. ${result.new_cases} new cases; ${result.findings} patterns found.`, Boolean(result.warning));
})));
$('#load-demo').addEventListener('click', () => busy($('#load-demo'), async () => {
  const result = await api('/demo', { method: 'POST' });
  await refresh();
  toast(`Demo loaded. ${result.new_cases} cases ready for review.`);
}));
$('#import-button').addEventListener('click', () => busy($('#import-button'), async () => {
  const file = $('#import-file').files[0];
  if (!file) throw new Error('Choose a JSON file first.');
  if (file.size > 2_000_000) throw new Error('File exceeds 2 MB.');
  const body = JSON.parse(await file.text());
  await api('/import', { method: 'POST', body: JSON.stringify(body) });
  await refresh();
  $('#import-result').textContent = 'Import complete. Run detection to generate cases.';
  toast('Network imported successfully.');
}));
$('#download-sample').addEventListener('click', () => busy($('#download-sample'), async () => download('sentinel-sample.json', await api('/demo-file'))));
$('#neo4j-sync').addEventListener('click', () => busy($('#neo4j-sync'), async () => {
  const result = await api('/neo4j/sync', { method: 'POST' });
  toast(`Synced ${result.accounts} accounts and ${result.transactions} transfers to Neo4j.`);
}));

async function loadAudit() {
  const result = await api('/audit');
  $('#audit-integrity').textContent = result.valid ? `Chain verified · ${result.events.length} events have consistent hashes and ordering.` : 'Chain verification failed. The audit history may have been modified.';
  $('#audit-integrity').classList.toggle('error', !result.valid);
  $('#audit-events').innerHTML = `<div class="table-scroll"><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Subject</th><th>Event hash</th></tr></thead><tbody>${result.events.map((event) => `<tr><td>${date(event.created)}</td><td>${escapeHTML(event.actor)}</td><td>${escapeHTML(event.action.replaceAll('_', ' '))}</td><td>${escapeHTML(event.subject)}</td><td class="mono">${escapeHTML(event.hash.slice(0, 14))}…</td></tr>`).join('')}</tbody></table></div>`;
}
$('#refresh-audit').addEventListener('click', () => busy($('#refresh-audit'), async () => { await loadAudit(); toast('Audit chain verification complete.'); }));

function transferTable(transfers) {
  if (!transfers.length) return '<div class="empty">No transactions in this view.</div>';
  return `<div class="table-scroll"><table><thead><tr><th>Transaction</th><th>From</th><th>To</th><th>Amount</th><th>Time</th></tr></thead><tbody>${transfers.map((t) => `<tr><td class="mono">${escapeHTML(t.id)}</td><td class="mono">${escapeHTML(t.source)}</td><td class="mono">${escapeHTML(t.target)}</td><td><strong>${money(t.amount_minor)}</strong></td><td>${date(t.timestamp)}</td></tr>`).join('')}</tbody></table></div>`;
}

function renderLedger() {
  const transfers = state.transactions.filter((t) => !state.account || t.source === state.account || t.target === state.account);
  $('#ledger-count').textContent = `${transfers.length} transfers`;
  $('#transaction-ledger').innerHTML = transferTable(transfers.slice().sort((a, b) => b.timestamp.localeCompare(a.timestamp)));
}
function selectAccount(id) {
  state.account = id || null;
  $('#account-select').value = id || '';
  renderAccount(); renderLedger(); drawGraphs();
}
function renderAccount() {
  const account = state.accounts.find((a) => a.id === state.account);
  if (!account) { $('#account-detail').innerHTML = '<p class="muted">Select a node or choose an account below.</p>'; return; }
  const incoming = state.transactions.filter((t) => t.target === account.id);
  const outgoing = state.transactions.filter((t) => t.source === account.id);
  const cases = state.cases.filter((item) => item.accounts.includes(account.id));
  $('#account-detail').innerHTML = `<p class="eyebrow mono">${escapeHTML(account.id)}</p><h3>${escapeHTML(account.name)}</h3><p class="small muted">${escapeHTML(account.type)} · ${escapeHTML(account.country)}</p><div class="detail-stat"><span>Incoming volume</span><strong>${money(incoming.reduce((s, t) => s + t.amount_minor, 0))}</strong></div><div class="detail-stat"><span>Outgoing volume</span><strong>${money(outgoing.reduce((s, t) => s + t.amount_minor, 0))}</strong></div><div class="detail-stat"><span>Anomaly context</span><strong>${account.anomaly_score ?? 'N/A'}${account.anomaly_score === null ? '' : '/100'}</strong></div><p class="small muted">Relative Isolation Forest score across this workspace. Not a probability.</p>${cases.map((item) => `<button class="text-button open-case" data-id="${escapeHTML(item.id)}">${escapeHTML(item.title)}</button>`).join('<br>')}`;
}
$('#account-select').addEventListener('change', (event) => selectAccount(event.target.value));
$('#reset-network').addEventListener('click', () => { $('#network-filter').value = ''; selectAccount(null); });
$('#network-filter').addEventListener('change', drawGraphs);

const graphNodes = new Map();
function drawGraph(canvas) {
  const bounds = canvas.getBoundingClientRect();
  if (!bounds.width || !bounds.height) return;
  const ratio = window.devicePixelRatio || 1;
  canvas.width = bounds.width * ratio; canvas.height = bounds.height * ratio;
  const ctx = canvas.getContext('2d'); ctx.scale(ratio, ratio);
  const width = bounds.width, height = bounds.height;
  if (!state.accounts.length) {
    ctx.fillStyle = '#8da0ac'; ctx.textAlign = 'center'; ctx.font = '14px Segoe UI';
    ctx.fillText('Your transaction network will appear here', width / 2, height / 2); return;
  }
  const flagged = new Set(state.cases.flatMap((item) => item.accounts));
  const cycles = new Set(state.cases.filter((item) => item.rule === 'circular_flow').flatMap((item) => item.accounts));
  const fanins = new Set(state.cases.filter((item) => item.rule === 'fan_in').flatMap((item) => item.accounts).filter((id) => !cycles.has(id)));
  const onlyFlagged = canvas.id === 'explorer-graph' && $('#network-filter').value === 'flagged';
  const accounts = state.accounts.filter((a) => !onlyFlagged || flagged.has(a.id));
  const groups = [accounts.filter((a) => cycles.has(a.id)), accounts.filter((a) => fanins.has(a.id)), accounts.filter((a) => !flagged.has(a.id))];
  const nodes = new Map();
  const layout = [[width * .27, height * .38, Math.min(width * .16, height * .23)], [width * .72, height * .38, Math.min(width * .17, height * .24)], [width * .5, height * .73, Math.min(width * .28, height * .15)]];
  groups.forEach((group, g) => group.forEach((account, index) => {
    const [cx, cy, radius] = layout[g];
    const angle = index / group.length * Math.PI * 2 - Math.PI / 2;
    nodes.set(account.id, { account, x: cx + Math.cos(angle) * radius, y: cy + Math.sin(angle) * radius * (g === 2 ? .65 : 1), flagged: flagged.has(account.id) });
  }));
  graphNodes.set(canvas.id, nodes);
  const evidence = new Set(state.cases.flatMap((item) => item.transactions));
  const links = new Map();
  state.transactions.forEach((t) => { const key = `${t.source}|${t.target}`; if (!links.has(key) || evidence.has(t.id)) links.set(key, t); });
  links.forEach((t) => {
    const from = nodes.get(t.source), to = nodes.get(t.target);
    if (!from || !to) return;
    const focus = state.account && (t.source === state.account || t.target === state.account);
    const risk = evidence.has(t.id);
    ctx.strokeStyle = focus ? '#0c8678' : risk ? '#d5a176' : '#c4d9d8';
    ctx.lineWidth = focus ? 2 : risk ? 1.6 : .7;
    ctx.globalAlpha = state.account && !focus ? .2 : risk ? .8 : .45;
    const dx = to.x - from.x, dy = to.y - from.y, length = Math.hypot(dx, dy);
    if (!length) return;
    const endX = to.x - dx / length * 13, endY = to.y - dy / length * 13;
    ctx.beginPath(); ctx.moveTo(from.x, from.y); ctx.lineTo(endX, endY); ctx.stroke();
    const angle = Math.atan2(dy, dx);
    ctx.beginPath(); ctx.moveTo(endX, endY); ctx.lineTo(endX - 5 * Math.cos(angle - .5), endY - 5 * Math.sin(angle - .5));
    ctx.moveTo(endX, endY); ctx.lineTo(endX - 5 * Math.cos(angle + .5), endY - 5 * Math.sin(angle + .5)); ctx.stroke();
  });
  ctx.globalAlpha = 1;
  nodes.forEach((node, id) => {
    const selected = id === state.account;
    ctx.beginPath(); ctx.arc(node.x, node.y, selected ? 15 : 11, 0, Math.PI * 2);
    ctx.fillStyle = selected ? '#127e74' : node.flagged ? '#fff3e6' : '#e6f3f0'; ctx.fill();
    ctx.lineWidth = selected ? 2 : 1.5; ctx.strokeStyle = selected ? '#0b514b' : node.flagged ? '#d5a071' : '#6aaea5'; ctx.stroke();
    ctx.fillStyle = selected ? '#fff' : node.flagged ? '#b9824d' : '#4c988d';
    ctx.beginPath(); ctx.arc(node.x, node.y, 3, 0, Math.PI * 2); ctx.fill();
    ctx.font = '9px Segoe UI'; ctx.textAlign = 'center'; ctx.fillStyle = '#79909c';
    ctx.fillText(id.replace('ACC-', ''), node.x, node.y + 25);
  });
}
function drawGraphs() { drawGraph($('#overview-graph')); drawGraph($('#explorer-graph')); }
$$('canvas').forEach((canvas) => {
  canvas.addEventListener('click', (event) => {
    const rect = canvas.getBoundingClientRect();
    const node = [...(graphNodes.get(canvas.id)?.values() || [])].find((n) => Math.hypot(n.x - (event.clientX - rect.left), n.y - (event.clientY - rect.top)) < 18);
    if (node) { selectAccount(node.account.id); page('network'); }
  });
  canvas.addEventListener('mousemove', (event) => {
    const rect = canvas.getBoundingClientRect();
    const node = [...(graphNodes.get(canvas.id)?.values() || [])].find((n) => Math.hypot(n.x - (event.clientX - rect.left), n.y - (event.clientY - rect.top)) < 18);
    canvas.title = node ? `${node.account.id} · ${node.account.name}` : '';
    canvas.style.cursor = node ? 'pointer' : 'default';
  });
});
window.addEventListener('resize', drawGraphs);
initialize();
