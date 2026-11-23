'use strict';
const T = window.__TAURI__;
const invoke = T.core.invoke;
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const fmtB = b => {
  b = +b || 0;
  if (b >= 1073741824) return (b / 1073741824).toFixed(1) + ' GB';
  if (b >= 1048576) return (b / 1048576).toFixed(1) + ' MB';
  if (b >= 1024) return Math.round(b / 1024) + ' KB';
  return b + ' B';
};
const fmtR = b => (b ? fmtB(b) + '/s' : '–');
const ago = t => {
  if (!t) return '–';
  const s = Math.max(0, (Date.now() - t) / 1000);
  if (s < 5) return 'now';
  if (s < 60) return Math.floor(s) + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return new Date(t).toLocaleDateString();
};
const clock = t => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
const SEV = { 3: 'High', 2: 'Medium', 1: 'Low' };
const RULES = {
  exfil_site: 'Uploads to file-sharing, paste and bot sites',
  upload: 'Large uploads',
  ip_lookup: 'Public IP lookups',
  catcher: 'Request-catcher services',
  tunnel: 'Tunnels and dynamic DNS',
  lolbin: 'Windows tools going online',
  script: 'Script hosts going online',
  bad_port: 'Suspicious ports',
  odd_port: 'Uploads on non-standard ports',
  risky_folder: 'Programs in download/temp folders',
  bad_signature: 'Broken signatures',
  unsigned: 'Unsigned programs sending data',
  bare_ip: 'Data to bare IP addresses',
  beacon: 'Timed check-ins (beaconing)',
  dns_odd: 'Unusual DNS names',
  dns_tunnel: 'DNS tunnelling',
  new_app: 'First time online',
  mail_out: 'Programs sending email by themselves',
  ftp_out: 'Programs using FTP',
  remote_session: 'Screen sharing and remote control',
  inbound: 'Incoming connections',
  smb_copy: 'Files copied from shared folders',
  secret_read: 'Programs opening passwords, cookies or wallets',
  secret_upload: 'Password files read, then data sent',
  docs_upload: 'Documents collected, then uploaded',
  trust_broken: 'Trusted programs that changed',
  monitor_stopped: 'Monitoring stopped',
  monitor_blind: 'No network events',
  fw_rules_removed: 'Firewall blocks deleted',
  fw_off: 'Firewall turned off',
  defender_off: 'Defender turned off',
  defender_exclusion: 'Defender exclusions',
  root_cert: 'New root certificates',
  hosts_changed: 'Hosts file changes',
  proxy_changed: 'Proxy changes',
  startup_new: 'New programs starting with Windows',
  dns_changed: 'New DNS servers',
  rdp_on: 'Remote Desktop turned on',
  known_bad: 'Known malware servers',
  malware_hash: 'Known malware files',
  defender_found: 'Found by Microsoft Defender',
  cam_mic: 'Camera and microphone use',
  cam_mic_use: 'Camera or microphone turned on',
  update: 'New Kestryl version',
  away_upload: 'Data sent while you were away',
  clipboard_swap: 'Copied wallet or bank numbers swapped',
  decrypt_session: 'HTTPS decryption started or ended',
  decrypt_password: 'HTTPS decryption password',
};
// Ports for incoming connections in History (the live tables get the name from Kestryl).
const SVC = { 3389: 'Remote Desktop', 445: 'file sharing (SMB)', 139: 'file sharing (NetBIOS)', 22: 'SSH', 23: 'Telnet', 5900: 'VNC', 5985: 'WinRM', 5986: 'WinRM', 80: 'web', 443: 'web (HTTPS)', 7680: 'Delivery Optimization', 5357: 'network discovery' };
const CLASS = { system: 'Windows folder', installed: 'Program Files', user: 'User folder', risky: 'Download / temp folder', unknown: 'Unknown (no access)' };

const clockShort = t => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
const mmss = ms => { const s = Math.max(0, Math.round(ms / 1000)); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`; };
const fmtDay = t =>new Date(t).toLocaleDateString([], { day: 'numeric', month: 'short', year: 'numeric' });
const cssv = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();

// "JP" -> "Japan"; "??" -> "Unknown".
const ccName = (() => {
  let dn = null;
  try { dn = new Intl.DisplayNames(['en'], { type: 'region' }); } catch (e) { /* older WebView */ }
  return cc => {
    if (!cc || cc === '??') return 'Unknown';
    try { const n = dn && dn.of(cc); if (n && n !== cc) return n; } catch (e) { /* not a region code */ }
    return (typeof WORLD !== 'undefined' && WORLD.c[cc] && WORLD.c[cc].n) || cc;
  };
})();
const HOST_NOTE = 'Runs servers for thousands of other sites and apps, so its name says whose computer it is, not whose site. The site name tells you who you really talked to.';
// "Japan · Google" for a connection (empty for the local network).
const placeOf = f => [f.cc ? ccName(f.cc) : '', f.org ? f.org + (f.host ? ' (hosting)' : '') : ''].filter(Boolean).join(' · ');
const analyticsTag = f => (f.analytics ? ' <span class="tag" data-pop="Usage data (telemetry) sent to the maker of the program. It can be turned off on the Blocking tab, under Analytics and telemetry.">analytics</span>' : '');
// Friendly name of a program row ("Microsoft Edge" for msedge.exe).
const friendly = p => { const L = progInfo(p); return L ? L.n : p.name; };

// Where a program file came from (Mark of the Web), as HTML.
function originHtml(o) {
  if (!o || !o.kind) return '';
  const when = o.created ? fmtDay(o.created) : '';
  if (o.kind === 'download') {
    const odd = oddSource(o.site);
    return `Downloaded from <b>${esc(o.site || 'the internet (site not recorded)')}</b>${when ? ' on ' + when : ''}` +
      (odd ? ` <span class="tag med hint" data-pop="${esc(odd)}">worth a look</span>` : '') +
      (o.url ? `<div class="sub mono adv">${esc(o.url)}</div>` : '') +
      (o.referrer ? `<div class="sub adv">linked from ${esc(o.referrer)}</div>` : '');
  }
  const t = {
    store: 'Installed from the Microsoft Store',
    windows: 'Part of Windows',
    installed: 'Installed in Program Files' + (when ? ' on ' + when : ''),
    local: 'No download note: installed by another program, copied from a USB stick or network folder, or made on this PC' + (when ? `. File dated ${when}` : ''),
    gone: 'The file is no longer there',
  }[o.kind];
  return t ? esc(t) + '.' : '';
}
const originShort = o => (o && o.kind === 'download' ? `downloaded from ${o.site || 'the internet'}` : o && o.kind === 'store' ? 'from the Microsoft Store' : '');

// One colour per program: the five busiest of the last two minutes keep theirs while they stay busy.
const SLOTS = ['--s1', '--s2', '--s3', '--s4', '--s5'];
const slotOf = new Map();
const colOf = name => cssv(slotOf.get(name) || '--s6');
const sw = name => `<span class="sw" style="background:${colOf(name)}"></span>`;

const state = {
  alertSel: null, theme: 'kestryl', connSub: '', snapN: 0, connSel: null,
  tab: 'status', snap: null, sel: null, sort: { key: 'activity', dir: -1 },
  alertSev: 0, alerts: [], alertSig: '', open: new Set(), rules: null, settings: null, autostart: null, netExtra: null,
  status: null, statusAt: 0, checking: false, hist: null, histDays: [], histDay: null, histErr: '', histOpen: new Set(),
  adv: false, analytics: null, places: null, placesDay: null, placesErr: '', placesSel: null, placesAt: 0,
  dec: { st: null, list: [], open: new Set(), reveal: false, pick: '', sig: '' },
};

// ---------------------------------------------------------------- feedback

let flashTimer;
function flash(msg, err = false) {
  const f = $('#flash');
  f.textContent = msg;
  f.className = 'flash' + (err ? ' err' : '');
  f.hidden = false;
  clearTimeout(flashTimer);
  flashTimer = setTimeout(() => (f.hidden = true), err ? 7000 : 4500);
}

// Yes/no dialog. With `pw`, it also asks for a password and resolves to it (null on Cancel).
function ask(title, body, yes = 'OK', pw = false) {
  return new Promise(res => {
    $('#modal-title').textContent = title;
    $('#modal-body').textContent = body;
    $('#modal-yes').textContent = yes;
    const inp = $('#modal-pw');
    inp.value = '';
    inp.hidden = !pw;
    $('#modal').hidden = false;
    const done = v => {
      const val = inp.value;
      inp.value = '';
      inp.hidden = true;
      inp.onkeydown = null;
      $('#modal').hidden = true;
      $('#modal-yes').onclick = $('#modal-no').onclick = null;
      res(pw ? (v && val ? val : null) : v);
    };
    $('#modal-yes').onclick = () => done(true);
    $('#modal-no').onclick = () => done(false);
    if (pw) {
      inp.placeholder = 'Decryption password';
      inp.onkeydown = e => { if (e.key === 'Enter') done(true); if (e.key === 'Escape') done(false); };
      setTimeout(() => inp.focus(), 30);
    }
  });
}
const askPassword = (title, body, yes) => ask(title, body, yes, true);

// Hover pop-up for any element with data-pop (plain text, wrapped, newlines kept).
const pop = Object.assign(document.createElement('div'), { className: 'pop', hidden: true });
document.body.append(pop);
function hidePop() { pop.hidden = true; pop.anchor = null; }
document.addEventListener('mouseover', e => {
  const el = e.target.closest('[data-pop]');
  if (el === pop.anchor) return;
  if (!el) return hidePop();
  pop.anchor = el;
  pop.textContent = el.dataset.pop;
  pop.hidden = false;
  const r = el.getBoundingClientRect();
  let y = r.bottom + 6;
  if (y + pop.offsetHeight > innerHeight - 8) y = Math.max(8, r.top - pop.offsetHeight - 6);
  pop.style.left = Math.max(8, Math.min(r.left, innerWidth - pop.offsetWidth - 8)) + 'px';
  pop.style.top = y + 'px';
});
document.addEventListener('scroll', hidePop, true);

// Collapsed "how to read this" block under a heading.
const help = (key, items, label = 'How to read this') =>
  `<details class="help" data-h="${key}"><summary>${label}</summary><ul>${items.map(i => `<li>${i}</li>`).join('')}</ul></details>`;

async function act(cmd, args, btn) {
  if (btn) btn.disabled = true;
  try {
    const msg = await invoke(cmd, args);
    if (msg) flash(msg);
    return true;
  } catch (e) {
    flash(String(e), true);
    return false;
  } finally {
    if (btn) btn.disabled = false;
  }
}

// ---------------------------------------------------------------- shared actions

async function blockApp(exe, pid, name, btn) {
  if (!exe) return flash('This process has no file path (it is part of Windows). Block its destination instead.', true);
  if (!(await ask(`Block ${name}?`, `${name} will not be able to send or receive anything over the network until you remove the rule on the Blocking tab. Open connections are closed now.`, 'Block'))) return;
  const ok = await act('block_app', { exe, pid }, btn);
  if (ok) loadRules();
  return ok;
}
async function blockIp(ip, btn) {
  if (!(await ask(`Block ${ip}?`, 'No program on this PC will be able to reach this address.', 'Block'))) return;
  if (await act('block_ip', { ip }, btn)) loadRules();
}
async function blockDomain(domain, btn) {
  if (!(await ask(`Block ${domain}?`, `Blocks every address ${domain} resolves to, for all programs. Big sites share servers (CDNs), so this can also block other sites hosted on the same addresses.`, 'Block'))) return;
  if (await act('block_domain', { domain }, btn)) loadRules();
}
async function kill(pid, name, btn) {
  if (!(await ask(`End ${name}?`, 'The process is closed immediately; unsaved work in it is lost.', 'End process'))) return;
  await act('kill', { pid }, btn);
}
// Trusted IP / domain: hidden from views (unless "show traffic") and never alerted.
async function trustDest(target, site, btn) {
  if (await act('trust_dest', { target, site: !!site }, btn)) { loadSettings(); tick(); }
}
const trustBtn = f => (f.trusted ? '' : `<button class="btn sm" data-a="trust" data-v="${esc(f.domain || f.ip)}" data-site="${f.domain ? 1 : ''}" title="Trust ${esc(f.domain ? 'this site and its subdomains' : f.ip)}: hide its traffic, never alert">Trust</button>`);
const trustTag = f => (f.trusted ? ' <span class="tag ok">trusted</span>' : '');
// One of Google's, Microsoft's or Apple's own services (Settings → Known-safe services).
const safeTag = f => (f.safe ? ` <span class="tag" data-pop="${esc(f.safe)}'s own service, from the list ${esc(f.safe)} publishes (Settings → Known-safe services). Alerts that only say a destination looks unusual stay quiet for normal programs; upload and stealer alerts do not.">${esc(f.safe)}</span>` : '');
const isIpTarget = t => /^\d{1,3}(\.\d{1,3}){3}(\/\d+)?$/.test(t) || t.includes(':');

const trust = (exeKey, on, btn) => act('trust', { exeKey, on }, btn).then(() => loadSettings());
const reveal = path => invoke('reveal', { path }).catch(e => flash(String(e), true));

// ---------------------------------------------------------------- header

// Header sparkline: download as a soft area, upload as a line, last two minutes.
function drawChart(hist) {
  const c = $('#chart');
  const dpr = window.devicePixelRatio || 1;
  const w = 120, h = 32;
  if (c.width !== w * dpr) { c.width = w * dpr; c.height = h * dpr; }
  const g = c.getContext('2d');
  g.setTransform(dpr, 0, 0, dpr, 0, 0);
  g.clearRect(0, 0, w, h);
  const pts = hist.slice(-120);
  if (pts.length < 2) return;
  const step = w / 119, x0 = w - (pts.length - 1) * step;
  const path = (i, max) => pts.forEach((v, j) => { const x = x0 + j * step, y = h - 1 - (v[i] / max) * (h - 3); j ? g.lineTo(x, y) : g.moveTo(x, y); });
  const dmax = Math.max(8192, ...pts.map(x => x[1])) * 1.1, umax = Math.max(4096, ...pts.map(x => x[0])) * 1.1;
  g.beginPath(); path(1, dmax); g.lineTo(w, h); g.lineTo(x0, h); g.closePath();
  g.globalAlpha = .22; g.fillStyle = cssv('--tx3'); g.fill(); g.globalAlpha = 1;
  g.beginPath(); path(0, umax); g.strokeStyle = cssv('--accent'); g.lineWidth = 1.5; g.lineJoin = 'round'; g.stroke();
}

const TITLES = { status: 'Status', activity: 'Activity', connections: 'Connections', alerts: 'Alerts', history: 'History', dns: 'DNS lookups', network: 'Network', blocked: 'Blocking', settings: 'Settings', places: 'Where data went', decrypt: 'HTTPS decryption' };
function pageSub() {
  const s = state.snap;
  switch (state.tab) {
    case 'status': return state.status && state.status.audit_t ? `Windows settings checked ${ago(state.status.audit_t)}` : 'Checking this PC…';
    case 'activity': return 'Live, last 2 minutes';
    case 'connections': return state.connSub;
    case 'alerts': return s ? `${s.unread} unread` : '';
    case 'history': return 'What every program sent and received, per day, for 30 days';
    case 'dns': return 'Every name a program looked up';
    case 'network': return 'Adapters, connection settings, devices and open ports';
    case 'blocked': return 'Windows Firewall rules made by Kestryl';
    case 'places': return 'The countries and companies your programs sent data to';
    case 'decrypt': return 'Read what one program sends inside its encrypted connections';
    default: return '';
  }
}

function renderTop() {
  const s = state.snap;
  $('#up').textContent = fmtR(s.up);
  $('#down').textContent = fmtR(s.down);
  drawChart(s.history);
  const full = s.mode === 'full';
  const mode = full
    ? `<span><span class="dot"></span>Full monitoring</span>`
    : `<span><span class="dot warn"></span>${s.mode === 'limited' ? 'Limited mode' : 'Starting'}</span>` +
      (s.elevated ? '' : `<button class="btn sm" id="elevate">Restart as administrator</button>`);
  if ($('#mode').dataset.html !== mode) {
    $('#mode').dataset.html = mode;
    $('#mode').innerHTML = mode;
    const eb = $('#elevate');
    if (eb) eb.onclick = () => act('restart_admin', {}, eb);
  }

  const b = [];
  const dec = s.decrypt;
  if (dec) {
    b.push(`<div class="banner dec"><i class="ic">&#xE72E;</i><span><b>HTTPS decryption is on</b> for ${esc(dec.name)}: Kestryl can read what it sends. Stops by itself in <b class="num" id="bn-left"></b>.${dec.sim ? ' (simulation)' : ''}</span><div class="grow"></div>
      <button class="btn sm adv" data-bn="open">Show what it sent</button><button class="btn sm" data-bn="stop">Stop now</button></div>`);
  }
  if (s.sim) b.push(`<div class="banner warn"><b>Simulation.</b> The programs invoice_viewer.exe, updater.exe, svc_helper.exe, syncsvc.exe and the extra powershell.exe / chrome.exe rows are fake, as are the clipboard swap, the "while you were away" report and the places, to show what alerts look like.</div>`);
  if (!full && s.mode === 'limited' && !s.elevated) b.push(`<div class="banner">Limited mode only sees which programs hold TCP connections. Byte counts, UDP, DNS names, upload alerts and blocking need administrator rights.</div>`);
  if (s.etw_error) b.push(`<div class="banner bad">Kernel network tracing could not start: ${esc(s.etw_error)}</div>`);
  if (s.health && s.health.net === false) b.push(`<div class="banner bad"><b>Network monitoring was stopped by another program.</b> Kestryl is restarting it; see Alerts.</div>`);
  if (state.rules && state.rules.cut_off) b.push(`<div class="banner bad"><b>Internet is cut off.</b> Programs cannot connect until you restore it.</div>`);
  if (state.rules && state.rules.firewall_off.length) b.push(`<div class="banner warn">Windows Firewall is off for ${esc(state.rules.firewall_off.join(', '))}, so blocks don't apply there.</div>`);
  if (s.learning) b.push(`<div class="banner">Learning which programs normally go online. "First time online" alerts start after 10 minutes.</div>`);
  setHtml($('#banners'), b.join(''));
  if (dec && $('#bn-left')) $('#bn-left').textContent = mmss(dec.until - Date.now());

  const cnt = $('#alert-count');
  cnt.textContent = s.unread ? (s.unread > 99 ? '99+' : s.unread) : '';
  cnt.className = 'b' + (s.unread_high ? ' hot' : '');
  const cut = state.rules && state.rules.cut_off;
  const cb = $('#cutoff');
  const lbl = cut ? 'Restore' : 'Cut off';
  if (cb.lastElementChild.textContent !== lbl) cb.lastElementChild.textContent = lbl;
  cb.title = cut ? 'Internet is cut off. Press to let programs connect again.' : 'Block every program from reaching the network until you restore it';
  cb.classList.toggle('on', !!cut);
  const sub = pageSub();
  if ($('#page-sub').textContent !== sub) $('#page-sub').textContent = sub;
}

$('#banners').onclick = async e => {
  const b = e.target.closest('[data-bn]');
  if (!b) return;
  if (b.dataset.bn === 'open') switchTab('decrypt');
  if (b.dataset.bn === 'stop' && (await act('decrypt_stop', {}, b))) { tick(); if (state.tab === 'decrypt') loadDecrypt(); }
};

$('#cutoff').onclick = async e => {
  const on = !(state.rules && state.rules.cut_off);
  if (on && !(await ask('Cut off the internet?', 'Every program is blocked from opening new network connections (Windows Firewall default: block outbound). Use this if you think something is stealing data right now. Press "Restore internet" to undo.', 'Cut off'))) return;
  if (await act('set_cutoff', { on }, e.currentTarget)) loadRules();
};

// ---------------------------------------------------------------- activity

function procTags(p) {
  // Kestryl itself and the helpers it starts: never a risk, never alerted.
  if (p.own) return '<span class="tag ok hint" data-pop="This is Kestryl itself, or a helper it started (signature checks, Defender scans). Kestryl never alerts about its own work.">Kestryl</span>';
  const t = [];
  if (p.sim) t.push('<span class="tag med">simulated</span>');
  const look = lookalike(p);
  if (look) t.push(`<span class="tag ${look.includes(', but signed by') ? 'med' : 'high'} hint" data-pop="${esc(look)}">look-alike name</span>`);
  if (p.class === 'risky') t.push('<span class="tag high">temp/download folder</span>');
  if (p.sig === 'invalid') t.push('<span class="tag high">broken signature</span>');
  else if (p.sig === 'unsigned') t.push('<span class="tag med">unsigned</span>');
  else if (p.sig === 'untrusted') t.push('<span class="tag med">untrusted signer</span>');
  if (p.script === 'lolbin') t.push('<span class="tag high">Windows tool</span>');
  else if (p.script === 'shell') t.push('<span class="tag med">script host</span>');
  else if (p.script === 'interpreter') t.push('<span class="tag">interpreter</span>');
  if (p.browser) t.push('<span class="tag">browser</span>');
  if (p.remote) t.push(`<span class="tag med">remote control: ${esc(p.remote)}</span>`);
  if (p.secrets) t.push('<span class="tag high">opened passwords</span>');
  if (p.incoming) t.push(`<span class="tag">${p.incoming} incoming</span>`);
  if (p.trust_broken) t.push('<span class="tag high">changed since trusted</span>');
  if (p.trusted) t.push('<span class="tag ok">trusted</span>');
  if (p.exited) t.push('<span class="tag">exited</span>');
  if (p.alerts) t.push(`<span class="tag high">${p.alerts} alert${p.alerts > 1 ? 's' : ''}</span>`);
  return t.join('');
}
const sigChip = p => (p.class === 'system' && p.sig === 'signed' ? '<span class="chip">Windows</span>'
  : p.sig === 'signed' ? '<span class="chip">Signed</span>' : p.sig === 'unsigned' ? '<span class="chip bad">Unsigned</span>'
  : p.sig === 'invalid' ? '<span class="chip bad">Broken</span>' : p.sig === 'untrusted' ? '<span class="chip warn">Untrusted</span>'
  : p.sig === 'pending' ? '<span class="chip">Checking</span>' : '<span class="muted">–</span>');
const publisher = p => (p.sig === 'signed' ? esc(p.signer) : p.sig === 'pending' ? '<span class="muted">checking…</span>' : p.sig === 'unknown' ? '<span class="muted">–</span>' : `<span class="muted">${esc(p.sig)}</span>`);

const COLS = [
  ['name', 'Program', ''], ['rate_out', 'Upload', 'r'], ['rate_in', 'Download', 'r'], ['out', 'Sent', 'r'],
  ['in', 'Received', 'r'], ['flows', 'Destinations', 'r'], ['signer', 'Signature', ''], ['last', 'Last active', 'r'],
];

function renderActivity() {
  const s = state.snap;
  const q = $('#proc-q').value.trim().toLowerCase();
  const inet = $('#inet-only').checked;
  let rows = s.procs.filter(p => (!inet || p.internet) && (!q || p.name.toLowerCase().includes(q) || p.exe.toLowerCase().includes(q) || friendly(p).toLowerCase().includes(q) || String(p.pid) === q));
  const { key, dir } = state.sort;
  const val = p => (key === 'activity' ? p.rate_out * 4 + p.rate_in + p.last / 1e9 : key === 'name' || key === 'signer' ? (p[key] || '').toLowerCase() : p[key]);
  rows.sort((a, b) => (val(a) > val(b) ? dir : val(a) < val(b) ? -dir : 0));
  $('#proc-sum').textContent = `${rows.length} program${rows.length === 1 ? '' : 's'} · sent ${fmtB(s.totals[0])} · received ${fmtB(s.totals[1])} since start` +
    (s.hidden_flows ? ` · ${s.hidden_flows} trusted connection${s.hidden_flows === 1 ? '' : 's'} hidden` : '');
  const head = '<thead><tr>' + COLS.map(([k, l, c]) => `<th class="sort ${c} ${key === k ? 'sorted' : ''}" data-k="${k}">${l}${key === k ? (dir < 0 ? ' ↓' : ' ↑') : ''}</th>`).join('') + '</tr></thead>';
  const body = rows.map(p => `<tr class="click ${state.sel === p.pid ? 'sel' : ''} ${p.exited ? 'dim' : ''} ${p.alerts && (p.class === 'risky' || p.sig === 'unsigned' || p.sig === 'invalid') ? 'flag' : ''}" data-pid="${p.pid}">
      <td class="pcell">${sw(p.name)}<span class="pn"><span class="pname">${esc(friendly(p))}</span><span class="sub adv" style="display:inline"> ${friendly(p) !== p.name ? esc(p.name) + ' · ' : ''}${p.pid}</span>
        <span class="sub">${p.services && p.services.length ? esc(p.services.slice(0, 3).join(', ')) + (p.services.length > 3 ? ` +${p.services.length - 3}` : '') : publisher(p)}</span>
        ${procTags(p) ? `<span class="tags">${procTags(p)}</span>` : ''}</span></td>
      <td class="r num ${p.rate_out ? 'live' : 'zero'}">${fmtR(p.rate_out)}</td>
      <td class="r num ${p.rate_in ? '' : 'zero'}">${fmtR(p.rate_in)}</td>
      <td class="r num">${fmtB(p.out)}</td><td class="r num">${fmtB(p.in)}</td>
      <td class="r num">${p.open}<span class="muted"> / ${p.flows}</span></td>
      <td>${sigChip(p)}</td>
      <td class="r num muted">${ago(p.last)}</td></tr>`).join('');
  $('#procs').innerHTML = head + '<tbody>' + (body || `<tr><td colspan="8" class="empty">${s.mode === 'starting' ? 'Starting…' : 'No programs have used the network yet.'}</td></tr>`) + '</tbody>';
}

// ---------------------------------------------------------------- activity graph

// Per-program upload/download of the last 120 seconds, fed from every snapshot (also while hidden).
const G = { len: 120, per: new Map() };
function feedGraph(s) {
  const cur = new Map();
  for (const p of s.procs) {
    if (!p.rate_out && !p.rate_in) continue;
    const a = cur.get(p.name) || [0, 0];
    a[0] += p.rate_out; a[1] += p.rate_in;
    cur.set(p.name, a);
  }
  for (const [k, v] of G.per) {
    const r = cur.get(k) || [0, 0];
    v.up.push(r[0]); v.dn.push(r[1]); v.up.shift(); v.dn.shift();
    cur.delete(k);
    if (!v.up.some(Boolean) && !v.dn.some(Boolean)) G.per.delete(k);
  }
  for (const [k, r] of cur) {
    const up = Array(G.len).fill(0), dn = Array(G.len).fill(0);
    up[G.len - 1] = r[0]; dn[G.len - 1] = r[1];
    G.per.set(k, { up, dn });
  }
  const sum = a => a.reduce((x, y) => x + y, 0);
  const top = [...G.per].map(([k, v]) => [k, sum(v.up) * 4 + sum(v.dn)]).sort((a, b) => b[1] - a[1]).slice(0, 5).map(x => x[0]);
  for (const k of [...slotOf.keys()]) if (!top.includes(k)) slotOf.delete(k);
  const used = new Set(slotOf.values());
  for (const k of top) if (!slotOf.has(k)) { const f = SLOTS.find(c => !used.has(c)); if (f) { slotOf.set(k, f); used.add(f); } }
}

// A round number of bytes/s at or above v (1, 2, 5, 10, 20, 50... KB or MB).
function niceRate(v) {
  const base = v >= 1048576 ? 1048576 : 1024;
  const x = Math.max(1, v / base);
  const e = Math.pow(10, Math.floor(Math.log10(x)));
  const m = [1, 2, 5, 10].find(k => k * e >= x);
  return m * e * base;
}
const axisB = b => (b >= 1048576 ? +(b / 1048576).toFixed(1) + ' MB' : Math.round(b / 1024) + ' KB');

function renderGraph() {
  const svg = $('#act-graph');
  const W = svg.clientWidth, H = svg.clientHeight;
  if (!W) return;
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
  const N = G.len, L = 66, T = 8, B = 20;
  const series = [...slotOf.keys()].filter(k => G.per.has(k)).map(k => ({ n: k, c: colOf(k), ...G.per.get(k) }));
  const other = { n: 'Other', c: cssv('--s6'), up: Array(N).fill(0), dn: Array(N).fill(0) };
  for (const [k, v] of G.per) if (!slotOf.has(k)) for (let i = 0; i < N; i++) { other.up[i] += v.up[i]; other.dn[i] += v.dn[i]; }
  if (other.up.some(Boolean) || other.dn.some(Boolean)) series.push(other);
  const tu = Array(N).fill(0), td = Array(N).fill(0);
  for (const s of series) for (let i = 0; i < N; i++) { tu[i] += s.up[i]; td[i] += s.dn[i]; }
  const upMax = niceRate(Math.max(8192, ...tu)), dnMax = niceRate(Math.max(65536, ...td));
  const mid = T + (H - T - B) * 0.45, upH = mid - T, dnH = H - B - mid;
  const X = i => L + i / (N - 1) * (W - L);
  const yu = v => mid - Math.min(v, upMax) / upMax * upH, yd = v => mid + Math.min(v, dnMax) / dnMax * dnH;
  const poly = (a, b, y) => a.map((v, i) => `${i ? 'L' : 'M'}${X(i).toFixed(1)},${y(v).toFixed(1)}`).join('') + b.map((_, i) => `L${X(N - 1 - i).toFixed(1)},${y(b[N - 1 - i]).toFixed(1)}`).join('') + 'Z';
  let out = '', cu = Array(N).fill(0), cd = Array(N).fill(0);
  const dop = cssv('--dn-op');
  for (const s of series) {
    const nu = cu.map((v, i) => v + s.up[i]), nd = cd.map((v, i) => v + s.dn[i]);
    out += `<path d="${poly(nu, cu, yu)}" fill="${s.c}" opacity=".9"/><path d="${poly(nd, cd, yd)}" fill="${s.c}" opacity="${dop}"/>`;
    cu = nu; cd = nd;
  }
  const gc = cssv('--grid'), t2 = cssv('--tx2');
  let grid = '';
  for (const v of [upMax, upMax / 2]) { const y = yu(v); grid += `<line x1="${L}" x2="${W}" y1="${y}" y2="${y}" stroke="${gc}"/><text x="${L - 8}" y="${y + 4}" text-anchor="end">${axisB(v)}/s</text>`; }
  for (const v of [dnMax / 2, dnMax]) { const y = yd(v); grid += `<line x1="${L}" x2="${W}" y1="${y}" y2="${y}" stroke="${gc}"/><text x="${L - 8}" y="${y + 4}" text-anchor="end">${axisB(v)}/s</text>`; }
  grid += `<text x="${L - 8}" y="${mid - 6}" text-anchor="end" fill="${t2}">Upload</text><text x="${L - 8}" y="${mid + 14}" text-anchor="end" fill="${t2}">Download</text>`;
  grid += [[0, '2 min ago'], [60, '1 min ago'], [N - 1, 'now']].map(([i, t]) => `<text x="${X(i)}" y="${H - 5}" text-anchor="${i === 0 ? 'start' : i === N - 1 ? 'end' : 'middle'}">${t}</text>`).join('');
  // The newest medium/high alert of these two minutes, marked where it happened.
  const now = Date.now();
  const a = state.alerts.find(x => x.sev >= 2 && now - x.last < 118000);
  let mark = '';
  if (a) {
    const mx = X(N - 1 - (now - a.last) / 1000), mk = cssv('--s4');
    const label = a.title.length > 64 ? a.title.slice(0, 62) + '…' : a.title;
    const left = mx > W * 0.55;
    mark = `<line x1="${mx}" x2="${mx}" y1="${T}" y2="${H - B}" stroke="${mk}" stroke-dasharray="3 3"/><circle cx="${mx}" cy="${T + 4}" r="4" fill="${mk}"/>
      <text x="${left ? mx - 10 : mx + 10}" y="${T + 8}" text-anchor="${left ? 'end' : 'start'}" fill="${cssv('--mark')}" font-weight="600">${esc(label)}</text>`;
  }
  const font = `font-family="Segoe UI Variable Text, Segoe UI" font-size="11"`;
  svg.innerHTML = `<g ${font} fill="${cssv('--tx3')}">${grid}</g>${out}<line x1="${L}" x2="${W}" y1="${mid}" y2="${mid}" stroke="${cssv('--axis')}"/><g ${font} font-size="11.5">${mark}</g>`;
  setHtml($('#act-legend'), series.length ? series.map(s => `<span><i style="background:${s.c}"></i>${esc(s.n)}</span>`).join('') : '<span class="muted">Nothing is using the network right now.</span>');
}

const destOf = a => (a.domain || a.ip ? `${a.domain || a.ip}${a.port ? ':' + a.port : ''}` : '');
function renderSide() {
  const s = state.snap;
  const online = s.procs.filter(p => p.internet && !p.exited).length;
  const open = s.procs.reduce((n, p) => n + (p.open || 0), 0);
  const inc = s.procs.reduce((n, p) => n + (p.incoming || 0), 0);
  setHtml($('#act-side'), `<h2>Right now</h2>
    <div class="stat"><span>Programs online</span><b>${online}</b></div>
    <div class="stat"><span>Open connections</span><b>${open}</b></div>
    <div class="stat"><span>Incoming connections</span><b>${inc}</b></div>
    <div class="stat"><span>Kestryl firewall rules</span><b>${state.rules ? state.rules.rules.length : '–'}</b></div>`);
}

$('#procs').onclick = e => {
  const th = e.target.closest('th[data-k]');
  if (th) {
    const k = th.dataset.k;
    state.sort = { key: k, dir: state.sort.key === k ? -state.sort.dir : k === 'name' || k === 'signer' ? 1 : -1 };
    return renderActivity();
  }
  const tr = e.target.closest('tr[data-pid]');
  if (tr) { state.sel = +tr.dataset.pid; renderActivity(); renderDetail(true); }
};
$('#proc-q').oninput = renderActivity;
$('#inet-only').onchange = renderActivity;

const dirTag = f => (f.inb ? ` <span class="tag ${f.scope === 'internet' ? 'med' : ''}" title="Another device connected to this PC">incoming</span>` : '');
const peekBtn = f => `<button class="btn sm" data-a="peek" data-v="${esc(f.ip)}" data-port="${f.port}" data-name="${esc(f.name || '')}" data-dom="${esc(f.domain || '')}" title="Capture this traffic for a few seconds and show what it is">Peek</button>`;

const flowKey = f => `${f.pid}|${f.ip}|${f.port}|${f.inb ? 1 : 0}`;
function flowRows(flows, withProc) {
  return flows.map(f => {
    const where = placeOf(f);
    const dest = (f.domain ? `${esc(f.domain)}<div class="sub mono">${esc(f.ip)}</div>` : `<span class="mono">${esc(f.ip)}</span>`) + dirTag(f) + analyticsTag(f) +
      (where ? `<div class="sub">${esc(where)}</div>` : '');
    return `<tr class="click ${f.open ? '' : 'dim'} ${state.connSel === flowKey(f) ? 'sel' : ''}" data-fk="${esc(flowKey(f))}">
      ${withProc ? `<td>${sw(f.name)}<span class="pn"><span class="pname">${esc(f.name)}</span> <span class="sub">${f.pid}</span></span></td>` : ''}
      <td class="wrap">${dest}${trustTag(f)}${safeTag(f)}</td>
      <td class="num">${f.port}${f.service ? ` <span class="sub">${esc(f.service)}</span>` : ''}${f.inb ? ' <span class="sub">on this PC</span>' : ''}</td>
      ${withProc ? `<td class="num">${f.proto.toUpperCase()}</td>` : ''}
      <td class="sub">${esc(f.enc)}</td>
      <td class="r num ${f.rate_out ? 'live' : ''}">${fmtB(f.out)}</td>
      <td class="r num">${fmtB(f.in)}</td>
      ${withProc ? `<td class="r num ${f.rate_out ? 'live' : 'zero'}">${fmtR(f.rate_out)}</td>` : ''}
      <td class="num muted"><span class="dot ${f.open ? '' : 'off'}"></span>${f.open ? 'open' : ago(f.last)}</td></tr>`;
  }).join('');
}

function onFlowAction(e) {
  const b = e.target.closest('button[data-a]');
  if (!b) return;
  if (b.dataset.a === 'info') ipInfo(b.dataset.v);
  if (b.dataset.a === 'trust') trustDest(b.dataset.v, !!b.dataset.site, b);
  if (b.dataset.a === 'ip') blockIp(b.dataset.v, b);
  if (b.dataset.a === 'dom') blockDomain(b.dataset.v, b);
  if (b.dataset.a === 'peek') peekSheet(b.dataset.v, +b.dataset.port, b.dataset.name, b.dataset.dom);
}

function renderDetail(full) {
  const d = $('#detail');
  const p = state.snap && state.snap.procs.find(x => x.pid === state.sel);
  $('#tab-activity .split').classList.toggle('with-detail', !!p);
  if (!p) { d.hidden = true; return; }
  d.hidden = false;
  if (full || d.dataset.pid != p.pid) {
    d.dataset.pid = p.pid;
    const sig = p.sig === 'signed' ? `Signed by ${esc(p.signer || 'a trusted publisher')}` : { unsigned: 'Not signed', invalid: 'Signature broken (file was modified)', untrusted: 'Signed, but by an untrusted certificate', pending: 'Checking…', unknown: 'Could not check' }[p.sig] || esc(p.sig);
    const key = (p.exe || p.name).toLowerCase();
    const L = progInfo(p);
    const look = lookalike(p);
    const what = p.own ? 'Kestryl itself, or a helper it started. Kestryl never alerts about its own work.'
      : look ? `<b class="s3">${esc(look)}</b>`
      : L ? `${esc(L.w)}<div class="sub">${esc(UPLOAD_NOTE[L.up])}</div>`
      : '<span class="muted">Not one of the common programs Kestryl knows. Check who published it and where it came from.</span>';
    const sigWord = p.sig === 'signed' ? '<span class="okt">signed</span>' : p.sig === 'pending' ? '<span>checking</span>'
      : p.sig === 'unknown' ? '<span>not checked</span>' : `<span class="badt">${p.sig === 'invalid' ? 'signature broken' : p.sig === 'untrusted' ? 'untrusted signer' : 'not signed'}</span>`;
    const sigs = procSignals(p);
    d.innerHTML = `<div class="dh"><div class="dtt">
        <h2>${esc(friendly(p))}</h2>
        <div class="sub">${[friendly(p) !== p.name ? esc(p.name) : '', `<span class="adv">pid ${p.pid}</span>`,
          p.parent_name ? `started by ${esc(p.parent_name)}<span class="adv"> (pid ${p.parent})</span>` : '', p.exited ? 'exited' : '']
          .filter(Boolean).map(x => (x.startsWith('<span class="adv">') ? x : `<span>${x}</span>`)).join('<span class="dsep"> · </span>')}</div>
        </div><button class="close-x" id="d-close" title="Close (Esc)">&#xE711;</button></div>
      <div class="idcard"><div class="it"><i class="ic">&#xE7C3;</i>Program${sigWord}</div>
        <dl>
          <dt>What it is</dt><dd>${what}</dd>
          <dt>Publisher</dt><dd>${sig}</dd>
          <dt>Came from</dt><dd id="d-origin"><span class="muted">…</span></dd>
          <dt>File</dt><dd class="mono">${p.exe ? esc(p.exe) : '<span class="muted">not visible (system process or no access)</span>'}</dd>
          <dt class="adv">Location</dt><dd class="adv">${CLASS[p.class] || ''}</dd>
          ${p.cmd ? `<dt class="adv">Command line</dt><dd class="mono adv">${esc(p.cmd)}</dd>` : ''}
          ${p.services && p.services.length ? `<dt>Services</dt><dd>${esc(p.services.join(', '))}</dd>` : ''}
          ${p.remote ? `<dt>Remote control</dt><dd>${esc(p.remote)}: lets another computer see and control this screen</dd>` : ''}
        </dl></div>
      <div class="facts">
        <div class="fact"><small>Sent</small><b id="d-out"></b></div>
        <div class="fact"><small>Received</small><b id="d-in"></b></div>
        <div class="fact"><small>Upload now</small><b id="d-rate"></b></div>
      </div>
      ${sigs ? `<h3>Signals</h3><div class="sigs">${sigs}</div>` : ''}
      <div id="d-scan"></div>
      <div id="d-files"></div>
      <h3>Destinations</h3>
      <div class="dests" id="d-flows"></div>
      <div class="actions dfoot">
        <button class="btn danger" id="d-block">Block internet for this app</button>
        <button class="btn" id="d-trust">${p.trusted ? 'Stop trusting' : 'Trust (no alerts)'}</button>
        <button class="btn" id="d-kill">End process</button>
        ${p.exe ? '<button class="btn" id="d-show">Show file</button>' : ''}
        ${p.exe && !p.own ? '<button class="btn adv" id="d-dec" title="Read what this program sends inside HTTPS, for a few minutes, with your decryption password">Decrypt HTTPS…</button>' : ''}
      </div>`;
    $('#d-close').onclick = () => { state.sel = null; renderDetail(); renderActivity(); };
    $('#d-block').onclick = e => blockApp(p.exe, p.pid, p.name, e.currentTarget);
    $('#d-trust').onclick = e => trust(key, !p.trusted, e.currentTarget).then(() => renderDetail(true));
    $('#d-kill').onclick = e => kill(p.pid, p.name, e.currentTarget);
    if (p.exe) $('#d-show').onclick = () => reveal(p.exe);
    if ($('#d-dec')) $('#d-dec').onclick = () => { state.dec.pick = p.exe.toLowerCase(); state.dec.sig = ''; switchTab('decrypt'); };
    $('#d-flows').onclick = onFlowAction;
  }
  $('#d-out').textContent = fmtB(p.out);
  $('#d-in').textContent = fmtB(p.in);
  $('#d-rate').textContent = fmtR(p.rate_out);
}

// The program's tags as rows in the drawer: red = act on it, amber = worth a look, green = fine, grey = information.
function procSignals(p) {
  const t = document.createElement('template');
  t.innerHTML = procTags(p);
  return [...t.content.querySelectorAll('.tag')].map(tag => {
    const k = tag.classList.contains('high') ? 'h' : tag.classList.contains('med') ? 'm' : tag.classList.contains('ok') ? 'o' : 'n';
    const pop = tag.dataset.pop ? ` hint" data-pop="${esc(tag.dataset.pop)}` : '';
    return `<div class="signal ${k}${pop}"><i class="ic">${k === 'o' ? '&#xE73E;' : k === 'n' ? '&#xE946;' : '&#xE7BA;'}</i>${esc(tag.textContent)}</div>`;
  }).join('');
}

// The drawer floats over the page: a click outside it or Esc closes it.
$('#tab-activity .split').addEventListener('click', e => {
  if (e.target === e.currentTarget && e.currentTarget.classList.contains('with-detail')) $('#d-close').click();
});
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && !$('#detail').hidden && $('#sheet').hidden && $('#modal').hidden) $('#d-close').click();
});

$('#detail').addEventListener('click', async e => {
  const b = e.target.closest('[data-d]');
  const p = state.snap && state.snap.procs.find(x => x.pid === state.sel);
  if (!b || !p) return;
  if (b.dataset.d === 'scan') {
    b.disabled = true;
    b.textContent = 'Scanning…';
    try {
      const r = await invoke('scan_file', { path: p.exe });
      flash(r.state === 'threat' ? `Microsoft Defender: ${r.threat}` : r.state === 'clean' ? 'Microsoft Defender found no threats in this file.' : r.err, r.state !== 'clean');
    } catch (err) { flash(String(err), true); }
    renderDetailFlows();
  }
  if (b.dataset.d === 'vt') {
    const h = (b.closest('.scanbox').querySelector('.hash') || {}).textContent || '';
    invoke('open_virustotal', { sha256: h.replace('SHA-256 ', '').trim() }).catch(err => flash(String(err), true));
  }
});

async function renderDetailFlows() {
  if (state.sel == null || $('#detail').hidden) return;
  renderDetail(false);
  const [flows, extra] = await Promise.all([invoke('flows', { pid: state.sel }), invoke('proc_extra', { pid: state.sel })]);
  const box = $('#d-flows');
  if (!box) return;
  const sec = extra.secrets || [];
  const docs = extra.docs;
  const p = state.snap.procs.find(x => x.pid === state.sel);
  setHtml($('#d-origin'), originHtml(extra.origin) || '<span class="muted">Unknown</span>');
  const sc = extra.scan;
  const scanState = !sc ? '<span class="sub">not scanned yet</span>'
    : sc.state === 'threat' ? `<span class="tag high">${esc(sc.threat)}</span>`
    : sc.state === 'clean' ? `<span class="tag ok">no threats</span><span class="sub">${ago(sc.t)}</span>`
    : sc.state === 'running' ? '<span class="sub">scanning…</span>' : `<span class="sub">${esc(sc.err)}</span>`;
  setHtml($('#d-scan'), p && p.exe ? `<div class="scanbox"><div class="l1"><b>Microsoft Defender</b>${scanState}<div class="grow"></div>
      <button class="btn sm" data-d="scan" ${sc && sc.state === 'running' ? 'disabled' : ''}>${sc && sc.state !== 'running' ? 'Scan again' : 'Scan file'}</button>
      ${sc && sc.sha256 ? '<button class="btn sm" data-d="vt" title="Opens this file\'s VirusTotal page in your browser. Only its fingerprint (SHA-256) is sent, nothing else.">VirusTotal</button>' : ''}</div>
      ${sc && sc.sha256 ? `<div class="hash adv">SHA-256 ${esc(sc.sha256)}</div>` : ''}</div>` : '');
  setHtml($('#d-files'), sec.length || (docs && docs.n) ? `<h3>Files it opened</h3><div class="dests">${sec.map(h => `<div class="dest">
      <div class="l1"><span class="dn">${esc(h.label)}</span>${h.uploaded ? '<span class="tag high">then sent data</span>' : ''}<span class="st">${ago(h.t)}</span></div>
      <div class="l2"><span class="sub mono">${esc(h.path)}</span></div></div>`).join('')}
    ${docs && docs.n ? `<div class="dest"><div class="l1"><span class="dn">${docs.n} of your documents or photos${docs.collected ? ' (counts as collecting)' : ''}</span></div>
      <div class="l2"><span class="sub mono">${docs.sample.map(esc).join('<br>')}</span></div></div>` : ''}</div>` : '');
  box.innerHTML = flows.map(f => `<div class="dest ${f.open ? '' : 'dim'}">
      <div class="l1"><span class="dn">${esc(f.domain || f.ip)}${trustTag(f)}${dirTag(f)}${analyticsTag(f)}</span>
        <span class="num ${f.rate_out ? 'live' : ''}">${fmtB(f.out)} out</span><span class="num muted">${fmtB(f.in)} in</span>
        <span class="st">${f.open ? 'open' : ago(f.last)}</span></div>
      <div class="l2"><span class="sub">${f.host ? `<span class="hint" data-pop="${esc(HOST_NOTE)}">${esc(placeOf(f))}</span>` : esc(placeOf(f))}<span class="mono adv">${placeOf(f) ? ' · ' : ''}${f.domain ? esc(f.ip) + ' · ' : ''}${f.proto.toUpperCase()} ${f.port}${f.service ? ' ' + esc(f.service) : ''} · ${esc(f.enc)}</span></span>
        ${f.scope === 'internet' ? `<span class="adv"><button class="btn sm" data-a="info" data-v="${esc(f.ip)}">IP info</button>${peekBtn(f)}</span>${trustBtn(f)}<button class="btn sm adv" data-a="ip" data-v="${esc(f.ip)}">Block IP</button>${f.domain ? `<button class="btn sm" data-a="dom" data-v="${esc(f.domain)}">Block site</button>` : ''}` : `<span class="adv">${f.scope === 'lan' ? peekBtn(f) : ''}</span>${trustBtn(f)}<span class="sub">${f.scope === 'lan' ? 'local network' : esc(f.scope)}</span>`}</div>
    </div>`).join('') || '<div class="empty">No destinations yet.</div>';
}

// ---------------------------------------------------------------- connections

async function renderConnections() {
  const flows = await invoke('flows', { pid: null });
  const q = $('#conn-q').value.trim().toLowerCase();
  const sc = $('#conn-scope').dataset.value;
  const dir = $('#conn-dir').dataset.value;
  const openOnly = $('#open-only').checked;
  const hideSafe = $('#hide-safe').checked;
  const rows = flows.filter(f =>
    (sc === 'all' || (sc === 'internet' ? f.scope === 'internet' : f.scope !== 'internet')) &&
    (dir === 'all' || (dir === 'in') === !!f.inb) &&
    (!openOnly || f.open) &&
    (!hideSafe || !f.safe) &&
    (!q || f.name.toLowerCase().includes(q) || f.domain.includes(q) || f.ip.includes(q) || String(f.port) === q));
  $('#conn-sum').textContent = `${rows.length} of ${flows.length}`;
  state.connSub = `${flows.filter(f => f.open).length} open, ${flows.length} in the last 15 minutes`;
  $('#conns').innerHTML = `<thead><tr><th>Program</th><th>Remote address</th><th>Port</th><th>Proto</th><th>Encryption</th><th class="r">Sent</th><th class="r">Received</th><th class="r">Upload</th><th>Status</th></tr></thead><tbody>` +
    (flowRows(rows, true) || '<tr><td colspan="9" class="empty">Nothing matches.</td></tr>') + '</tbody>';
  renderConnInfo(flows.find(f => flowKey(f) === state.connSel));
}

// The selected connection: what it is, and every action on it.
function renderConnInfo(f) {
  const box = $('#conn-info');
  $('#conn-grid').classList.toggle('with-info', !!f);
  box.hidden = !f;
  if (!f) return;
  const inet = f.scope === 'internet';
  setHtml(box, `<div class="ph">Connection<button class="close-x" data-a="close" title="Close" style="margin-left:auto">&#xE711;</button></div>
    <div class="ipn">${esc(f.ip)}</div>
    ${f.domain ? `<div class="dom">${esc(f.domain)}</div>` : '<div class="dom muted">No name looked up</div>'}
    <div class="tags">${f.inb ? `<span class="tag ${inet ? 'med' : ''}">incoming</span>` : ''}<span class="tag">${esc(inet ? 'internet' : f.scope === 'lan' ? 'local network' : f.scope)}</span>${f.trusted ? '<span class="tag ok">trusted</span>' : ''}${f.safe ? `<span class="tag">${esc(f.safe)} service</span>` : ''}</div>
    <dl class="kv">
      <dt>Program</dt><dd>${sw(f.name)}<span class="pn"><b>${esc(f.name)}</b> <span class="sub">pid ${f.pid}</span></span></dd>
      ${f.cc ? `<dt>Country</dt><dd>${esc(ccName(f.cc))}</dd>` : ''}
      ${f.org ? `<dt>Company</dt><dd>${esc(f.org)}${f.host ? `<div class="sub">${esc(HOST_NOTE)}</div>` : ''}</dd>` : ''}
      ${f.analytics ? '<dt>Purpose</dt><dd>Usage data (telemetry) for the maker. Can be turned off on the Blocking tab.</dd>' : ''}
      <dt>Port</dt><dd>${f.proto.toUpperCase()} ${f.port}${f.service ? ' · ' + esc(f.service) : ''}${f.inb ? ' <span class="sub">on this PC</span>' : ''}</dd>
      <dt>Encryption</dt><dd>${esc(f.enc)}</dd>
      <dt>Traffic</dt><dd>${fmtB(f.out)} sent, ${fmtB(f.in)} received</dd>
      <dt>Status</dt><dd>${f.open ? 'open' + (f.rate_out ? `, sending ${fmtR(f.rate_out)}` : '') : 'closed ' + ago(f.last)}</dd>
    </dl>
    <div class="actions">${inet ? `<button class="btn dangerf" data-a="ip" data-v="${esc(f.ip)}">Block IP</button>${f.domain ? `<button class="btn danger" data-a="dom" data-v="${esc(f.domain)}">Block site</button>` : ''}<button class="btn" data-a="info" data-v="${esc(f.ip)}">IP info</button>` : ''}
      ${inet || f.scope === 'lan' ? peekBtn(f).replace('btn sm', 'btn') : ''}${trustBtn(f).replace('btn sm', 'btn')}</div>`);
}
$('#conns').onclick = e => {
  const tr = e.target.closest('tr[data-fk]');
  if (!tr) return;
  state.connSel = state.connSel === tr.dataset.fk ? null : tr.dataset.fk;
  renderConnections();
};
$('#conn-info').onclick = e => {
  if (e.target.closest('[data-a="close"]')) { state.connSel = null; return renderConnections(); }
  onFlowAction(e);
};
['#conn-q', '#conn-scope', '#conn-dir', '#open-only', '#hide-safe'].forEach(s => ($(s).oninput = renderConnections));
// Segmented filters keep their value in data-value and fire "input" like a select would.
document.addEventListener('click', e => {
  const b = e.target.closest('.seg[data-value] > [data-v]');
  if (!b) return;
  const seg = b.parentElement;
  seg.dataset.value = b.dataset.v;
  [...seg.children].forEach(x => x.classList.toggle('on', x === b));
  seg.dispatchEvent(new Event('input'));
});

// ---------------------------------------------------------------- alerts

async function loadAlerts(force) {
  const list = await invoke('alerts');
  const sig = list.map(a => `${a.id}.${a.last}.${a.read}.${a.count}`).join('|') + state.alertSev;
  state.alerts = list;
  // Rendering the list marks the selected alert read, so only do it on the Alerts page.
  if (state.tab !== 'alerts') { state.alertSig = ''; return; }
  if (!force && sig === state.alertSig) return;
  state.alertSig = sig;
  renderAlerts();
}

function renderAlerts() {
  const n = v => state.alerts.filter(a => !v || a.sev === v).length;
  for (const v of [0, 3, 2, 1]) $('#af-' + v).textContent = n(v) || '';
  const rows = state.alerts.filter(a => !state.alertSev || a.sev === state.alertSev);
  if (!rows.length) {
    $('#alert-list').innerHTML = `<div class="agrid" style="display:block"><div class="panel empty">${state.alerts.length ? 'No alerts at this level.' : 'No alerts. Kestryl pops up when a program does something worth a look.'}</div></div>`;
    return;
  }
  if (!rows.some(a => a.id === state.alertSel)) state.alertSel = rows[0].id;
  const a = rows.find(x => x.id === state.alertSel);
  if (!a.read) { a.read = true; invoke('alert_read', { id: a.id }); }
  const list = rows.map(x => `<div class="ai ${x.id === a.id ? 'on' : ''} ${x.read ? '' : 'unread'}" data-id="${x.id}" data-t="sel">
      <div class="l1"><span class="sv s${x.sev}">${SEV[x.sev]}${x.count > 1 ? ` · ×${x.count}` : ''}</span><span class="num">${ago(x.last)}</span></div>
      <div class="t">${esc(x.title)}</div>
      <div class="w">${x.sim ? '<span class="sim">simulated · </span>' : ''}${esc(x.name)}${destOf(x) ? ' · ' + esc(destOf(x)) : ''}</div></div>`).join('');
  const dest = a.domain || a.ip ? `${esc(a.domain || a.ip)}${a.domain && a.ip ? ' <span class="sub mono adv">' + esc(a.ip) + '</span>' : ''}${a.port ? ' <span class="sub adv">port ' + a.port + '</span>' : ''}` : '';
  const same = state.alerts.filter(x => x.rule === a.rule).length;
  const L = a.system ? null : progInfo({ name: a.name, exe: a.exe });
  const detail = `<div class="adh"><span class="chip ${a.sev === 3 ? 'bad' : a.sev === 2 ? 'warn' : ''}">${SEV[a.sev]}</span>
      <span class="muted num">${new Date(a.last).toLocaleString()}${a.count > 1 ? ` · ${a.count} times since ${new Date(a.t).toLocaleString()}` : ''}${a.sim ? ' · simulated' : ''}</span></div>
    <h2>${esc(a.title)}</h2>
    <p class="why">${esc(a.why)}</p>
    <dl class="kv">
      ${a.system ? `<dt>About</dt><dd>${esc(a.name)}</dd>` : `<dt>Program</dt><dd class="mono">${esc(a.exe || a.name)}${a.pid ? ` <span class="sub adv">pid ${a.pid}</span>` : ''}</dd>
      ${L ? `<dt>What it is</dt><dd><b>${esc(L.n)}</b>: ${esc(L.w)}</dd>` : ''}
      <dt>Publisher</dt><dd>${esc(a.signer || '–')}</dd>`}
      ${a.origin ? `<dt>Came from</dt><dd>${esc(a.origin[0].toUpperCase() + a.origin.slice(1))}</dd>` : ''}
      ${a.service ? `<dt>Services</dt><dd>${esc(a.service)}</dd>` : ''}
      ${a.parent ? `<dt>Started by</dt><dd>${esc(a.parent)}</dd>` : ''}
      ${a.cmd ? `<dt class="adv">Command line</dt><dd class="mono adv">${esc(a.cmd)}</dd>` : ''}
      ${dest ? `<dt>${a.rule === 'inbound' || a.rule === 'smb_copy' ? 'From' : 'Destination'}</dt><dd>${dest}</dd>` : ''}
      ${a.bytes_out ? `<dt>Sent</dt><dd class="num">${fmtB(a.bytes_out)}</dd>` : ''}
      ${a.files && a.files.length ? `<dt>File${a.files.length > 1 ? 's' : ''}</dt><dd class="mono">${a.files.map(esc).join('<br>')}</dd>` : ''}
      <dt>Alert type</dt><dd>${esc(RULES[a.rule] || a.rule)}</dd>
    </dl>
    <div class="actions">
      ${a.rule === 'update' ? `${(state.update || {}).can_install ? '<button class="btn primary" data-t="upd-install">Update now</button>' : ''}<button class="btn" data-t="upd-page">${(state.update || {}).can_install ? 'Release page' : 'Open download page'}</button>` : ''}
      ${a.system && a.rule !== 'update' ? '<button class="btn" data-t="status">Open Status</button>' : ''}
      ${a.exe ? '<button class="btn dangerf" data-t="app">Block app</button>' : ''}
      ${a.domain ? `<button class="btn danger" data-t="dom">Block ${esc(a.domain)}</button>` : ''}
      ${a.ip ? `<button class="btn danger adv" data-t="ip">Block ${esc(a.ip)}</button>` : ''}
      ${a.ip ? '<button class="btn adv" data-t="info">IP info</button>' : ''}
      ${a.rule === 'decrypt_session' || a.rule === 'decrypt_password' ? '<button class="btn adv" data-t="decrypt">Open Decrypt</button>' : ''}
      ${a.domain || a.ip ? '<button class="btn" data-t="tdest">Trust destination</button>' : ''}
      ${a.pid > 4 ? '<button class="btn" data-t="kill">End process</button>' : ''}
      ${a.system ? '' : '<button class="btn" data-t="trust">Trust this app</button>'}
      <button class="btn" data-t="mute">Mute "${esc(RULES[a.rule] || a.rule)}"</button>
      ${a.exe ? '<button class="btn" data-t="show">Show file</button>' : ''}
      <button class="btn" data-t="dismiss">Dismiss</button>
      ${same > 1 ? `<button class="btn" data-t="dismiss-rule">Dismiss all ${same} like this</button>` : ''}
    </div>`;
  // The list and the detail panel scroll on their own (not #alert-list): keep where the user
  // was, and keep the detail position only while the same alert stays open.
  const box = $('#alert-list');
  const oldList = box.querySelector('.alist');
  const oldDet = box.querySelector('.adet');
  const listTop = oldList ? oldList.scrollTop : 0;
  const detTop = oldDet && +oldDet.dataset.id === a.id ? oldDet.scrollTop : 0;
  box.innerHTML = `<div class="agrid"><div class="panel alist">${list}</div><div class="panel adet" data-id="${a.id}">${detail}</div></div>`;
  box.querySelector('.alist').scrollTop = listTop;
  box.querySelector('.adet').scrollTop = detTop;
}

function openAlert(id) {
  state.alertSel = id;
  state.alertSev = 0;
  $$('#alert-filter button').forEach(x => x.classList.toggle('on', x.dataset.sev === '0'));
  switchTab('alerts');
  setTimeout(() => { const el = $(`.ai[data-id="${id}"]`); if (el) el.scrollIntoView({ block: 'nearest' }); }, 120);
}

$('#alert-list').onclick = async e => {
  const el = e.target.closest('[data-t]');
  const box = e.target.closest('[data-id]');
  if (!el || !box) return;
  const a = state.alerts.find(x => x.id === +box.dataset.id);
  if (!a) return;
  const t = el.dataset.t;
  if (t === 'sel') {
    state.alertSel = a.id;
    return renderAlerts();
  }
  if (t === 'app') blockApp(a.exe, a.pid, a.name, el);
  if (t === 'dom') blockDomain(a.domain, el);
  if (t === 'ip') blockIp(a.ip, el);
  if (t === 'info') ipInfo(a.ip);
  if (t === 'tdest') trustDest(a.domain || a.ip, !!a.domain, el);
  if (t === 'kill') kill(a.pid, a.name, el);
  if (t === 'show') reveal(a.exe);
  if (t === 'trust') await trust((a.exe || a.name).toLowerCase(), true, el);
  if (t === 'mute') { await act('mute', { rule: a.rule, on: true }, el); loadSettings(); }
  if (t === 'dismiss') { await invoke('alert_dismiss', { id: a.id }); loadAlerts(true); }
  if (t === 'dismiss-rule') {
    const n = state.alerts.filter(x => x.rule === a.rule).length;
    if (!(await ask(`Dismiss all ${n} alerts like this?`, `Removes every "${RULES[a.rule] || a.rule}" alert from the list. New ones still appear; use Mute to stop them.`, 'Dismiss all'))) return;
    await act('alert_dismiss_rule', { rule: a.rule }, el);
    loadAlerts(true);
  }
  if (t === 'status') switchTab('status');
  if (t === 'decrypt') switchTab('decrypt');
  if (t === 'upd-install') updateInstall(el);
  if (t === 'upd-page') invoke('update_open_page').catch(err => flash(String(err), true));
};
$('#alert-filter').onclick = e => {
  const b = e.target.closest('button');
  if (!b) return;
  $$('#alert-filter button').forEach(x => x.classList.toggle('on', x === b));
  state.alertSev = +b.dataset.sev;
  renderAlerts();
};
$('#alerts-read').onclick = async () => { await invoke('alert_read', { id: null }); loadAlerts(true); };
$('#alerts-clear').onclick = async () => {
  if (!(await ask('Clear all alerts?', 'The alert history is deleted. Blocks and trusted apps are kept.', 'Clear'))) return;
  await invoke('alert_dismiss', { id: null });
  loadAlerts(true);
};

T.event.listen('open-alert', e => openAlert(e.payload));

// ---------------------------------------------------------------- dns

const DNS_STATUS = { 0: 'ok', 9003: 'no such name', 9501: 'no records', 1460: 'timed out', 1214: 'invalid name', 87: 'cached/other' };
async function renderDns() {
  const rows = await invoke('dns');
  const q = $('#dns-q').value.trim().toLowerCase();
  const f = rows.filter(r => !q || r.name.includes(q) || r.proc.toLowerCase().includes(q) || r.answers.some(a => a.includes(q)));
  $('#dns').innerHTML = `<thead><tr><th>Time</th><th>Program</th><th>Name</th><th>Answer</th><th>Result</th><th></th></tr></thead><tbody>` +
    (f.slice(0, 600).map(r => `<tr><td class="num muted">${clock(r.t)}</td><td>${esc(r.proc)} <span class="sub">${r.pid}</span></td>
      <td class="wrap">${esc(r.name)}</td><td class="num wrap muted">${esc(r.answers.slice(0, 4).join(', '))}${r.answers.length > 4 ? ' …' : ''}</td>
      <td class="sub">${esc(DNS_STATUS[r.status] || 'error ' + r.status)}</td>
      <td>${r.flag ? `<span class="tag med">${esc(r.flag)}</span>` : ''}</td></tr>`).join('') ||
      `<tr><td colspan="6" class="empty">${state.snap && state.snap.mode === 'full' ? 'No lookups yet.' : 'DNS lookups are only visible in full monitoring (run as administrator).'}</td></tr>`) + '</tbody>';
}
$('#dns-q').oninput = renderDns;

// ---------------------------------------------------------------- network

async function loadNetExtra() {
  try { state.netExtra = await invoke('network_extra'); } catch (e) { state.netExtra = { error: String(e) }; }
  renderNetwork();
}

// Well-known ports, shown on hover in the listening-ports table.
const PORTS = {
  'tcp 135': 'RPC endpoint mapper. Windows uses it to find its own services. Always there; cannot be turned off.',
  'tcp 139': 'NetBIOS session: old-style Windows file and printer sharing.',
  'udp 137': 'NetBIOS name service: old-style name lookup on the local network.',
  'udp 138': 'NetBIOS datagram: old-style network browsing.',
  'tcp 445': 'SMB: Windows file and printer sharing. Should never be open to the internet; fine on a home/office network.',
  'tcp 3389': 'Remote Desktop. Anyone who can reach it can try passwords. Turn off in Settings → System → Remote Desktop if you do not use it.',
  'tcp 5040': 'Connected Devices Platform (CDPSvc): phone link, nearby sharing.',
  'tcp 5357': 'Network discovery (WS-Discovery over HTTP): lets other PCs see this one in Network.',
  'udp 3702': 'WS-Discovery: finding printers and PCs on the local network.',
  'udp 1900': 'SSDP / UPnP: finding TVs, media servers and routers on the local network.',
  'udp 5353': 'mDNS: device names on the local network (printers, Chromecast, phones).',
  'udp 5355': 'LLMNR: local name lookup when DNS does not know a name.',
  'tcp 7680': 'Delivery Optimization: Windows Update sharing updates between PCs.',
  'udp 123': 'Time sync (NTP).',
  'udp 68': 'DHCP: getting an IP address from the router.',
  'udp 500': 'IPsec / VPN key exchange.',
  'udp 4500': 'IPsec / VPN traffic through NAT.',
  'tcp 5985': 'WinRM: remote PowerShell management. Not on by default; turn off if you did not enable it.',
  'tcp 22': 'SSH server.',
  'tcp 80': 'Web server (HTTP). On Windows often the built-in HTTP.sys used by Windows features.',
  'tcp 443': 'Web server (HTTPS).',
};
const RAT_PORTS = new Set([1337, 31337, 4444, 5555, 6666, 6667, 6697, 12345, 27374, 1604, 3460, 8808, 9001, 9050]);
const portNote = l => PORTS[`${l.proto} ${l.port}`] ||
  (RAT_PORTS.has(l.port) ? 'Port often used by remote-access trojans and hacking tools. Check this program.' :
   l.port >= 49664 && l.port <= 49679 && l.proto === 'tcp' ? 'Windows internal RPC (lsass, wininit, services, spoolsv, svchost). Normal on every Windows PC.' :
   l.port >= 49152 ? 'Temporary (dynamic) port the program picked itself.' : '');

const CORE = new Set(['system', 'lsass.exe', 'wininit.exe', 'services.exe', 'csrss.exe', 'smss.exe', 'winlogon.exe']);
// Can this listening port be closed, and how? [label, explanation, can end the process]
function closeInfo(l, svcs) {
  const n = l.name.toLowerCase();
  const end = `End ${l.name} to close it now; it opens again the next time the program starts.`;
  if (l.pid <= 4 || n === 'system')
    return ['no, Windows', 'Windows itself (the kernel) holds this port: file sharing, network discovery or a built-in web service. It cannot be ended.' +
      (l.exposed ? ' To shut it off from other devices, use Block incoming.' : ''), false];
  if (CORE.has(n))
    return ['no, Windows', `${l.name} is a core part of Windows. Ending it crashes or logs off Windows. It only accepts Windows' own internal calls.` +
      (l.exposed ? ' Block incoming if you want to shut it off from other devices.' : ''), false];
  if (n === 'svchost.exe' || svcs.length)
    return ['service', `Windows service${svcs.length > 1 ? 's' : ''}: ${svcs.length ? svcs.join(', ') : 'unknown (press refresh under Connection settings)'}.\n` +
      `Don't end ${l.name}: it hosts ${n === 'svchost.exe' ? 'services' : 'a service'} that Windows restarts or needs. To close the port, stop and disable the service in Services (Win+R → services.msc), only if you know you don't need that feature` +
      (l.exposed ? ', or use Block incoming.' : '.'), false];
  if (!l.exposed)
    return ['not needed', `Only programs on this PC can connect (loopback). Usually an app talking to its own helper. Nothing to close. ${end}`, true];
  return ['yes', `${end}\nOr use Block incoming: other devices can no longer connect, for good, while the program keeps working on this PC.`, true];
}

function addrInfo(addr) {
  const list = String(addr || '').split(', ').filter(Boolean);
  const loop = a => a.startsWith('127.') || a === '::1';
  const why = a => (a === '0.0.0.0' ? 'every IPv4 address of this PC' : a === '::' ? 'every IPv6 address of this PC' :
    loop(a) ? 'loopback: only this PC' : a.startsWith('fe80') ? 'IPv6 link-local: local network only' : 'only this one address');
  const short = list.some(a => a === '0.0.0.0' || a === '::') ? 'all adapters' : list.every(loop) ? 'loopback' :
    list[0] + (list.length > 1 ? ` +${list.length - 1}` : '');
  return [short, list.map(a => `${a}  ·  ${why(a)}`).join('\n')];
}

// Replace a container's HTML only when it changed, keeping its scroll position.
function setHtml(el, html) {
  if (!el || el._html === html) return;
  if (pop.anchor && el.contains(pop.anchor)) hidePop();
  const x = el.scrollLeft;
  el._html = html;
  el.innerHTML = html;
  el.scrollLeft = x;
}

// setHtml that also keeps open <details> (help notes, Details rows) open.
function keepOpen(el, html) {
  if (!el) return;
  const open = $$('details[open]', el).map(d => d.dataset.h || d.dataset.k).filter(Boolean);
  setHtml(el, html);
  open.forEach(k => { const d = el.querySelector(`details[data-h="${k}"], details[data-k="${k}"]`); if (d) d.open = true; });
}

function netSkeleton() {
  $('#network').innerHTML = `<div class="page wide">
    <h2>Adapters</h2><p class="lead">Live throughput per network card (virtual filter layers hidden).</p>
    ${help('net-ad', [
      '<b>Adapter</b>: a network card. Ethernet and Wi-Fi are real ones; VPN, Hyper-V, WSL, VirtualBox and Bluetooth adapters are virtual.',
      '<b>Addresses</b>: 192.168.x.x, 10.x.x.x and 172.16–31.x.x are private addresses inside your network, invisible from the internet. fe80:… is an automatic IPv6 address, harmless.',
      '<b>MAC</b>: the hardware ID of the card. Only devices on your local network see it.',
      '<b>Down / Up</b>: speed right now. <b>Total</b>: since the adapter connected (usually since Windows started).',
      '<b>Worth a look</b>: Up stays high while you are not uploading anything (no backup, sync, video call or game). Open Activity and sort by Upload to see which program it is.',
    ])}
    <div class="box" id="net-ad"></div>
    <h2>Connection settings <button class="link" id="net-refresh" style="font-size:12px;font-weight:400;margin-left:8px">refresh</button></h2>
    <p class="lead">Gateway (your router) and DNS servers decide where traffic and name lookups go; unexpected DNS servers can mean hijacking.</p>
    ${help('net-cfg', [
      'Read once when you open the tab. Press <b>refresh</b> after switching Wi-Fi or turning a VPN on or off.',
      '<b>Network</b>: the name Windows gave this network, and its type. <b>Public</b> hides this PC from other devices (right for cafés, hotels, airports). <b>Private</b> allows file sharing and discovery (home or office). Change it in Windows Settings → Network &amp; internet → your adapter → Network profile type.',
      '<b>IPv4</b>: this PC\'s address and the size of the network (/24 = up to 254 devices).',
      '<b>Gateway</b>: your router, where all internet traffic leaves. Normally on the same network as your IPv4, often ending in .1.',
      '<b>DNS servers</b>: who turns names (google.com) into addresses. Normal: your router\'s address, your company\'s servers, your VPN\'s own server, or well-known public ones: 1.1.1.1 / 1.0.0.1 (Cloudflare), 8.8.8.8 / 8.8.4.4 (Google), 9.9.9.9 (Quad9), 208.67.222.222 (OpenDNS).',
      '<b>Worth a look</b>: a DNS server you never set and do not recognise. Malware and fake Wi-Fi hotspots change DNS to send you to fake sites. Look it up with IP info above.',
    ])}
    <div class="box" id="net-cfg"></div>
    <h2>Devices on your local network</h2><p class="lead">Other machines this PC has talked to recently (from the ARP table).</p>
    ${help('net-arp', [
      'Not a scan: only devices that exchanged packets with this PC recently. Devices that never talked to it are not listed.',
      '<b>MAC</b>: the first 6 characters name the maker. Search "MAC lookup" plus those characters to see who made a device.',
      '<b>State</b>: Reachable = answered in the last half minute. Stale = known but not checked recently (normal). Delay / Probe = Windows is checking it right now.',
      '<b>Worth a look</b>: your gateway\'s MAC changes while you are on the same network, or another IP shows the gateway\'s MAC. That can mean someone on the network is intercepting traffic (ARP spoofing). Common on untrusted Wi-Fi; use a VPN there.',
    ])}
    <div class="box" id="net-arp"></div>
    <h2>Listening ports</h2><p class="lead">Programs waiting for incoming connections. "Network" means other devices can try to connect. Hover an address, port or answer for details.</p>
    ${help('net-ls', [
      'A listening port is a door a program keeps open so others can connect to it. Programs going online (Activity) do not need one.',
      '<b>Address</b>: "all adapters" (0.0.0.0 / ::) means every network card, so other devices can try. "loopback" (127.0.0.1 / ::1) means only this PC. One address means only that network card.',
      '<b>Reachable from</b>: <b>network</b> = other devices can try to connect. Windows Firewall still turns them away unless the program or port was allowed, usually when someone clicked Allow on a Windows Firewall prompt. <b>this PC only</b> = nothing outside can reach it.',
      'Normal on every Windows PC: 135, 139, 445, 5040, 7680, 5353, 5355, 1900, 3702 and 49664–49679, held by System, svchost.exe, lsass.exe, wininit.exe, services.exe and spoolsv.exe.',
      '<b>Can close?</b> <b>yes</b>: End the program, or Block incoming (a firewall rule, kept until you remove it on the Blocking tab). <b>service</b>: a Windows service; stop it in services.msc rather than ending the process. <b>no, Windows</b>: part of Windows, cannot be ended; Block incoming still works. <b>not needed</b>: only this PC can reach it.',
      '<b>Worth a look</b>: a program you don\'t recognise listening on the network, especially one in Downloads, Temp or AppData, unsigned, or on ports like 4444, 5555, 1337, 31337 or 6667. Remote-access trojans wait for the attacker this way. Use Show file, check its Publisher on Activity, then Block incoming and End.',
    ])}
    <div class="box" id="net-ls"></div>
    <h2>Who connected to this PC</h2><p class="lead">Connections another device opened to a program here, right now and in the last 15 minutes. The full day is on the History tab.</p>
    ${help('net-in', [
      'Most PCs see none. On a home or office network you may see file sharing (port 445) from your own other computers, printers or a NAS.',
      '<b>From the internet</b> (tagged) is rare and worth checking: it needs a port forwarded in your router, UPnP, or a program that opened a hole for itself.',
      '<b>Remote Desktop (3389), VNC (5900), SSH (22), WinRM (5985)</b>: someone can control this PC or run commands on it. Fine if that is you or your IT; otherwise use Block incoming above and turn the feature off.',
      '<b>Sent</b> is what this PC gave the other device. Large numbers on file sharing mean files were copied from this PC.',
      '<b>Peek</b> captures the traffic for a few seconds and shows whether it is encrypted.',
    ])}
    <div class="box" id="net-in"></div></div>`;
  $('#net-refresh').onclick = loadNetExtra;
  $('#net-ls').onclick = onListenerAction;
  $('#net-in').onclick = onFlowAction;
}

async function renderNetwork() {
  const [n, allFlows] = await Promise.all([invoke('network'), invoke('flows', { pid: null })]);
  const x = state.netExtra;
  if (!$('#net-ad')) netSkeleton();
  setHtml($('#net-ad'), `<table class="grid"><thead><tr><th>Adapter</th><th>Addresses</th><th>MAC</th><th class="r">Down</th><th class="r">Up</th><th class="r">Total down</th><th class="r">Total up</th></tr></thead><tbody>
    ${n.adapters.map(a => `<tr><td class="pname">${esc(a.name)}</td><td class="num wrap">${esc(a.ips.join(', ')) || '–'}</td><td class="num">${esc(a.mac)}</td>
      <td class="r num">${fmtR(a.rx_rate)}</td><td class="r num ${a.tx_rate ? 'live' : ''}">${fmtR(a.tx_rate)}</td><td class="r num">${fmtB(a.rx_total)}</td><td class="r num">${fmtB(a.tx_total)}</td></tr>`).join('')}
    </tbody></table>`);
  const cfg = x && x.config ? x.config.map(c => `<tr><td><span class="pname">${esc(c.alias)}</span><div class="sub">${esc(c.desc)}</div></td>
      <td>${esc(c.network)}<div class="sub">${esc(c.category)}</div></td><td class="num wrap">${esc(c.ipv4)}</td>
      <td class="num">${esc(c.gateway) || '–'}</td><td class="num wrap">${esc(c.dns) || '–'}</td></tr>`).join('') : '';
  setHtml($('#net-cfg'), x && x.error ? `<div class="empty">${esc(x.error)}</div>` : !x ? '<div class="empty">Loading…</div>' :
    `<table class="grid"><thead><tr><th>Interface</th><th>Network</th><th>IPv4</th><th>Gateway</th><th>DNS servers</th></tr></thead><tbody>${cfg}</tbody></table>`);
  const nb = x && x.neighbors ? x.neighbors.map(d => `<tr><td class="num">${esc(d.ip)}</td><td class="num">${esc(d.mac)}</td><td class="sub">${esc(d.state)}</td><td class="sub">${esc(d.iface)}</td></tr>`).join('') : '';
  setHtml($('#net-arp'), !x || x.error ? '<div class="empty">–</div>' : nb ? `<table class="grid"><thead><tr><th>IP</th><th>MAC</th><th>State</th><th>Interface</th></tr></thead><tbody>${nb}</tbody></table>` : '<div class="empty">None seen.</div>');

  const svc = {};
  for (const s of (x && x.services) || []) (svc[s.pid] = svc[s.pid] || []).push(`${s.display} (${s.name})`);
  const fw = (state.rules && state.rules.rules) || [];
  const rows = n.listeners.map(l => {
    const svcs = svc[l.pid] || [];
    const [ans, why, endable] = closeInfo(l, svcs);
    const [ashort, afull] = addrInfo(l.addr);
    const note = portNote(l);
    const target = `${l.proto.toUpperCase()} ${l.port}`;
    const rule = fw.find(r => r.kind === 'port' && r.target === target);
    const progPop = [l.exe || 'File path not visible (part of Windows, or no access).', svcs.length ? 'Services: ' + svcs.join(', ') : ''].filter(Boolean).join('\n');
    return `<tr>
      <td class="lprog" data-pop="${esc(progPop)}"><span class="pname">${esc(l.name)}</span> <span class="sub">${l.pid}</span>${svcs.length ? `<div class="sub ell">${esc(svcs[0].replace(/ \(.*\)$/, ''))}${svcs.length > 1 ? ` +${svcs.length - 1}` : ''}</div>` : ''}</td>
      <td class="r num"><span ${note ? `class="hint" data-pop="${esc(target + ': ' + note)}"` : ''}>${l.port}</span></td>
      <td class="num">${l.proto.toUpperCase()}</td>
      <td class="num"><span class="hint addr" data-pop="${esc(afull)}">${esc(ashort)}</span></td>
      <td>${l.exposed ? '<span class="tag med">network</span>' : '<span class="sub">this PC only</span>'}${rule ? ' <span class="tag ok">incoming blocked</span>' : ''}</td>
      <td><span class="tag hint" data-pop="${esc(why)}">${ans}</span></td>
      <td><div class="acts">${l.exe ? `<button class="btn sm" data-la="file" data-v="${esc(l.exe)}">Show file</button>` : ''}${
        rule ? `<button class="btn sm" data-la="unblock" data-v="${esc(rule.id)}">Unblock</button>` :
        l.exposed ? `<button class="btn sm" data-la="block" data-proto="${l.proto}" data-port="${l.port}" data-name="${esc(l.name)}">Block incoming</button>` : ''}${
        endable ? `<button class="btn sm" data-la="end" data-pid="${l.pid}" data-name="${esc(l.name)}">End</button>` : ''}</div></td></tr>`;
  }).join('');
  setHtml($('#net-ls'), `<table class="grid"><thead><tr><th>Program</th><th class="r">Port</th><th>Proto</th><th>Address</th><th>Reachable from</th><th>Can close?</th><th></th></tr></thead><tbody>
    ${rows || '<tr><td colspan="7" class="empty">No listening ports.</td></tr>'}</tbody></table>`);
  const inb = allFlows.filter(f => f.inb);
  setHtml($('#net-in'), inb.length ? `<table class="grid"><thead><tr><th>Program</th><th>On port</th><th>From</th><th class="r">Sent</th><th class="r">Received</th><th>Status</th><th></th></tr></thead><tbody>
    ${inb.map(f => `<tr class="${f.open ? '' : 'dim'}"><td><span class="pname">${esc(f.name)}</span> <span class="sub">${f.pid}</span></td>
      <td class="num">${f.port}${f.service ? ` <span class="sub">${esc(f.service)}</span>` : ''}</td>
      <td class="num">${esc(f.domain || f.ip)}${f.domain ? ` <span class="sub">${esc(f.ip)}</span>` : ''}${f.scope === 'internet' ? ' <span class="tag med">internet</span>' : ' <span class="sub">local network</span>'}</td>
      <td class="r num">${fmtB(f.out)}</td><td class="r num">${fmtB(f.in)}</td><td class="num muted">${f.open ? 'open' : ago(f.last)}</td>
      <td class="r">${f.scope === 'internet' ? `<button class="btn sm" data-a="info" data-v="${esc(f.ip)}">IP info</button> ` : ''}${peekBtn(f)} <button class="btn sm" data-a="ip" data-v="${esc(f.ip)}">Block IP</button></td></tr>`).join('')}
    </tbody></table>` : `<div class="empty">${state.snap && state.snap.mode === 'full' ? 'Nobody has connected to this PC in the last 15 minutes.' : 'Incoming connections are seen in full monitoring (administrator); limited mode only shows open ones.'}</div>`);
}

async function onListenerAction(e) {
  const b = e.target.closest('button[data-la]');
  if (!b) return;
  const d = b.dataset;
  if (d.la === 'file') reveal(d.v);
  if (d.la === 'end') kill(+d.pid, d.name, b);
  if (d.la === 'unblock' && (await act('unblock', { id: d.v }, b))) loadRules();
  if (d.la === 'block') {
    const t = `${d.proto.toUpperCase()} ${d.port}`;
    if (!(await ask(`Block incoming ${t}?`, `Other devices will no longer be able to connect to port ${d.port} on this PC. ${d.name} keeps running, and programs on this PC can still use it. Remove the rule on the Blocking tab to undo.`, 'Block'))) return;
    if (await act('block_port', { proto: d.proto, port: +d.port }, b)) loadRules();
  }
}

// ---------------------------------------------------------------- blocking

async function loadRules() {
  try { state.rules = await invoke('rules'); } catch (e) { state.rules = { error: String(e), rules: [], hosts: [], firewall_off: [] }; }
  if (state.snap) renderTop();
  if (state.tab === 'blocked') renderBlocked();
  if (state.tab === 'network') renderNetwork();
}

function renderBlocked() {
  const r = state.rules;
  if (!r) { $('#blocked').innerHTML = '<div class="empty">Loading…</div>'; return; }
  const profiles = (r.profiles || []).map(p => `<span>${esc(p.name)}: <b>${p.enabled === 'True' ? 'on' : 'off'}</b></span>`).join('');
  const user = r.rules.filter(x => !['script', 'tracker', 'analytics'].includes(x.kind));
  const KIND = { app: 'Program', ip: 'Address', domain: 'Website', port: 'Incoming port' };
  const an = state.analytics || [];
  const anOn = an.filter(i => i.on).length;
  const anRow = i => `<div class="srow"><div><b>${esc(i.name)}</b>${i.on ? ` <span class="tag ok">blocked${i.t ? ' since ' + fmtDay(i.t) : ''}</span>` : ''}
      <small>${esc(i.what)}</small><small><b class="muted">Side effect:</b> ${esc(i.side)}</small>
      ${i.domains ? `<small class="mono adv">${i.domains.map(esc).join(', ')}</small>` : ''}
      ${(i.errors || []).length ? `<small class="err-text">Not changed: ${i.errors.map(esc).join('; ')}</small>` : ''}</div>
    <label class="check"><input type="checkbox" data-an="${esc(i.id)}" ${i.on ? 'checked' : ''}> ${i.on ? 'Blocked' : 'Allowed'}</label></div>`;
  $('#blocked').innerHTML = `<div class="blk">
    ${r.error ? `<div class="banner bad" style="margin-bottom:14px">${esc(r.error)}</div>` : ''}
    <div class="panel sec">
      <div class="sech">Windows Firewall</div>
      <p class="sd">Kestryl blocks through Windows Firewall rules (group "Kestryl"), so blocks keep working when Kestryl is closed.
        Windows only applies a new rule to new connections, so while it runs Kestryl also closes any connection it sees moving data past a block
        (IPv4 TCP; Windows has no way to close an IPv6 or UDP one, those stop when the program reconnects).</p>
      <div class="status-line">${profiles}<span>Outgoing by default: <b>${r.cut_off ? 'blocked (cut off)' : 'allowed'}</b></span></div>
    </div>
    <div class="panel sec">
      <div class="sech">Script lockdown</div>
      <p class="sd">Stops script engines and built-in Windows tools that malware uses to download payloads and send data out
        (PowerShell, Windows Script Host, mshta, certutil, bitsadmin, rundll32, regsvr32, MSBuild and more) from using the network.
        Your own PowerShell scripts that need the internet will stop working while this is on.</p>
      <div class="srow"><div><b>${r.lockdown ? 'On' : 'Off'}</b><small>${r.lockdown ? 'These programs cannot reach the network.' : 'Script engines and Windows tools can go online.'}
        <details><summary>${r.hosts.length} programs covered on this PC</summary><ul class="hosts">${r.hosts.map(h => `<li>${esc(h.split('\\').slice(-1)[0])} <span class="muted">${h.includes('SysWOW64') || h.includes('Framework\\') ? '32-bit' : ''}</span></li>`).join('')}</ul></details></small></div>
        <button class="btn ${r.lockdown ? '' : 'primary'}" id="lockdown">${r.lockdown ? 'Turn off' : 'Turn on'}</button></div>
    </div>
    <div class="panel sec" id="blk-an">
      <div class="sech">Analytics and telemetry <small class="muted" style="font-weight:400">${an.length ? `${anOn} of ${an.length} blocked` : ''}</small></div>
      <p class="sd">Windows, Edge, Office and Chrome send usage data ("telemetry") to their makers. These switches turn that off with the settings Microsoft and Google document for companies, and the last one blocks the collection servers in Windows Firewall.
        Every change is written down first, so switching it back puts everything exactly as it was. Needs administrator.</p>
      ${help('blk-an', [
        'Nothing here stops Windows Update, Defender, the Microsoft Store or signing in to your accounts.',
        '<b>Windows Home and Pro</b> cannot go below "required" diagnostic data through settings alone. Stopping the telemetry service (DiagTrack) and blocking it in the firewall is what stops the rest.',
        '"Managed by your organization" in Edge or Chrome only means these policies are set. Nobody else controls the browser.',
        '<b>Analytics servers</b> are blocked for every program, by address, like a blocked site. If something you use breaks, switch it back.',
        'The switch shows what Kestryl did. If another tool or a Windows update changes these settings later, Kestryl does not fight it.',
      ], 'What exactly changes')}
      ${an.length ? an.map(anRow).join('') : '<div class="empty">Loading…</div>'}
    </div>
    <div class="panel sec">
      <div class="sech">Block something</div>
      <p class="sd">A website (pastebin.com), an IP address or range (203.0.113.7, 203.0.113.0/24), or a program path (C:\\Tools\\app.exe).</p>
      <div class="addrow"><input type="text" id="manual" style="width:420px" placeholder="Domain, IP or program path" spellcheck="false"><button class="btn primary" id="manual-go">Block</button></div>
    </div>
    <div class="panel sec">
      <div class="sech">Your blocks</div>
      ${user.length ? `<table class="grid"><thead><tr><th>Type</th><th>Target</th><th>Rule</th><th></th></tr></thead><tbody>
        ${user.map(x => `<tr><td>${KIND[x.kind] || esc(x.kind)}</td><td class="mono wrap">${esc(x.target)}</td><td class="sub">${esc(x.name)}${x.enabled ? '' : ' (disabled)'}</td>
          <td class="r"><button class="btn sm" data-id="${esc(x.id)}">Remove</button></td></tr>`).join('')}</tbody></table>` : '<div class="empty">Nothing blocked yet. Block from an alert, a program, or a connection.</div>'}
    </div>
  </div>`;
  $('#lockdown').onclick = async e => { if (await act('set_lockdown', { on: !r.lockdown }, e.currentTarget)) loadRules(); };
  const go = async () => {
    const v = $('#manual').value.trim();
    if (!v) return;
    const btn = $('#manual-go');
    const isIp = /^[0-9a-f.:]+(\/\d+)?$/i.test(v) && /[.:]/.test(v) && !/[g-z]/i.test(v);
    let ok;
    if (/\.exe$/i.test(v) && /[\\/]/.test(v)) ok = await act('block_app', { exe: v, pid: null }, btn);
    else if (isIp) ok = await act('block_ip', { ip: v }, btn);
    else ok = await act('block_domain', { domain: v }, btn);
    if (ok) { $('#manual').value = ''; loadRules(); }
  };
  $('#manual-go').onclick = go;
  $('#manual').onkeydown = e => { if (e.key === 'Enter') go(); };
  $$('#blocked button[data-id]').forEach(b => (b.onclick = async () => { if (await act('unblock', { id: b.dataset.id }, b)) loadRules(); }));
  $$('#blocked [data-an]').forEach(c => (c.onchange = async () => {
    const it = an.find(i => i.id === c.dataset.an);
    const on = c.checked;
    if (on && it && !(await ask(`Block ${it.name}?`, `${it.what}\n\nSide effect: ${it.side}\n\nYou can undo it any time with the same switch.`, 'Block'))) { c.checked = false; return; }
    c.disabled = true;
    await act('set_analytics', { id: c.dataset.an, on });
    loadAnalytics();
  }));
}

async function loadAnalytics() {
  try { state.analytics = await invoke('analytics_list'); } catch (e) { console.error(e); }
  if (state.tab === 'blocked') renderBlocked();
}

// ---------------------------------------------------------------- settings

async function loadSettings() {
  state.settings = await invoke('settings');
  state.update = await invoke('update_state').catch(() => state.update);
  if (state.tab === 'settings') renderSettings();
}

const SNAV = [['set-alerts', 'Alerts'], ['set-protect', 'Protection'], ['set-intel', 'Threat lists'], ['set-safe', 'Known-safe services'], ['set-geo', 'Country data'], ['set-theme', 'Theme'], ['set-tdest', 'Trusted IPs and domains'],
  ['set-trust', 'Trusted programs'], ['set-mute', 'Muted alert types'], ['set-update', 'Updates'], ['set-see', 'What Kestryl can see'], ['set-diag', 'Diagnostics', 1]];

// Settings → Updates and the update alert: download, check the signature, install, restart.
async function updateInstall(btn) {
  const u = state.update || {};
  const v = u.available ? u.available.version : 'the new version';
  if (!(await ask(`Install Kestryl ${v}?`, 'Kestryl downloads the setup from its GitHub releases, checks that it is signed with Kestryl\'s key, then closes, installs and starts again. Monitoring pauses for about a minute. Windows may ask for administrator permission.', 'Update now'))) return;
  if (await act('update_install', {}, btn)) setTimeout(loadSettings, 3000);
}

// Settings → Known-safe services → View: every range (or name) of one service.
async function safeSheet(id) {
  $('#sheet').hidden = false;
  $('#sheet-body').innerHTML = '<p class="muted">Loading…</p>';
  let r;
  try { r = await invoke('safe_entries', { id }); } catch (e) { $('#sheet-body').innerHTML = `<p class="err-text">${esc(e)}</p>`; return; }
  const list = xs => xs.map(x => `<div data-v="${esc(x.toLowerCase())}">${esc(x)}</div>`).join('');
  $('#sheet-body').innerHTML = `<h2>${esc(r.name)}</h2>
    <p class="sd" style="margin-top:8px">${esc(r.desc)}</p>
    <p class="note">Source: <span class="mono">${esc(r.source)}</span></p>
    <label class="search" style="margin:10px 0"><i class="ic">&#xE721;</i><input id="safe-q" type="search" placeholder="Filter" spellcheck="false"></label>
    <div class="sub">${r.entries.length.toLocaleString()} ${id === 'windows' ? 'names' : 'address ranges'}</div>
    <div class="mono" id="safe-list" style="margin-top:6px;line-height:19px">${list(r.entries) || '<span class="muted">Not downloaded yet. Use Update lists now in Settings.</span>'}</div>
    ${r.excluded.length ? `<details class="help" style="margin-top:14px"><summary>Left out: ${r.excluded.length.toLocaleString()} Google Cloud customer ranges</summary>
      <p class="note">Google rents these to anyone, so they are never counted as safe, even though they are inside Google's address space.</p>
      <div class="mono" id="safe-excl" style="line-height:19px">${list(r.excluded)}</div></details>` : ''}`;
  $('#safe-q').oninput = e => {
    const q = e.target.value.trim().toLowerCase();
    $$('#safe-list [data-v], #safe-excl [data-v]').forEach(x => (x.hidden = !!q && !x.dataset.v.includes(q)));
  };
}

function renderSettings() {
  const s = state.settings;
  if (!s) return;
  const st = s.stats;
  const openHelp = $$('#settings details.help[open]').map(d => d.dataset.h);
  const scroller = $('#settings');
  const top = scroller.scrollTop;
  const H = 'What this does';
  const lists = s.intel || [];
  const geo = s.geo || {};
  const fileState = !s.file_watch ? 'Off' : s.health && s.health.files ? 'Running' : s.health && s.health.files_error ? 'Error: ' + esc(s.health.files_error) : s.mode === 'full' ? 'Starting' : 'Starts with full monitoring';
  scroller.innerHTML = `<div class="sgrid">
  <div class="snav">${SNAV.map(([id, l, adv], i) => `<a data-sec="${id}" class="${i === 0 ? 'on' : ''} ${adv ? 'adv' : ''}">${l}</a>`).join('')}</div>
  <div>
    <div class="panel sec" id="set-alerts">
      <div class="sech">Alerts</div>
      ${help('s-alerts', [
        '<b>Upload limit</b>: when one program sends more than this many MB to the internet within 60 seconds, you get a "Large upload" alert. Default 20 MB.',
        'Lower it (5–10) to catch smaller leaks, such as documents or browser passwords. Raise it (100 or more) if large uploads are normal for you (cloud backup, OneDrive, YouTube, video calls). Better still: leave it, and trust the program that uploads a lot.',
        '<b>Pop-up</b>: the small window in the bottom-right corner, with a Block app button. <b>high risk only</b> = quietest. <b>medium and high</b> = recommended. <b>everything</b> = also low-risk notes (signed apps doing something unusual), which is noisy.',
        'Every alert is saved on the Alerts page, whatever you choose here. Press <b>Save</b> after changing these.',
      ], H)}
      <div class="srow"><div><b>Upload alert</b><small>Alert when one program uploads more than this to the internet within a minute</small></div>
        <div class="ctl"><input type="number" id="s-up" min="1" max="10000" value="${s.upload_mb}"><span class="muted">MB</span></div></div>
      <div class="srow"><div><b>Pop-up in the corner of the screen</b><small>New alerts show even while Kestryl is in the tray</small></div>
        <div class="ctl"><select id="s-min"><option value="3" ${s.popup_min == 3 ? 'selected' : ''}>High risk only</option><option value="2" ${s.popup_min == 2 ? 'selected' : ''}>Medium and high</option><option value="1" ${s.popup_min == 1 ? 'selected' : ''}>Everything</option></select>
          <label class="check"><input type="checkbox" id="s-pop" ${s.popups ? 'checked' : ''}></label></div></div>
      <div class="sfoot"><button class="btn primary" id="s-save">Save</button></div>
    </div>

    <div class="panel sec" id="set-protect">
      <div class="sech">Protection</div>
      ${help('s-files', [
        '<b>File monitoring</b> uses Windows\' own file tracing (no driver). Only file <b>names</b> are checked; contents are never read, and nothing leaves the PC.',
        'The browser opening its own password file is normal and ignored, as are Windows Defender, Windows Search, backup and cloud-sync apps doing their job. You get an alert when another program opens one of these files, and a stronger one when it then sends data out. That is what password stealers do.',
        '<b>Start with Windows</b> creates a task named <b>Kestryl</b> in Task Scheduler that starts kestryl.exe --hidden when you sign in, with full monitoring. Kestryl must itself be running as administrator to turn this on or off. It points to the kestryl.exe that was running when you turned it on.',
        'Open the window again from the tray icon (near the clock). Closing the window keeps Kestryl running; quit from the tray menu.',
        '<b>Clipboard guard</b> looks only for crypto wallet addresses and bank account numbers (IBAN) in what you copy. If a program replaces one with a different one within a few seconds, that is "clipper" malware sending your payment to a thief, and you get a high alert. Nothing you copy is saved or sent; an alert keeps only a shortened form (bc1qxy…0wlh). Password managers that ask Windows to keep their copies private are skipped.',
      ], H)}
      <div class="srow"><div><b>Clipboard guard</b><small>Warns when a program swaps a wallet address or bank account number you copied</small></div>
        <label class="check"><input type="checkbox" id="s-clip" ${s.clip_guard ? 'checked' : ''}></label></div>
      <div class="srow"><div><b>Camera turned on</b><small>Pops up every time any app or browser tab turns on the camera, not only unusual programs</small></div>
        <label class="check"><input type="checkbox" id="s-cam" ${s.cam_notify ? 'checked' : ''}></label></div>
      <div class="srow"><div><b>Microphone turned on</b><small>The same for the microphone. Calls and voice chat turn it on often, so this is off at first</small></div>
        <label class="check"><input type="checkbox" id="s-mic" ${s.mic_notify ? 'checked' : ''}></label></div>
      <div class="srow"><div><b>File monitoring</b><small>Which programs open passwords, cookies, wallets, keys and documents · ${fileState}</small></div>
        <label class="check"><input type="checkbox" id="s-files" ${s.file_watch ? 'checked' : ''}></label></div>
      <div class="srow"><div><b>Start with Windows</b><small>Runs Kestryl hidden in the tray at sign-in, with administrator rights${state.autostart == null ? '' : state.autostart ? ' · On' : ' · Off'}</small></div>
        <button class="btn" id="s-auto">${state.autostart == null ? 'Checking…' : state.autostart ? 'Turn off' : 'Turn on'}</button></div>
    </div>

    <div class="panel sec" id="set-intel">
      <div class="sech">Threat lists</div>
      <p class="sd">Every connection and name lookup is checked against public lists of known malware servers. They are downloaded every 12 hours straight from their publishers; nothing about this PC is sent.${s.intel_demo ? ' Simulation: made-up lists.' : ''}</p>
      ${help('s-intel', [
        '<b>abuse.ch Feodo Tracker</b> and <b>C2IntelFeeds</b>: control servers of botnets, Cobalt Strike and other remote-control malware. A match is a high alert.',
        '<b>Spamhaus DROP</b>: whole networks run by criminals. <b>Emerging Threats</b>: hacked machines seen attacking others. A match is a medium alert.',
        '<b>ThreatFox</b> (abuse.ch) is the biggest list of remote-access trojan and stealer servers (AsyncRAT, Remcos, Quasar, Lumma…) and of malware file fingerprints. It needs a free key: sign in at auth.abuse.ch, open Optional → API keys, create one and paste it here.',
        'Kestryl also asks Microsoft Defender to scan unsigned programs and programs in temp or download folders when they first show up. That scan only reports; Kestryl never deletes files.',
      ], H)}
      ${lists.length ? `<table class="grid"><thead><tr><th>List</th><th class="r">Entries</th><th>Updated</th><th></th></tr></thead><tbody>${lists.map(l => `<tr><td>${esc(l.name)}<div class="sub">${esc(l.desc)}</div></td><td class="r">${l.n.toLocaleString()}</td><td class="muted">${l.t ? ago(l.t) : 'never'}</td><td class="sub wrap">${esc(l.err)}</td></tr>`).join('')}</tbody></table>` : '<div class="empty">Loading the lists…</div>'}
      <div class="srow"><div><b>abuse.ch Auth-Key</b><small>${s.abuse_key_set ? 'Set: ThreatFox is checked too.' : 'Optional, free. Adds ThreatFox.'}</small></div>
        <div class="ctl"><input type="password" id="s-key" style="width:240px" placeholder="${s.abuse_key_set ? '••••••••••••' : 'Paste key'}" spellcheck="false" autocomplete="off">
          <button class="btn" id="s-key-save">Save</button>${s.abuse_key_set ? '<button class="btn" id="s-key-del">Remove</button>' : ''}</div></div>
      <div class="sfoot"><button class="btn" id="s-intel-go">Update lists now</button></div>
    </div>

    <div class="panel sec" id="set-safe">
      <div class="sech">Known-safe services</div>
      <p class="sd">Addresses that belong to Google's, Microsoft's and Apple's own services, from the lists these companies publish. Connections to them are tagged, and alerts that only say a destination looks unusual (check-ins on a timer, bare IP addresses, uncommon ports) stay quiet for normal programs.</p>
      ${help('s-safe', [
        '<b>Still reported, even to these services:</b> large uploads, programs opening your passwords or cookies and then sending data, programs sending email or using FTP by themselves, file-sharing and paste sites, and known malware servers. Password stealers upload to Google Drive and OneDrive too.',
        '<b>Never quieted:</b> unsigned programs, programs running from Temp or Downloads, scripts and Windows tools.',
        '<b>Left out on purpose:</b> Google Cloud and Azure customer servers (anyone can rent one, and malware control servers often sit there), and networks that carry everyone\'s content, such as Cloudflare, Akamai and Amazon CloudFront.',
        'Google\'s and Microsoft\'s lists are downloaded once a day straight from Google and Microsoft. Nothing about this PC is sent; the request is the same from every copy of Kestryl. Windows Update and Apple are built in.',
      ], H)}
      <div class="srow"><div><b>Use known-safe services</b><small>Off: every address is judged the same, as before</small></div>
        <label class="check"><input type="checkbox" id="s-safe" ${s.safe_on ? 'checked' : ''}></label></div>
      ${(s.safe || []).length ? `<table class="grid"><thead><tr><th>Service</th><th class="r">Entries</th><th>Updated</th><th>On</th><th></th></tr></thead><tbody>${s.safe.map(l => `<tr class="${s.safe_on ? '' : 'dim'}">
          <td>${esc(l.name)}<div class="sub">${esc(l.desc)}</div>${l.err ? `<div class="sub err-text">${esc(l.err)}</div>` : ''}</td>
          <td class="r num">${l.n.toLocaleString()}${l.excluded ? `<div class="sub">${l.excluded.toLocaleString()} left out</div>` : ''}</td>
          <td class="muted">${l.t ? ago(l.t) : l.id === 'google' || l.id === 'microsoft' ? 'not yet' : 'built in'}</td>
          <td><label class="check"><input type="checkbox" data-safe-svc="${esc(l.id)}" ${(s.safe_off || []).includes(l.id) ? '' : 'checked'} ${s.safe_on ? '' : 'disabled'}></label></td>
          <td class="r"><button class="btn sm" data-safe-view="${esc(l.id)}">View</button></td></tr>`).join('')}</tbody></table>` : ''}
      <div class="addrow"><input type="text" id="s-safe-ip" style="width:240px" placeholder="Test an address, like 142.250.74.46" spellcheck="false"><button class="btn" id="s-safe-test">Test</button></div>
      <p class="note" id="s-safe-res" hidden></p>
      <div class="sfoot"><button class="btn" id="s-safe-go">Update lists now</button></div>
    </div>

    <div class="panel sec" id="set-geo">
      <div class="sech">Country and company data</div>
      <p class="sd">The Places page and the country next to each connection come from DB-IP's free database. It is downloaded once a month (about 12 MB) and used on this PC only: the addresses your programs talk to are never sent anywhere to be looked up.${geo.demo ? ' Simulation: made-up places.' : ''}</p>
      <div class="status-line"><span>Status: <b>${geo.ready ? 'ready' : geo.demo ? 'demo' : 'not downloaded yet'}</b></span>
        ${geo.ranges ? `<span>Address ranges: <b class="num">${geo.ranges.toLocaleString()}</b></span>` : ''}${geo.companies ? `<span>Companies: <b class="num">${geo.companies.toLocaleString()}</b></span>` : ''}
        ${geo.country_t ? `<span>Updated: <b>${ago(geo.country_t)}</b></span>` : ''}${s.home ? `<span>Home country: <b>${esc(ccName(s.home))}</b></span>` : ''}</div>
      ${geo.err ? `<p class="note err-text">${esc(geo.err)}</p>` : ''}
      <p class="note">${esc(geo.attribution || '')}. Home country is taken from Windows (Settings → Time &amp; language → Region).</p>
      <div class="sfoot"><button class="btn" id="s-geo-go">Download now</button></div>
    </div>

    <div class="panel sec" id="set-theme">
      <div class="sech">Theme</div>
      <div class="themes">${THEMES.map(([id, name, pv]) => `<button class="th ${state.theme === id ? 'on' : ''}" data-theme-id="${id}">
        <div class="${pv.length > 1 ? 'pvs' : ''}">${pv.map(c => `<div class="pv ${c}"><i></i><s></s><u></u></div>`).join('')}</div><b>${name}</b></button>`).join('')}</div>
    </div>

    <div class="panel sec" id="set-tdest">
      <div class="sech">Trusted IPs and domains</div>
      <p class="sd">Never raise alerts. Their traffic is hidden from Activity, Connections, DNS lookups and the totals unless you switch on Show traffic. A domain includes all its subdomains; ranges like 142.250.0.0/15 work too.</p>
      ${help('s-tdest', [
        'Use it to clear noise from places you know are fine: your company servers, your NAS or printer, Windows Update, your antivirus.',
        'For normal programs: traffic to a trusted destination never alerts, and is also left out of the "Large upload" count.',
        '<b>Exception</b>: unsigned programs, programs in Temp or Downloads, scripts and Windows tools are never hidden or silenced by a trusted destination. A stealer uploading to a trusted Google Drive or Discord still shows up.',
        '<b>Careful</b>: do not trust big sites where anyone can upload. google.com covers drive.google.com, discord.com covers Discord webhooks, telegram.org covers bot uploads.',
        'Domains are matched through the names DNS returned, so they need full monitoring (administrator).',
      ], H)}
      <div class="addrow"><input type="text" id="td-new" style="width:320px" placeholder="google.com, 8.8.8.8 or 142.250.0.0/15" spellcheck="false"><button class="btn primary" id="td-add">Add</button></div>
      ${(s.trusted_dests || []).length ? `<table class="grid"><thead><tr><th>IP, range or domain</th><th>Type</th><th>Show traffic</th><th></th></tr></thead><tbody>${s.trusted_dests.map(t => `<tr>
          <td class="mono wrap">${esc(t.target)}</td>
          <td class="sub">${isIpTarget(t.target) ? (t.target.includes('/') ? 'IP range' : 'IP address') : 'Domain'}</td>
          <td><label class="check"><input type="checkbox" data-show="${esc(t.target)}" ${t.show ? 'checked' : ''}> ${t.show ? 'Shown' : 'Hidden'}</label></td>
          <td class="r"><button class="btn sm" data-untrust="${esc(t.target)}">Remove</button></td></tr>`).join('')}</tbody></table>`
        : '<div class="empty">None yet. Use Trust on a connection, an alert or the IP info panel, or add one above.</div>'}
    </div>

    <div class="panel sec" id="set-trust">
      <div class="sech">Trusted programs</div>
      <p class="sd">Their traffic is still shown, but they never raise alerts. Trust follows the file: if it is replaced or loses its signature, Kestryl watches it again and tells you.</p>
      ${s.trusted.length ? `<table class="grid"><tbody>${s.trusted.map(t => `<tr><td class="mono wrap">${esc(t)}</td><td class="r"><button class="btn sm" data-trust="${esc(t)}">Remove</button></td></tr>`).join('')}</tbody></table>` : '<div class="empty">None. Add with Trust this app on an alert, or Trust on a program in Activity.</div>'}
    </div>

    <div class="panel sec" id="set-mute">
      <div class="sech">Muted alert types</div>
      <p class="sd">A muted type never alerts again, for any program. If one program is the problem, trust that program instead.</p>
      ${s.muted.length ? `<table class="grid"><tbody>${s.muted.map(m => `<tr><td>${esc(RULES[m] || m)}</td><td class="r"><button class="btn sm" data-mute="${esc(m)}">Un-mute</button></td></tr>`).join('')}</tbody></table>` : '<div class="empty">None.</div>'}
    </div>

    <div class="panel sec" id="set-update">
      <div class="sech">Updates</div>
      ${(() => {
        const u = state.update || {};
        const r = u.available;
        return `<p class="sd">This is Kestryl ${esc(u.current || '')}. Kestryl asks its GitHub releases page once a day whether a newer version is out, and tells you. Nothing is installed until you click Update now.</p>
      ${help('s-update', [
        'The check is one request to GitHub\'s public API. GitHub sees that this PC asked (its IP address), nothing else.',
        '<b>Update now</b> downloads the new setup from GitHub and installs it only if it is signed with Kestryl\'s update key, which is built into this copy. A changed or swapped file is refused. Kestryl then closes, the installer runs (Windows may ask for administrator permission) and Kestryl starts again.',
        'The portable Kestryl.exe cannot replace itself: it shows the new version and opens the download page instead.',
      ], H)}
      <div class="srow"><div><b>Check for new versions</b><small>Once a day, from github.com/${esc('HacanAle/Kestryl')}</small></div>
        <label class="check"><input type="checkbox" id="s-upd" ${u.auto ? 'checked' : ''}></label></div>
      <div class="status-line"><span>Installed: <b>${esc(u.current || '')}</b>${u.installed ? '' : ' <span class="sub">(portable)</span>'}</span>
        <span>Newest: <b>${r ? esc(r.version) : u.checked ? 'you have it' : 'not checked yet'}</b></span>
        ${u.checked ? `<span>Checked: <b>${ago(u.checked)}</b></span>` : ''}</div>
      ${u.err ? `<p class="note err-text">${esc(u.err)}</p>` : ''}
      ${r && r.notes ? `<div class="note" style="white-space:pre-line;max-height:220px;overflow:auto">${esc(r.notes)}</div>` : ''}
      ${r && !u.can_install ? `<p class="note">${u.installed ? 'This release cannot be installed from inside Kestryl yet (it is not signed for in-app updates). Download it from the release page.' : 'Download the new portable exe or the setup from the release page.'}</p>` : ''}
      <div class="sfoot"><button class="btn" id="s-upd-check" ${u.checking ? 'disabled' : ''}>Check now</button>
        ${r ? (u.can_install ? `<button class="btn primary" id="s-upd-go" ${u.installing ? 'disabled' : ''}>${u.installing ? 'Installing…' : 'Update now'}</button>` : '') + '<button class="btn" id="s-upd-page">Open release page</button>' : ''}</div>`;
      })()}
    </div>

    <div class="panel sec" id="set-see">
      <div class="sech">What Kestryl can and cannot see</div>
      <p class="sd" style="line-height:19px">Kestryl sees every program's connections in both directions: where they go, the port, how many bytes each way, how regularly, and which names were looked up, and checks them against lists of known malware servers.
        It sees which programs open password, cookie, wallet, key and document files, which programs use the camera and microphone, and it checks Windows' own safety settings and every place programs use to start with Windows.
        It does not decrypt anything by itself. Almost all traffic is encrypted (HTTPS), so no tool can read inside it without breaking that encryption.
        If you suspect one program, Advanced view has HTTPS decryption: protected by your own password, one program at a time, at most 30 minutes, with a red banner while it runs and every start and stop recorded as an alert.
        Peek shows whether a connection really is encrypted and where it really goes. What no network tool can see: malware that hides inside your browser, or malware that switches off Windows' own tracing (Kestryl reports that).
        Keep Windows Defender on: Kestryl watches behaviour and asks Defender about unsigned programs, but it is not an antivirus.</p>
    </div>

    <div class="panel sec adv" id="set-diag">
      <div class="sech">Diagnostics</div>
      <div class="status-line"><span>Mode: <b>${esc(s.mode)}</b></span><span>Administrator: <b>${s.elevated ? 'yes' : 'no'}</b></span>
        <span>Network events: <b class="num">${st.events}</b></span><span>DNS events: <b class="num">${st.dns_events}</b></span><span>Parse errors: <b class="num">${st.parse_errors}</b></span>
        <span>File events: <b class="num">${st.file_events}</b></span><span>File matches: <b class="num">${st.file_hits}</b></span><span>Missed by Windows: <b class="num">${s.health ? s.health.lost : 0}</b></span>
        <span>Defender scans: <b class="num">${s.scans || 0}</b></span></div>
      ${st.last_error || s.etw_error ? `<p class="note mono">${esc(s.etw_error || st.last_error)}</p>` : ''}
      <p class="note">Data folder: <button class="link" id="s-dir">${esc(s.data_dir)}</button></p>
      ${help('s-diag', [
        '<b>Mode</b>: <b>full</b> = running as administrator, everything works. <b>limited</b> = no admin rights: only TCP connections are seen, with no byte counts, UDP, DNS names, upload alerts or blocking.',
        '<b>Network events</b>: kernel network events received since Kestryl started. In full mode this number keeps rising. If it stays 0, monitoring is not working; restart Kestryl as administrator.',
        '<b>DNS events</b>: name lookups received. <b>Parse errors</b>: events Kestryl could not read; 0 or a few is fine.',
        '<b>File events</b>: file opens Windows reported. <b>File matches</b>: the few that were password, cookie, wallet, key or document files. <b>Missed by Windows</b>: events Windows dropped because the PC was too busy; a few is fine.',
        '<b>Data folder</b> (click to open): config.json holds settings, trusted lists, muted types and the security-check baseline; alerts.json the alert history; history\\ one file per day; intel\\ the downloaded threat lists; kestryl.log errors only.',
      ], H)}
    </div>
  </div></div>`;
  scroller.scrollTop = top;
  openHelp.forEach(h => { const d = $(`#settings details[data-h="${h}"]`); if (d) d.open = true; });
  $$('#settings .snav a').forEach(a => (a.onclick = () => { const el = $('#' + a.dataset.sec); if (el) el.scrollIntoView({ block: 'start', behavior: 'smooth' }); }));
  // The side menu follows the section at the top of the page.
  scroller.onscroll = () => {
    const y = scroller.getBoundingClientRect().top + 40;
    const cur = SNAV.map(([id]) => $('#' + id)).filter(el => el && el.offsetParent && el.getBoundingClientRect().top <= y).pop();
    const id = cur ? cur.id : SNAV[0][0];
    $$('#settings .snav a').forEach(x => x.classList.toggle('on', x.dataset.sec === id));
  };
  scroller.onscroll();
  $('#s-files').onchange = e => act('set_file_watch', { on: e.target.checked }).then(loadSettings);
  $('#s-clip').onchange = e => act('set_clip_guard', { on: e.target.checked }).then(loadSettings);
  $('#s-cam').onchange = e => act('set_sensor_notify', { kind: 'camera', on: e.target.checked }).then(loadSettings);
  $('#s-mic').onchange = e => act('set_sensor_notify', { kind: 'microphone', on: e.target.checked }).then(loadSettings);
  $('#s-safe').onchange = e => act('set_safe', { on: e.target.checked }).then(loadSettings);
  $$('#settings [data-safe-svc]').forEach(c => (c.onchange = () => act('set_safe_service', { id: c.dataset.safeSvc, on: c.checked }).then(loadSettings)));
  $$('#settings [data-safe-view]').forEach(b => (b.onclick = () => safeSheet(b.dataset.safeView)));
  const safeTest = async () => {
    const ip = $('#s-safe-ip').value.trim();
    if (!ip) return;
    const out = $('#s-safe-res');
    try {
      const r = await invoke('safe_test', { ip });
      out.textContent = r.text;
      out.className = 'note' + (r.safe ? ' ok-text' : '');
    } catch (err) { out.textContent = String(err); out.className = 'note err-text'; }
    out.hidden = false;
  };
  $('#s-safe-test').onclick = safeTest;
  $('#s-safe-ip').onkeydown = e => { if (e.key === 'Enter') safeTest(); };
  $('#s-safe-go').onclick = e => act('safe_refresh', {}, e.currentTarget).then(() => setTimeout(loadSettings, 8000));
  $('#s-upd').onchange = e => act('set_update_check', { on: e.target.checked }).then(loadSettings);
  $('#s-upd-check').onclick = async e => {
    const b = e.currentTarget;
    b.disabled = true;
    try {
      state.update = await invoke('update_check_now');
      flash(state.update.available ? `Kestryl ${state.update.available.version} is available.` : 'You have the newest version.');
    } catch (err) { flash(String(err), true); }
    loadSettings();
  };
  if ($('#s-upd-go')) $('#s-upd-go').onclick = e => updateInstall(e.currentTarget);
  if ($('#s-upd-page')) $('#s-upd-page').onclick = () => invoke('update_open_page').catch(err => flash(String(err), true));
  $('#s-geo-go').onclick = e => act('geo_refresh', {}, e.currentTarget).then(() => setTimeout(loadSettings, 15000));
  $('#s-save').onclick = e => act('save_settings', { uploadMb: +$('#s-up').value || 20, popups: $('#s-pop').checked, popupMin: +$('#s-min').value }, e.currentTarget).then(loadSettings);
  $('#s-auto').onclick = async () => {
    if (state.autostart == null) return;
    try {
      const r = await invoke('autostart', { on: !state.autostart });
      state.autostart = r.on;
      flash(r.msg);
      renderSettings();
    } catch (err) { flash(String(err), true); }
  };
  $('#s-key-save').onclick = e => { const v = $('#s-key').value.trim(); if (v) act('set_abuse_key', { key: v }, e.currentTarget).then(ok => ok && setTimeout(loadSettings, 4000)); };
  if ($('#s-key-del')) $('#s-key-del').onclick = e => act('set_abuse_key', { key: '' }, e.currentTarget).then(loadSettings);
  $('#s-intel-go').onclick = e => act('intel_refresh', {}, e.currentTarget).then(() => setTimeout(loadSettings, 6000));
  $('#s-dir').onclick = () => reveal(s.data_dir);
  $$('#settings [data-theme-id]').forEach(b => (b.onclick = async () => {
    applyTheme(b.dataset.themeId);
    await invoke('set_theme', { theme: b.dataset.themeId }).catch(err => flash(String(err), true));
    s.theme = b.dataset.themeId;
    renderSettings();
  }));
  $$('#settings [data-trust]').forEach(b => (b.onclick = () => trust(b.dataset.trust, false, b)));
  $$('#settings [data-mute]').forEach(b => (b.onclick = () => act('mute', { rule: b.dataset.mute, on: false }, b).then(loadSettings)));
  const addTd = async () => {
    const v = $('#td-new').value.trim();
    if (v && (await act('trust_dest', { target: v, site: false }, $('#td-add')))) loadSettings();
  };
  $('#td-add').onclick = addTd;
  $('#td-new').onkeydown = e => { if (e.key === 'Enter') addTd(); };
  $$('#settings [data-show]').forEach(c => (c.onchange = () => act('set_dest_show', { target: c.dataset.show, show: c.checked }).then(loadSettings)));
  $$('#settings [data-untrust]').forEach(b => (b.onclick = () => act('untrust_dest', { target: b.dataset.untrust }, b).then(loadSettings)));
}

// ---------------------------------------------------------------- IP info

const regionName = (() => {
  let dn = null;
  try { dn = new Intl.DisplayNames(['en'], { type: 'region' }); } catch (e) { /* older WebView */ }
  return c => { if (!c) return ''; try { return dn ? `${dn.of(c)} (${c})` : c; } catch (e) { return c; } };
})();

async function ipInfo(ip) {
  $('#sheet').hidden = false;
  $('#sheet-body').innerHTML = `<h2>${esc(ip)}</h2><p class="muted" style="margin-top:10px">Looking up…</p>`;
  try {
    renderIpInfo(await invoke('ip_info', { ip }));
  } catch (e) {
    $('#sheet-body').innerHTML = `<h2>${esc(ip)}</h2><p class="err-text">${esc(e)}</p>`;
  }
}

function renderIpInfo(r) {
  const g = r.geo || {}, d = r.rdap || {}, seen = r.seen || { flows: [], names: [] };
  const kv = rows => `<dl class="kv">${rows.filter(x => x[1]).map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl>`;
  const asn = (g.org || '').match(/^(AS\d+)\s+(.*)$/);
  const place = [g.city, g.region].filter(Boolean).join(', ');
  const site = seen.names[0] || g.hostname || '';
  $('#sheet-body').innerHTML = `
    <h2>${esc(r.ip)}</h2>
    <div class="sub">${esc(g.hostname || seen.names[0] || '')}</div>
    ${g.bogon ? '<p class="note">Reserved address (test or special-purpose range). It does not belong to anyone on the public internet.</p>' : ''}
    <h3>Network and location <span class="src">ipinfo.io</span></h3>
    ${r.geo ? kv([
      ['Operator', esc(asn ? asn[2] : g.org)],
      ['ASN', esc(asn ? asn[1] : '')],
      ['Hostname', esc(g.hostname)],
      ['Location', esc([place, regionName(g.country)].filter(Boolean).join(' · '))],
      ['Timezone', esc(g.timezone)],
      ['Anycast', g.anycast ? 'yes, served from many places' : ''],
    ]) : `<p class="note">${esc(r.geo_error)}</p>`}
    <h3>Registered owner <span class="src">official registry, via rdap.org</span></h3>
    ${r.rdap ? kv([
      ['Owner', esc(d.owner)],
      ['Network', esc([d.name, /\s-\s/.test(d.handle || '') ? '' : d.handle].filter(Boolean).join(' · '))],
      ['Range', `<span class="mono">${esc(d.cidr || d.range)}</span>`],
      ['Country', esc(regionName(d.country))],
      ['Abuse contact', esc(d.abuse)],
      ['Registered', esc(d.registered)],
      ['Last changed', esc(d.changed)],
      ['Registry', esc(d.registry)],
      ['Notes', (d.remarks || []).map(esc).join('<br>')],
    ]) : `<p class="note">${esc(r.rdap_error)}</p>`}
    <h3>Seen on this PC</h3>
    ${seen.names.length ? `<p class="mono" style="margin:0 0 8px">${seen.names.map(esc).join(', ')}</p>` : ''}
    ${seen.flows.length ? `<div class="dests">${seen.flows.map(f => `<div class="dest ${f.open ? '' : 'dim'}">
        <div class="l1"><span class="dn">${esc(f.name)} <span class="sub">${f.pid}</span></span><span class="num">${fmtB(f.out)} out</span><span class="num muted">${fmtB(f.in)} in</span><span class="st">${f.open ? 'open' : ago(f.last)}</span></div>
        <div class="l2"><span class="sub mono">${f.proto.toUpperCase()} ${f.port}${f.service ? ' ' + esc(f.service) : ''}</span></div></div>`).join('')}</div>`
      : '<p class="muted">No program on this PC has talked to it since Kestryl started.</p>'}
    <div class="actions"><button class="btn dangerf" id="sh-block">Block this IP</button><button class="btn" id="sh-trust">Trust this IP</button>${site ? `<button class="btn" id="sh-trust-site" title="${esc(site)}">Trust site</button>` : ''}<button class="btn" id="sh-copy">Copy IP</button></div>
    <p class="note">${r.demo ? 'Simulation: these details are made up; the demo does not contact ipinfo.io or rdap.org.' : 'Only this IP address is sent, over HTTPS, to ipinfo.io and rdap.org. Results are kept for an hour.'}</p>`;
  $('#sh-block').onclick = e => blockIp(r.ip, e.currentTarget);
  $('#sh-copy').onclick = () => navigator.clipboard.writeText(r.ip).then(() => flash('Copied.'));
  $('#sh-trust').onclick = e => trustDest(r.ip, false, e.currentTarget);
  if (site) $('#sh-trust-site').onclick = e => trustDest(site, true, e.currentTarget);
}

$('#sheet').onclick = e => { if (e.target.id === 'sheet' || e.target.id === 'sheet-close') $('#sheet').hidden = true; };
document.addEventListener('keydown', e => { if (e.key === 'Escape') $('#sheet').hidden = true; });
const lookupTyped = () => { const v = $('#ip-q').value.trim(); if (v) ipInfo(v); };
$('#ip-go').onclick = lookupTyped;
$('#ip-q').onkeydown = e => { if (e.key === 'Enter') lookupTyped(); };

// ---------------------------------------------------------------- status

const LVL = { ok: 0, info: 1, warn: 2, bad: 3 };
const worse = (a, b) => (LVL[b] > LVL[a] ? b : a);
const plural = (n, one, many) => `${n} ${n === 1 ? one : many || one + 's'}`;
const daysAgo = iso => {
  const t = new Date(iso);
  if (isNaN(t)) return null;
  const day = d => new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
  return Math.max(0, Math.round((day(new Date()) - day(t)) / 86400000));
};
const seenText = t => (t ? `added ${new Date(t).toLocaleString()}` : 'there before Kestryl started watching');
const ul = items => (items.length ? `<ul class="plain">${items.map(i => `<li>${i}</li>`).join('')}</ul>` : '');
const table = (head, rows) => (rows.length ? `<div class="box"><table class="grid"><thead><tr>${head.map(h => `<th>${h}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table></div>` : '');
const RISK = { high: '<span class="tag high">risky</span>', med: '<span class="tag med">check</span>', ok: '' };
// Paths wrap only at their backslashes, never in the middle of a name.
const pathHtml = p => esc(p).replace(/\\/g, '\\<wbr>');

// One entry of a Details list: name line, the command on one line (full text on hover),
// the reason it is flagged, and its buttons. `name`, `tags`, `meta`, `why` are HTML.
const irow = ({ cls = '', name, tags = '', meta = '', path = '', pop = '', why = '', acts = '' }) => `<div class="irow ${cls}">
  <div class="im"><div class="i1"><span class="pname">${name}</span>${tags}${meta ? `<span class="sub">${meta}</span>` : ''}</div>
    ${path ? `<div class="i2 mono" data-pop="${esc(pop || path)}">${esc(path)}</div>` : ''}
    ${why ? `<div class="i3">${why}</div>` : ''}</div>
  <div class="acts">${acts}</div></div>`;

// Flagged entries first; the normal ones folded away under "Show the other N".
const ilist = (key, flagged, normal, what) =>
  (flagged.length ? `<div class="ilist">${flagged.join('')}</div>` : '') +
  (normal.length ? `<details class="fold" data-k="${key}"><summary>${flagged.length ? `Show the other ${normal.length} ${what}` : `Show all ${normal.length} ${what}`}</summary><div class="ilist">${normal.join('')}</div></details>` : '');

async function loadStatus(force) {
  if (!force && Date.now() - state.statusAt < 10000) return;
  state.statusAt = Date.now();
  try { state.status = await invoke('status'); } catch (e) { console.error(e); return; }
  try { await loadAlerts(); } catch (e) { console.error(e); } // the clipboard check reads them
  if (state.tab === 'status') renderStatus();
}

function statusChecks(s) {
  const a = s.audit && s.audit.firewall ? s.audit : null;
  const h = s.health || {};
  const C = [];
  const add = (key, level, title, st, text, o = {}) => C.push({ key, level, title, st, text, ...o });

  // Monitoring itself
  {
    let level = 'ok', st = 'Full';
    const parts = ['network traffic', 'DNS'];
    if (s.file_watch && h.files) parts.push('file opens');
    let text = `Kestryl sees ${parts.join(', ')} and Windows' safety settings. ${s.stats.events.toLocaleString()} network events so far.`;
    if (s.sim) { level = 'info'; st = 'Simulation'; text = 'This is the --simulate demo: the suspicious programs and changes on this page are fake, to show what Kestryl reports. The security checks below are real (read-only).'; }
    else if (s.mode !== 'full') { level = 'bad'; st = s.mode === 'starting' ? 'Starting' : 'Limited'; text = 'Kestryl is not running as administrator, so it only sees which programs hold connections: no byte counts, DNS names, file monitoring, incoming connections or blocking.'; }
    else if (h.net === false) { level = 'bad'; st = 'Stopped'; text = 'Network monitoring was stopped by another program. Kestryl is restarting it.'; }
    else {
      if (s.file_watch && h.files === false) { level = 'warn'; text += ' File monitoring was stopped and is being restarted.'; }
      else if (s.file_watch && h.files_error) { level = 'warn'; text += ` File monitoring could not start: ${esc(h.files_error)}`; }
      else if (!s.file_watch) { level = 'warn'; text += ' File monitoring is off (Settings), so Kestryl cannot see programs opening your passwords.'; }
      if (h.lost > 1000) { level = worse(level, 'warn'); text += ` Windows dropped ${h.lost.toLocaleString()} events because the PC was busy, so some numbers are low.`; }
      if (h.restarts) text += ` Tracing was restarted ${plural(h.restarts, 'time')}.`;
    }
    if (s.learning) text += ' Still learning which programs normally go online (first 10 minutes).';
    add('mon', level, 'Monitoring', st, text, { acts: s.elevated || s.sim ? '' : '<button class="btn sm primary" data-sa="elevate">Restart as administrator</button>' });
  }

  // Alerts
  {
    const al = s.alerts;
    const level = al.high ? 'bad' : al.med ? 'warn' : 'ok';
    const st = al.high ? `${al.high} high` : al.med ? `${al.med} medium` : 'None';
    const text = al.high || al.med
      ? `In the last 24 hours: ${[al.high && `${al.high} high`, al.med && `${al.med} medium`, al.low && `${al.low} low`].filter(Boolean).join(', ')}. Open each one: it says what happened and what to do.`
      : al.low ? `Only ${plural(al.low, 'low-risk note')} in the last 24 hours.` : 'No alerts in the last 24 hours.';
    const inline = ul(al.top.map(t => `<button class="link" data-sa="alert" data-id="${t.id}">${esc(t.title)}</button> <span class="sub">${SEV[t.sev]} · ${esc(t.name)} · ${ago(t.last)}${t.sim ? ' · simulated' : ''}</span>`));
    add('alerts', level, 'Alerts', st, text, { inline, acts: '<button class="btn sm" data-sa="tab" data-v="alerts">Open alerts</button>' });
  }

  // Known malware servers (threat lists) and Defender's verdicts on scanned programs
  {
    const it = s.intel || { lists: [], size: 0 };
    const hits = s.intel_alerts || [];
    const sc = s.scans || { done: 0, queued: 0, threats: [] };
    const thr = sc.threats || [];
    const used = it.lists.filter(l => l.n > 0);
    const newest = Math.max(0, ...it.lists.map(l => l.t));
    let level = 'ok', st = 'None contacted';
    if (hits.some(h => h.sev >= 3) || thr.length) { level = 'bad'; st = thr.length ? 'Malware found' : 'Contacted'; }
    else if (hits.length) { level = 'warn'; st = 'Contacted'; }
    else if (!it.size) { level = 'info'; st = 'Lists loading'; }
    let text = it.size
      ? `Every connection and name lookup is checked against ${it.size.toLocaleString()} known malware servers from ${plural(used.length, 'list')}${newest ? `, updated ${ago(newest)}` : ''}.`
      : 'The threat lists are not downloaded yet: they load a few seconds after start, then every 12 hours.';
    text += hits.length ? ` In the last 7 days a program contacted a listed server ${plural(hits.length, 'time')}.` : ' No program contacted one in the last 7 days.';
    text += ` Microsoft Defender scanned ${plural(sc.done, 'unsigned or risky program')}${sc.queued ? ` (${sc.queued} waiting)` : ''}: ${thr.length ? `${thr.length} flagged` : 'nothing found'}.`;
    const inline = ul(hits.slice(0, 5).map(t => `<button class="link" data-sa="alert" data-id="${t.id}">${esc(t.title)}</button> <span class="sub">${SEV[t.sev]} · ${esc(t.domain || t.ip)} · ${ago(t.last)}</span>`)) +
      ul(thr.map(t => `<b>${esc(t.exe.split('\\').pop())}</b>: ${esc(t.threat)} <span class="sub mono">${esc(t.exe)}</span>`));
    const more = table(['List', 'Entries', 'Updated', 'Problem'], it.lists.map(l => `<tr><td>${esc(l.name)}<div class="sub">${esc(l.desc)}</div></td><td class="r">${l.n.toLocaleString()}</td><td class="muted">${l.t ? ago(l.t) : 'never'}</td><td class="sub wrap">${esc(l.err)}</td></tr>`)) +
      `<p class="note">${it.demo ? 'Simulation: made-up lists, nothing is downloaded. ' : ''}The lists come straight from their publishers; downloading them sends nothing about this PC. With a free abuse.ch key (Settings → Threat lists) Kestryl also checks ThreatFox, the largest list of remote-access trojan and stealer servers.</p>`;
    add('intel', level, 'Known malware servers', st, text, { inline, more, acts: '<button class="btn sm" data-sa="settings" data-v="set-intel">Lists</button>' });
  }

  // Passwords and personal files
  {
    const fa = s.file_alerts || [];
    const up = fa.filter(x => x.rule !== 'secret_read');
    const rd = fa.filter(x => x.rule === 'secret_read');
    let level = 'ok', st = 'Nothing seen', text;
    if (s.mode !== 'full' && !s.sim) { level = 'info'; st = 'Not watched'; text = 'File monitoring needs full monitoring (administrator). Without it Kestryl cannot tell which program opens your saved passwords.'; }
    else if (!s.file_watch) { level = 'info'; st = 'Off'; text = 'File monitoring is off in Settings, so Kestryl cannot tell which program opens your saved passwords.'; }
    else if (up.length) { level = up.some(x => x.sev >= 2) ? 'bad' : 'warn'; st = 'Data sent'; text = `In the last 7 days, ${plural(up.length, 'time')} a program read your passwords, cookies or documents and then sent data out. If you did not import passwords or run a backup, block it, then change your passwords from another device.`; }
    else if (rd.length) { level = rd.some(x => x.sev >= 3) ? 'bad' : rd.some(x => x.sev >= 2) ? 'warn' : 'info'; st = 'Opened'; text = `In the last 7 days, ${plural(rd.length, 'program')} opened saved passwords, cookies, wallets or keys that belong to another app, but sent nothing out afterwards.`; }
    else text = 'In the last 7 days no program other than their owner opened your saved browser passwords, cookies, crypto wallets, Telegram or Discord logins, or SSH keys, and none collected your documents and uploaded them.';
    const inline = ul(fa.slice(0, 6).map(t => `<button class="link" data-sa="alert" data-id="${t.id}">${esc(t.title)}</button> <span class="sub">${SEV[t.sev]} · ${ago(t.last)}</span>`));
    add('files', level, 'Passwords and personal files', st, text, { inline });
  }

  // Data sent today
  {
    const t = s.today;
    let level = 'info';
    const top = t.top.map(x => `${esc(x.name)} ${fmtB(x.out)}${x.dest ? ' → ' + esc(x.dest) : ''}`).join('; ');
    let text = `${fmtB(t.out)} sent and ${fmtB(t.in)} received today by ${plural(t.programs, 'program')}.${top ? ' Most went out from: ' + top + '.' : ''}`;
    if (t.night > 0) text += ` Between midnight and 6 am: ${fmtB(t.night)}${t.night_top.length ? ' (' + t.night_top.map(x => esc(x.name) + ' ' + fmtB(x.out)).join(', ') + ')' : ''}.`;
    if (t.night >= 100 * 1048576) { level = 'warn'; text += ' Fine if that was a backup or update; otherwise check who it was.'; }
    add('upload', level, 'Data sent today', fmtB(t.out), text, { acts: '<button class="btn sm" data-sa="tab" data-v="history">History</button>' });
  }

  // Where today's data went: countries and companies (offline database)
  {
    const m = s.map || {};
    const g = s.geo || {};
    const cs = (m.countries || []).filter(c => c.key !== '??' && c.out > 0);
    const os = (m.orgs || []).filter(o => o.key !== 'Unknown' && o.out > 0);
    const pct = b => (m.out ? Math.max(1, Math.round(b / m.out * 100)) : 0);
    let text, st = cs.length ? ccName(cs[0].key) : '–';
    if (!g.ready && !g.demo) { st = 'No data yet'; text = g.err ? `The country database could not be downloaded: ${esc(g.err)}` : 'The country and company database is downloading (about 12 MB, once a month). Until then Kestryl cannot say where data went.'; }
    else if (!cs.length) text = 'Nothing was sent to the internet today yet.';
    else {
      text = `Most of what was sent today went to ${cs.slice(0, 4).map(c => `${esc(ccName(c.key))} (${pct(c.out)}%)`).join(', ')}` +
        `${os.length ? `, to servers of ${os.slice(0, 4).map(o => esc(o.key)).join(', ')}` : ''}.`;
      const abroad = cs.filter(c => s.home && c.key !== s.home);
      if (s.home && abroad.length) text += ` Data leaving ${esc(ccName(s.home))} is normal: most big services run their servers in other countries.`;
    }
    add('places', 'info', 'Where your data went', st, text, { acts: '<button class="btn sm" data-sa="tab" data-v="places">Places</button>' });
  }

  // While you were away: what was sent while the screen was locked or nobody used the PC
  {
    const reps = s.away || [];
    const week = Date.now() - 7 * 86400000;
    const flagged = reps.filter(r => r.flagged && r.end >= week);
    const last = reps[0];
    const level = flagged.length ? 'warn' : 'ok';
    const st = s.away_now ? 'Recording' : flagged.length ? 'Check' : last ? fmtB(awayOut(last)) : 'Nothing yet';
    let text = s.away_now ? `Nobody has used this PC since ${clockShort(s.away_now)}; Kestryl is noting what is sent. ` : '';
    text += last ? `Last time you were away (${awayWhen(last)}): ${awaySummary(last)}`
      : 'When you lock the screen or leave the PC alone for 10 minutes, Kestryl notes what every program sends until you are back, and shows it here.';
    if (flagged.length) text += ` In the last 7 days, ${flagged.length === 1 ? 'once' : flagged.length + ' times'} an unsigned or unusual program sent data while you were away: open Details.`;
    const more = reps.length ? reps.map(awayBlock).join('') + '<p class="note">Only programs that sent something to the internet are listed. Kestryl\'s own downloads (threat lists, country data) are left out.</p>' : '';
    add('away', level, 'While you were away', st, text, { more });
  }

  // Remote access and incoming connections
  {
    const active = s.remote.filter(r => r.active);
    const idle = s.remote.filter(r => !r.active);
    const inc = s.incoming.filter(i => i.scope === 'internet');
    const sess = (s.sessions || []).filter(x => x.sev >= 3);
    let level = 'ok', st = 'None';
    let text = 'No remote-control tool is sharing this screen, and no device on the internet is connected to this PC.';
    if (active.length) { level = 'bad'; st = 'Screen shared'; text = `${[...new Set(active.map(r => esc(r.label)))].join(', ')} is sending this screen to another computer right now. If you did not start a support session yourself, close it and block it.`; }
    else if (sess.length) { level = 'bad'; st = 'Connected'; text = `In the last 24 hours: ${esc(sess[0].title)}. Open the alert for details.`; }
    else if (inc.length) { level = 'warn'; st = 'Incoming'; text = `${plural(inc.length, 'connection')} from the internet ${inc.length === 1 ? 'is' : 'are'} open to this PC: ${inc.slice(0, 3).map(i => `${esc(i.name)} on port ${i.port} from ${esc(i.ip)}`).join(', ')}.`; }
    else if (idle.length) { level = 'warn'; st = 'Installed'; text = `${[...new Set(idle.map(r => esc(r.label)))].join(', ')} is running but not sharing the screen now. Fine if you use it; fake "support" callers install exactly these tools.`; }
    const ti = s.today.inbound || [];
    const more = table(['Remote-control tool', 'Process', 'Sent last minute', 'Online'], s.remote.map(r => `<tr><td>${esc(r.label)}</td><td>${esc(r.name)} <span class="sub">${r.pid}</span></td><td class="num">${fmtB(r.out_min)}</td><td>${r.online ? 'yes' : 'no'}</td></tr>`)) +
      table(['Connected to this PC today', 'Program', 'Port', 'Sent', 'Last'], ti.map(r => `<tr><td class="num">${esc(r.dest)}${r.lan ? '' : ' <span class="tag med">internet</span>'}</td><td>${esc(r.name)}</td><td class="num">${r.port} <span class="sub">${esc(SVC[r.port] || '')}</span></td><td class="num">${fmtB(r.out)}</td><td class="num muted">${ago(r.last)}</td></tr>`));
    add('remote', level, 'Remote access', st, text + (ti.length ? ` Today ${plural(ti.length, 'device')} connected in.` : ''), { more, acts: '<button class="btn sm" data-sa="tab" data-v="network">Network</button>' });
  }

  // Camera and microphone (Windows' own record of which program used them)
  {
    const us = [...(s.sensors || [])].sort((x, y) => (y.active - x.active) || (Math.max(y.start, y.stop) - Math.max(x.start, x.stop)));
    const on = us.filter(u => u.active);
    const ca = s.cam_alerts || [];
    let level = ca.some(x => x.sev >= 3) ? 'bad' : ca.some(x => x.sev >= 2) ? 'warn' : 'ok';
    const st = on.length ? 'In use' : 'Off';
    let text = on.length ? `In use right now by ${on.map(u => `${esc(u.name)} (${u.kind})`).join(', ')}.` : 'Nothing is using the camera or microphone right now.';
    const past = [...new Set(us.filter(u => !u.active).map(u => esc(u.name)))];
    if (past.length) text += ` Used in the last 30 days by ${past.slice(0, 5).join(', ')}${past.length > 5 ? ` and ${past.length - 5} more` : ''}.`;
    text += ca.length ? ` ${plural(ca.length, 'program')} Kestryl did not expect turned one on in the last 7 days: open the alert.` : ' Programs for calls and recording are expected; anything else turning them on raises an alert.';
    const inline = ul(ca.slice(0, 4).map(t => `<button class="link" data-sa="alert" data-id="${t.id}">${esc(t.title)}</button> <span class="sub">${SEV[t.sev]} · ${ago(t.last)}</span>`));
    const more = table(['Program', 'Device', 'Last used', ''], us.map(u => `<tr><td>${esc(u.name)}<div class="sub mono">${esc(u.packaged ? 'Store app: ' + u.app : u.app)}</div></td><td>${u.kind}</td>
        <td class="muted">${u.active ? 'started ' + ago(u.start) : ago(u.stop)}</td><td>${u.active ? '<span class="tag high">in use</span>' : ''}</td></tr>`)) +
      '<p class="note">From Windows\' own record (Settings → Privacy &amp; security → Camera / Microphone → Recent activity), which also controls which apps may use them.</p>';
    add('cam', level, 'Camera and microphone', st, text, { inline, more });
  }

  // Clipboard guard (crypto wallet and bank number swaps)
  {
    const ca = state.alerts.filter(x => x.rule === 'clipboard_swap' && Date.now() - x.last < 7 * 86400000);
    let level = 'ok', st = 'On';
    let text = 'Kestryl checks every wallet address and bank account number (IBAN) you copy. If a program swaps it for a different one before you paste, you get an alert. Nothing you copy is saved or sent.';
    if (!s.clip_guard) { level = 'info'; st = 'Off'; text = 'Off in Settings → Protection. When on, Kestryl warns if a program swaps a wallet address or bank account number you copied, the trick "clipper" malware uses to steal payments.'; }
    else if (ca.length) { level = 'bad'; st = 'Swap caught'; text = `In the last 7 days a program changed a wallet address or bank number you had copied (${plural(ca.length, 'time')}). Never send money to an address you did not check letter by letter; open the alert to see which program did it.`; }
    const inline = ul(ca.slice(0, 4).map(t => `<button class="link" data-sa="alert" data-id="${t.id}">${esc(t.title)}</button> <span class="sub">${SEV[t.sev]} · ${ago(t.last)}</span>`));
    add('clip', level, 'Clipboard guard', st, text, { inline, acts: '<button class="btn sm" data-sa="settings" data-v="set-protect">Settings</button>' });
  }

  if (!a) {
    add('av', s.audit_error ? 'warn' : 'info', 'Windows security settings', s.audit_error ? 'Check failed' : 'Checking…', s.audit_error ? `The check failed: ${esc(s.audit_error)}` : 'Reading antivirus, firewall, certificates, proxy, hosts file and startup programs…');
  } else {
    // Antivirus
    {
      const d = a.defender;
      const avs = a.av || [];
      const other = avs.filter(x => x.on && !/defender/i.test(x.name));
      const thr = a.threats || [];
      const failed = thr.filter(x => !x.ok);
      const ex = (a.exclusions || []).filter(x => x && typeof x === 'object');
      const newEx = ex.filter(x => x.seen);
      let level = 'ok', st = 'On', text;
      if (d && d.rtp) text = `Microsoft Defender is on${d.sigAge != null ? `, virus definitions ${plural(d.sigAge, 'day')} old` : ''}.`;
      else if (other.length) text = `${other.map(x => esc(x.name)).join(', ')} protects this PC (Defender steps aside for it).`;
      else { level = 'bad'; st = 'Off'; text = 'No antivirus is scanning files as they arrive. Turn Microsoft Defender back on: Windows Security → Virus &amp; threat protection.'; }
      if (d && d.rtp && d.sigAge > 7) { level = worse(level, 'warn'); text += ' Definitions are out of date: open Windows Security and check for updates.'; }
      if (thr.length) { level = worse(level, failed.length ? 'bad' : 'warn'); st = failed.length ? 'Threat left' : st; text += ` ${plural(thr.length, 'threat')} found in the last 30 days${failed.length ? `, ${failed.length} NOT removed` : ', all dealt with'}.`; }
      else text += ' No threats found in the last 30 days.';
      if (newEx.length) { level = 'bad'; text += ` Defender was told to skip ${newEx.map(x => esc(x.v)).join(', ')} after Kestryl started watching.`; }
      else if (ex.length) { level = worse(level, 'warn'); text += ` Defender skips ${plural(ex.length, 'item')} (exclusions); check you know ${ex.length === 1 ? 'it' : 'them'}.`; }
      if (d && d.quickAge > 30 && d.fullAge > 30) text += ' No scan in the last month.';
      if (!a.exclOk) text += ' (Exclusions can only be read as administrator.)';
      const more = table(['Antivirus', 'State', 'Definitions'], avs.map(x => `<tr><td>${esc(x.name)}</td><td>${x.on ? 'on' : 'off'}</td><td>${x.uptodate ? 'up to date' : 'out of date'}</td></tr>`)) +
        table(['Threat', 'When', 'Removed', 'Where'], thr.map(x => `<tr><td>${esc(x.name || 'unknown')}</td><td class="num">${esc((x.when || '').slice(0, 16).replace('T', ' '))}</td><td>${x.ok ? 'yes' : '<b>no</b>'}</td><td class="mono wrap">${pathHtml(String(x.res || '').replace(/^file:_/, ''))}</td></tr>`)) +
        table(['Excluded from scanning', 'Since'], ex.map(x => `<tr><td class="mono wrap">${pathHtml(x.v)}</td><td class="sub">${seenText(x.seen)}</td></tr>`)) +
        (d ? `<p class="note">Tamper protection: ${d.tamper ? 'on' : 'off'} · last quick scan ${d.quickAge > 1000 ? 'never' : plural(d.quickAge, 'day') + ' ago'} · engine ${esc(d.version)}</p>` : '');
      add('av', level, 'Antivirus', st, text, { more });
    }
    // Firewall
    {
      const fw = a.firewall || [];
      const off = fw.filter(p => !p.on);
      let text = off.length
        ? `Windows Firewall is OFF for ${off.map(p => esc(p.name)).join(', ')} networks: blocks don't apply there and other devices can reach every program that listens. Turn it on: Windows Security → Firewall &amp; network protection.`
        : `Windows Firewall is on for ${fw.map(p => esc(p.name)).join(', ')} networks.`;
      text += ` Kestryl blocks in place: ${(a.fwRules || []).length}.`;
      if (state.rules && state.rules.cut_off) text += ' The internet is cut off by Kestryl.';
      add('fw', off.length ? 'bad' : 'ok', 'Firewall', off.length ? 'Off' : 'On', text, { acts: '<button class="btn sm" data-sa="tab" data-v="blocked">Blocking</button>' });
    }
    // Startup programs
    {
      const it = a.startup || [];
      const high = it.filter(x => x.risk === 'high');
      const med = it.filter(x => x.risk === 'med');
      const fresh = it.filter(x => x.seen);
      let text;
      const names = list => list.slice(0, 4).map(x => `<b>${esc(x.name.replace(/^\\/, ''))}</b>`).join(', ') + (list.length > 4 ? ` and ${list.length - 4} more` : '');
      if (high.length) text = `${high.length} look${high.length === 1 ? 's' : ''} dangerous: ${names(high)}. Open Details to see why; if one is yours, press Mark as mine, otherwise remove it and run a full virus scan.`;
      else if (med.length) text = `${med.length} need${med.length === 1 ? 's' : ''} a look: ${names(med)}. Open Details to see why.`;
      else text = 'All are signed, in normal program folders, or marked as yours.';
      text += ` ${plural(it.length, 'program')} start${it.length === 1 ? 's' : ''} automatically in total (Run keys, Startup folders, scheduled tasks, services, drivers, WMI, Winlogon and debugger hooks).`;
      if (fresh.length) text += ` ${fresh.length} added since Kestryl started watching.`;
      const rank = x => (x.risk === 'high' ? 0 : x.risk === 'med' ? 1 : 2);
      const sigText = x => (x.sig === 'Valid' ? (x.signer ? 'signed by ' + esc(x.signer) : 'signed') : esc({ NotSigned: 'unsigned', HashMismatch: 'broken signature', Missing: 'file missing', Error: 'signature unreadable' }[x.sig] || x.sig || 'unknown'));
      const srow = x => irow({
        cls: x.risk,
        name: esc(x.name.replace(/^\\/, '')),
        tags: (RISK[x.risk] || '') + (x.acked ? '<span class="tag ok">marked as yours</span>' : ''),
        meta: [esc(x.where), sigText(x), x.seen ? 'added ' + new Date(x.seen).toLocaleDateString() : 'there before Kestryl started watching'].join(' · '),
        path: x.cmd || x.exe,
        pop: [x.cmd || x.exe, x.exe && x.exe !== x.cmd ? 'Program: ' + x.exe : ''].filter(Boolean).join('\n'),
        why: x.why && !x.acked ? esc(x.why[0].toUpperCase() + x.why.slice(1)) + '.' : '',
        acts: (x.exe && x.sig !== 'Missing' ? `<button class="btn sm" data-sa="show" data-v="${esc(x.exe)}">Show file</button>` : '') +
          (x.acked ? `<button class="btn sm" data-sa="ack" data-v="${esc(x.key)}" data-on="">Unmark</button>`
            : x.risk !== 'ok' ? `<button class="btn sm" data-sa="ack" data-v="${esc(x.key)}" data-on="1" title="This is mine: stop reporting it">Mark as mine</button>` : ''),
      });
      const sorted = [...it].sort((x, y) => rank(x) - rank(y) || (y.seen || 0) - (x.seen || 0) || x.name.localeCompare(y.name));
      add('startup', high.length ? 'bad' : med.length || fresh.some(x => x.risk !== 'ok') ? 'warn' : 'ok', 'Programs that start with Windows', `${it.length}`, text, {
        more: ilist('startup-ok', sorted.filter(x => x.risk !== 'ok').map(srow), sorted.filter(x => x.risk === 'ok').map(srow), 'normal ones') +
          '<p class="note">Hover a command to see it in full. To remove an entry: Task Manager → Startup apps for Run entries, Task Scheduler (taskschd.msc) for tasks, or Sysinternals Autoruns, which shows every place and can delete entries. Kestryl itself only reads them.</p>',
      });
    }
    // Network settings that redirect or read traffic
    {
      const px = a.proxy || {};
      const proxyOn = px.on || px.pac || px.winhttp;
      const hosts = a.hosts_list || [];
      const hh = hosts.filter(x => x.risk === 'high'), hm = hosts.filter(x => x.risk === 'med');
      const roots = (a.roots || []).filter(r => !r.own); // Kestryl's own publisher / decryption certificate
      const own = r => r.issuer === r.subject && (cnOf(r.subject).toUpperCase() === String(a.computer || '').toUpperCase() || /^(DESKTOP|LAPTOP|WIN|PC)-[A-Z0-9]{4,}$/i.test(cnOf(r.subject)) || cnOf(r.subject) === 'localhost');
      const rNew = roots.filter(r => r.seen), rKey = roots.filter(r => r.key && !own(r));
      const dns = (a.dns || []).flatMap(i => (i.servers || []).map(sv => ({ ...sv, iface: i.iface })));
      const dnsUnknown = dns.filter(d => d.kind === 'unknown');
      let level = 'ok';
      const notes = [];
      if (hh.length) { level = 'bad'; notes.push(`the hosts file redirects or blocks ${plural(hh.length, 'important site')} (${hh.slice(0, 3).map(x => esc(x.host)).join(', ')})`); }
      if (rNew.some(r => r.key)) { level = 'bad'; notes.push('a root certificate with its private key on this PC was added: a program here can read your HTTPS traffic'); }
      if (proxyOn) { level = worse(level, 'warn'); notes.push(`a proxy is set (${esc(px.server || px.pac || px.winhttp)}): web traffic goes through it first`); }
      if (rKey.length && !rNew.some(r => r.key)) { level = worse(level, 'warn'); notes.push(`${plural(rKey.length, 'trusted root certificate')} ${rKey.length === 1 ? 'has its' : 'have their'} private key on this PC (${rKey.slice(0, 2).map(r => esc(cnOf(r.subject))).join(', ')}), so the program that made ${rKey.length === 1 ? 'it' : 'them'} can read HTTPS traffic. Antivirus web shields and developer tools (Fiddler, mkcert) do this on purpose`); }
      if (rNew.length && !rNew.some(r => r.key)) { level = worse(level, 'warn'); notes.push(`${plural(rNew.length, 'new root certificate')} since Kestryl started watching`); }
      if (dnsUnknown.length) { level = worse(level, 'warn'); notes.push(`unfamiliar DNS server${dnsUnknown.length > 1 ? 's' : ''} ${dnsUnknown.map(d => esc(d.ip)).join(', ')}`); }
      if (hm.length) { level = worse(level, 'warn'); notes.push(`the hosts file sends ${plural(hm.length, 'name')} to local addresses`); }
      const dnsText = [...new Set(dns.map(d => (d.label ? `${d.label} (${d.ip})` : d.kind === 'local' ? `local ${d.ip}` : d.ip)))].map(esc).join(', ') || 'automatic';
      const text = notes.length ? `Found: ${notes.join('; ')}.` : `No proxy, no hosts-file redirects, no new or self-made root certificates. DNS: ${dnsText}.`;
      const more = `<dl class="kv"><dt>Proxy</dt><dd>${proxyOn ? esc([px.on ? px.server : '', px.pac, px.winhttp && 'WinHTTP ' + px.winhttp].filter(Boolean).join(' · ')) : 'none'}</dd><dt>DNS servers</dt><dd>${dns.map(d => `${esc(d.ip)} <span class="sub">${esc(d.label || d.kind)} · ${esc(d.iface)}</span>`).join('<br>') || '–'}</dd></dl>` +
        table(['Hosts file entry', 'Points to', 'Since'], hosts.filter(x => x.host !== 'localhost').map(x => `<tr><td class="mono">${esc(x.host)} ${RISK[x.risk] || ''}</td><td class="mono">${esc(x.ip)}</td><td class="sub">${seenText(x.seen)}</td></tr>`)) +
        table(['Root certificate', 'Private key here', 'Valid', 'Since'], roots.filter(r => r.key || r.seen).map(r => `<tr><td class="wrap">${esc(cnOf(r.subject))} <span class="sub">${esc(r.store)}${own(r) ? ' · this PC\'s own certificate (made by Windows or a developer tool for this machine)' : ''}</span></td><td>${r.key ? (own(r) ? 'yes' : '<b>yes</b>') : 'no'}</td><td class="num">${esc(r.from)} – ${esc(r.to)}</td><td class="sub">${seenText(r.seen)}</td></tr>`)) +
        `<p class="note">${roots.length} trusted root certificates in total; only new ones and ones with a private key on this PC are listed. Remove one with Win+R → certmgr.msc.</p>`;
      add('netcfg', level, 'Proxy, DNS, hosts file and certificates', level === 'ok' ? 'Clean' : 'Changed', text, { more });
    }
    // Remote Desktop, sharing, UAC
    {
      const sh = a.shares || [];
      let level = 'ok', st = 'RDP off';
      const notes = [];
      if (a.uac === false) { level = 'bad'; st = 'UAC off'; notes.push('User Account Control is OFF: every program gets administrator rights without asking'); }
      if (a.rdp) { level = worse(level, 'warn'); st = 'RDP on'; notes.push('Remote Desktop is ON: anyone who can reach this PC can try to log in with a Windows password'); }
      if (sh.length) notes.push(`this PC shares ${plural(sh.length, 'folder')} on the network: ${sh.map(x => `${esc(x.name)} (${esc(x.path)})`).join(', ')}. Other devices may read them, depending on their permissions`);
      const text = notes.length ? notes.join('; ').replace(/^./, c => c.toUpperCase()) + '.' + (a.rdp || a.uac === false ? '' : ' Remote Desktop is off and User Account Control is on.') : 'Remote Desktop is off, no folders are shared, and User Account Control is on.';
      add('rdp', level, 'Remote Desktop, sharing and UAC', st, text);
    }
    // Windows Update
    {
      const d = a.lastUpdate ? daysAgo(a.lastUpdate) : null;
      if (d == null) add('upd', 'info', 'Windows Update', 'Unknown', 'Could not read the update history.');
      else add('upd', d > 45 ? 'warn' : 'ok', 'Windows Update', d === 0 ? 'Today' : d === 1 ? 'Yesterday' : `${d} days ago`,
        d > 45 ? `The last update was installed ${d} days ago. Security fixes come every month: Settings → Windows Update → Check for updates.` : `The last update was installed ${d === 0 ? 'today' : d === 1 ? 'yesterday' : plural(d, 'day') + ' ago'}.`);
    }
  }

  // Analytics and telemetry switches (Blocking tab)
  {
    const n = s.analytics_on || 0;
    const total = (state.analytics && state.analytics.length) || 5;
    add('analytics', n ? 'ok' : 'info', 'Analytics and telemetry', n ? `${n} of ${total} blocked` : 'Allowed',
      n ? `${plural(n, 'analytics switch', 'analytics switches')} of ${total} ${n === 1 ? 'is' : 'are'} on: less usage data goes to Microsoft and Google. Each one can be undone on the Blocking tab.`
        : 'Windows, Edge, Office and Chrome send usage data to their makers, as they do on every PC. You can turn that off on the Blocking tab; each switch can be undone.',
      { acts: '<button class="btn sm" data-sa="tab" data-v="blocked">Blocking</button>' });
  }

  // Programs online now
  {
    const r = s.risky || [];
    const bad = r.filter(x => x.class === 'risky' || x.sig === 'invalid' || x.script === 'lolbin');
    let level = bad.length ? 'bad' : r.length ? 'warn' : 'ok';
    let text = r.length
      ? `${plural(r.length, 'program')} used the internet in the last 5 minutes while unsigned, in a temp or download folder, or being a built-in Windows tool: ${r.slice(0, 4).map(x => esc(x.name)).join(', ')}.`
      : 'Every program online in the last 5 minutes is signed or a normal part of Windows.';
    if (s.trust_broken.length) { level = worse(level, 'warn'); text += ` ${plural(s.trust_broken.length, 'trusted program')} changed since you trusted ${s.trust_broken.length === 1 ? 'it' : 'them'}: ${s.trust_broken.map(k => esc(k.split('\\').pop())).join(', ')}.`; }
    add('online', level, 'Programs online now', r.length ? `${r.length}` : 'Normal', text, { acts: '<button class="btn sm" data-sa="tab" data-v="activity">Activity</button>' });
  }

  // Review of every program ever seen online
  {
    const rv = s.review || [];
    const todo = x => !x.trusted && !x.blocked && x.exists; // still to look at
    const hi = rv.filter(x => x.risk === 'high' && todo(x));
    const md = rv.filter(x => x.risk === 'med' && todo(x));
    const nb = rv.filter(x => x.blocked).length;
    const text = `Kestryl has seen ${plural(s.known_total, 'program')} use the internet. ${rv.length} live outside Windows and Program Files${hi.length ? `; ${hi.length} of them in temp or download folders or with a broken signature` : ''}${md.length ? `; ${md.length} unsigned` : ''}${nb ? `; ${nb} blocked by you` : ''}. Programs that were already there when Kestryl was installed never count as new, so look through this list once. Block or trust a program to take it off the list.`;
    const rrow = x => irow({
      cls: (todo(x) ? x.risk : '') + (x.exists ? '' : ' dim'),
      name: esc(x.exe.split('\\').pop()),
      tags: x.blocked ? '<span class="tag ok">blocked</span>' : x.trusted ? '<span class="tag ok">trusted</span>' : RISK[x.risk] || '',
      meta: [x.sig === 'signed' ? (x.signer ? 'signed by ' + esc(x.signer) : 'signed') : esc({ pending: 'checking signature…', unknown: 'signature not checked yet', unsigned: 'unsigned', invalid: 'broken signature', untrusted: 'untrusted signer' }[x.sig] || x.sig),
        esc(CLASS[x.class] || x.class), esc(originShort(x.from)), x.exists ? '' : 'file no longer there'].filter(Boolean).join(' · '),
      path: x.exe,
      why: x.from && x.from.kind === 'download' && todo(x) ? esc(oddSource(x.from.site)) : '',
      acts: x.exists ? `<button class="btn sm" data-sa="show" data-v="${esc(x.exe)}">Show file</button>` +
        (x.blocked ? `<button class="btn sm" data-sa="unblock" data-v="${esc(x.blocked)}">Unblock</button>` : `<button class="btn sm" data-sa="block" data-v="${esc(x.exe)}">Block</button>`) : '',
    });
    const flagged = rv.filter(x => x.risk !== 'ok' && todo(x));
    add('review', hi.length ? 'warn' : md.length ? 'warn' : 'ok', 'Programs to review once', hi.length || md.length ? `${hi.length + md.length} to check` : 'Fine', text,
      { more: ilist('review-ok', flagged.slice(0, 100).map(rrow), rv.filter(x => !flagged.includes(x)).slice(0, 300).map(rrow), 'programs') });
  }
  return C;
}

const cnOf = subj => { const m = String(subj || '').match(/CN=("[^"]+"|[^,]+)/); return m ? m[1].replace(/"/g, '') : subj; };

const CK_IC = { mon: 'E9D9', alerts: 'EA8F', intel: 'E730', files: 'E8D7', upload: 'E898', remote: 'E7F8', cam: 'E722', av: 'EA18', fw: 'ECE4',
  startup: 'E7E8', netcfg: 'E7EF', rdp: 'E703', upd: 'E895', online: 'E774', review: 'E71D', places: 'E909', away: 'E823', clip: 'E77F', analytics: 'E890' };

// ---- "While you were away" reports
const durText = ms => { const m = Math.round(ms / 60000); return m < 60 ? plural(m, 'minute') : `${Math.floor(m / 60)} h ${String(m % 60).padStart(2, '0')} min`; };
const awayProgs = r => (r.progs || []).filter(p => !p.own && p.out > 0);
const awayOut = r => awayProgs(r).reduce((a, p) => a + p.out, 0);
const awayWhen = r => `${r.why === 'locked' ? 'screen locked' : 'PC not used'} ${new Date(r.start).toDateString() === new Date().toDateString() ? '' : fmtDay(r.start) + ' '}${clockShort(r.start)}–${clockShort(r.end)}, ${durText(r.end - r.start)}`;
const destText = d => `${esc(d.dest)}${d.cc || d.org ? ` (${esc([d.cc ? ccName(d.cc) : '', d.org].filter(Boolean).join(', '))})` : ''}`;
function awaySummary(r) {
  const ps = awayProgs(r).sort((a, b) => b.out - a.out);
  if (!ps.length) return 'nothing was sent.';
  return `${fmtB(awayOut(r))} sent by ${plural(ps.length, 'program')}: ` +
    ps.slice(0, 3).map(p => `${esc(p.name)} ${fmtB(p.out)}${p.dests && p.dests[0] ? ' to ' + destText(p.dests[0]) : ''}`).join('; ') + (ps.length > 3 ? `; and ${ps.length - 3} more` : '') + '.';
}
const awayBlock = r => {
  const ps = awayProgs(r).sort((a, b) => b.flagged - a.flagged || b.out - a.out);
  return `<div class="sh" style="margin:6px 0 4px">${esc(awayWhen(r)[0].toUpperCase() + awayWhen(r).slice(1))}<small>${fmtB(awayOut(r))} sent${r.sim ? ' · simulated' : ''}</small></div>` +
    (ps.length ? `<div class="ilist">${ps.map(p => irow({
      cls: p.flagged ? 'high' : '',
      name: esc(p.name),
      tags: p.flagged ? '<span class="tag high">unusual</span>' : p.trusted ? '<span class="tag ok">trusted</span>' : '',
      meta: `${fmtB(p.out)} sent · ${fmtB(p.in)} received`,
      why: (p.dests || []).slice(0, 4).map(d => `${destText(d)} ${fmtB(d.out)}`).join(' · ') +
        (p.flagged ? '<br>Unsigned, in a temp or download folder, or a Windows tool, and it sent data while nobody was at the PC.' : ''),
    })).join('')}</div>` : '<p class="muted" style="margin:0">Nothing was sent.</p>');
};
const PH_COL = ['--s1', '--s2', '--s3', '--s4'];

// Stacked bars of bytes sent per hour, one colour per program (biggest four, then Other).
function stackBars(svg, ph, nowHour, night = false, single = '') {
  const W = svg.clientWidth, HH = svg.clientHeight;
  if (!W) return;
  svg.setAttribute('viewBox', `0 0 ${W} ${HH}`);
  const tp = 6, bottom = 20, left = 56, bw = (W - left) / 24;
  const tot = Array(24).fill(0);
  ph.forEach(p => p.v.forEach((b, h) => (tot[h] += b)));
  // Gridline step: a round number of MB (0.25, 0.5, 1, 2, 2.5, 5, 10, ...) so 4 steps cover the busiest hour.
  const maxMb = Math.max(1, ...tot) / 1048576;
  const e = Math.pow(10, Math.floor(Math.log10(maxMb / 4)));
  const step = [1, 2, 2.5, 5, 10].find(k => k * e * 4 >= maxMb) * e * 1048576;
  const top = step * 4, gc = cssv('--grid'), t2 = cssv('--tx2');
  const label = b => (b >= 1073741824 ? +(b / 1073741824).toFixed(1) + ' GB' : b >= 1048576 ? +(b / 1048576).toFixed(b < 10485760 ? 1 : 0) + ' MB' : Math.round(b / 1024) + ' KB');
  let g = '';
  if (night) g += `<rect x="${left}" y="${tp}" width="${bw * 6}" height="${HH - bottom - tp}" fill="${cssv('--panel2')}"/>`;
  for (let k = 0; k <= 4; k++) { const v = step * k, y = HH - bottom - v / top * (HH - bottom - tp); g += `<line x1="${left}" x2="${W}" y1="${y}" y2="${y}" stroke="${gc}"/><text x="${left - 8}" y="${y + 4}" text-anchor="end">${k ? label(v) : '0'}</text>`; }
  for (let h = 0; h < 24; h++) {
    const x = left + h * bw + 3, w = Math.max(2, bw - 6);
    let y = HH - bottom;
    ph.forEach((p, i) => {
      const b = p.v[h] || 0;
      if (!b) return;
      const hh = Math.max(1, b / top * (HH - bottom - tp));
      y -= hh;
      g += `<rect x="${x}" y="${y}" width="${w}" height="${hh}" fill="${single || cssv(p.key ? PH_COL[i] || '--s5' : '--s6')}"><title>${esc(p.name)} ${String(h).padStart(2, '0')}:00, ${fmtB(b)}</title></rect>`;
    });
    if (h % 3 === 0) g += `<text x="${x + w / 2}" y="${HH - 5}" text-anchor="middle">${String(h).padStart(2, '0')}:00</text>`;
  }
  if (nowHour != null) {
    const nx = left + (nowHour + 1) * bw;
    g += `<line x1="${nx}" x2="${nx}" y1="${tp}" y2="${HH - bottom}" stroke="${t2}" stroke-dasharray="2 3"/><text x="${nx + 5}" y="${tp + 9}" fill="${t2}">now</text>`;
  }
  svg.innerHTML = `<g font-family="Segoe UI Variable Text, Segoe UI" font-size="11" fill="${cssv('--tx3')}">${g}</g>`;
}
const phLegend = ph => ph.map((p, i) => `<span><i style="background:${cssv(p.key ? PH_COL[i] || '--s5' : '--s6')}"></i>${esc(p.name)}</span>`).join('');

function renderStatus() {
  const s = state.status;
  const box = $('#status');
  if (state.tab === 'status') setHtml($('#head-acts'), `<button class="btn" data-sa="recheck" ${state.checking ? 'disabled' : ''}>${state.checking ? 'Checking…' : 'Check again'}</button>`);
  if (!s) { box.innerHTML = '<div class="empty">Loading…</div>'; return; }
  const C = statusChecks(s);
  const bad = C.filter(c => c.level === 'bad'), warn = C.filter(c => c.level === 'warn');
  const pending = !s.audit_t && !s.audit_error;
  const n = bad.length + warn.length;
  const [cls, head, lead] = bad.length
    ? ['bad', 'Action needed', `${n === 1 ? 'One thing' : plural(n, 'thing')} on this PC ${n === 1 ? 'needs' : 'need'} your attention. Everything else Kestryl checks looks normal.`]
    : warn.length ? ['warn', 'Worth a look', `${n === 1 ? 'One thing is' : plural(n, 'thing') + ' are'} worth a look. Often fine: you may have set ${n === 1 ? 'it' : 'them'} up yourself.`]
    : pending ? ['wait', 'Checking…', 'Network monitoring is running; the Windows security check takes a few seconds.']
    : ['ok', 'All clear', 'Everything Kestryl checks looks normal right now.'];
  const first = t => t.replace(/<[^>]+>/g, '').split('. ')[0].replace(/\.+$/, '');
  const att = [...bad, ...warn].slice(0, 4).map(c => `<div class="att"><span class="chip ${c.level === 'bad' ? 'bad' : 'warn'}">${c.level === 'bad' ? 'Act now' : 'Check'}</span>
      <div><b>${esc(c.title)}: ${esc(c.st)}</b><small>${esc(first(c.text))}</small></div>
      <button class="btn ${c.level === 'bad' ? 'primary' : ''}" data-sa="go" data-v="${c.key}">Review</button></div>`).join('') +
    (n > 4 ? `<div class="att calm"><span></span><div><small>and ${n - 4} more below</small></div></div>` : '') ||
    `<div class="att calm"><span class="chip ok">OK</span><div><b>Nothing needs you right now</b><small>${C.length} checks: traffic, known malware servers, passwords and files, camera, remote access, antivirus, firewall, startup programs and Windows settings.</small></div></div>`;
  const ph = (s.today && s.today.prog_hours) || [];
  const html = `
    <div class="panel verdict ${cls}"><div class="vl"><div class="vk">${head}</div><p>${lead}</p></div><div>${att}</div></div>
    <div class="board">${C.map(c => `<button class="tile ${c.level}" data-sa="go" data-v="${c.key}"><i class="ic">&#x${CK_IC[c.key] || 'EA18'};</i><span class="tt">${esc(c.title)}</span><span class="ts">${esc(c.st)}</span></button>`).join('')}</div>
    <div class="panel today"><div class="ph">Upload by program<small>Today, per hour</small><div class="grow"></div><div class="legend" id="st-legend">${phLegend(ph)}</div></div><svg class="bars" id="st-bars"></svg></div>
    <div class="sh">All checks<small>${s.audit_t ? 'Windows settings checked ' + ago(s.audit_t) : ''}</small></div>
    ${help('st-how', [
      'Kestryl watches all the time: which program sends what where, who connects to this PC, which programs open your passwords and documents or switch on the camera, and whether any of them talks to a known malware server. Every 15 minutes, and within a minute of a change to a startup place, it also checks Windows\' own safety settings.',
      '<b>Green</b>: normal. <b>Amber</b>: worth a look, often fine (you may have set it up yourself). <b>Red</b>: act on it; each row says how.',
      'No tool can prove a PC is clean. Kestryl sees what malware does on the network and to these settings, and asks Microsoft Defender about unsigned programs; keep Defender on and Windows updated.',
      'The first look at the settings becomes the baseline: things that were already there are listed as "there before Kestryl started watching", changes after that raise alerts.',
    ])}
    <div class="sclist">${C.map(c => `<div class="scrow ${c.level}" id="ck-${c.key}">
      <span class="dot"></span>
      <div class="ck"><div><span class="t">${esc(c.title)}</span><span class="st">${esc(c.st)}</span></div>
        <div class="tx">${c.text}</div>${c.inline || ''}
        ${c.more ? `<details data-k="${c.key}"><summary>Details</summary><div class="more">${c.more}</div></details>` : ''}</div>
      <div class="acts">${c.acts || ''}</div></div>`).join('')}</div>`;
  keepOpen(box, html);
  const svg = $('#st-bars');
  if (svg) stackBars(svg, ph, new Date().getHours());
}

async function statusClick(e) {
  const b = e.target.closest('[data-sa]');
  if (!b) return;
  const d = b.dataset;
  if (d.sa === 'tab') switchTab(d.v);
  if (d.sa === 'settings') { switchTab('settings'); setTimeout(() => { const el = $('#' + d.v); if (el) el.scrollIntoView({ block: 'start' }); }, 80); }
  if (d.sa === 'go') {
    const el = $('#ck-' + d.v);
    if (el) {
      const det = el.querySelector('details');
      if (det) det.open = true;
      el.scrollIntoView({ block: 'center', behavior: 'smooth' });
      el.classList.add('flash-on');
      setTimeout(() => el.classList.remove('flash-on'), 1400);
    }
  }
  if (d.sa === 'alert') openAlert(+d.id);
  if (d.sa === 'show') reveal(d.v);
  if (d.sa === 'block' && (await blockApp(d.v, null, d.v.split('\\').pop(), b))) loadStatus(true);
  if (d.sa === 'unblock' && (await act('unblock', { id: d.v }, b))) { loadRules(); loadStatus(true); }
  if (d.sa === 'elevate') act('restart_admin', {}, b);
  if (d.sa === 'ack' && (await act('ack_startup', { key: d.v, on: !!d.on }, b))) loadStatus(true);
  if (d.sa === 'recheck') {
    state.checking = true;
    renderStatus();
    try { state.status = await invoke('audit_now'); flash('Security check done.'); } catch (err) { flash(String(err), true); }
    state.checking = false;
    renderStatus();
  }
}
$('#status').onclick = statusClick;
$('#head-acts').onclick = statusClick;

// ---------------------------------------------------------------- history

const dayLabel = d => {
  const dt = new Date(d + 'T00:00:00');
  const diff = Math.round((new Date(new Date().toDateString()) - dt) / 86400000);
  return diff === 0 ? 'Today' : diff === 1 ? 'Yesterday' : dt.toLocaleDateString([], { weekday: 'short', day: 'numeric', month: 'short' });
};

async function loadHistory(day) {
  try { state.histDays = await invoke('history_days'); } catch (e) { state.histDays = []; }
  day = day || state.histDay || (state.histDays[0] && state.histDays[0].day);
  if (day !== state.histDay) state.histOpen.clear();
  state.histDay = day;
  try { state.hist = day ? await invoke('history_day', { day }) : null; state.histErr = ''; } catch (e) { state.hist = null; state.histErr = String(e); }
  if (state.tab === 'history') renderHistory();
}


function renderHistory() {
  const h = state.hist;
  const days = state.histDays || [];
  const chips = days.map(d => `<button class="${d.day === state.histDay ? 'on' : ''}" data-day="${d.day}"><b>${dayLabel(d.day)}</b><small>${fmtB(d.out)} sent</small></button>`).join('');
  const head = `<h2>History</h2><p class="lead">What every program sent and received, per day, kept for 30 days. Saved every minute, so it survives restarts.</p>
    ${help('hist', [
      '<b>Sent</b> is data that left this PC: uploads, messages, backups, and what other devices took from it. <b>Received</b> is downloads, video, updates.',
      'The two charts show each hour of the day. Grey hours are midnight to 6 am, when most people are away: big uploads then are worth a look unless it was a backup or update.',
      'Click a program to see where its data went. Sites are grouped (all of googlevideo.com is one row); addresses without a name are shown as IPs.',
      'Trusted destinations whose traffic is hidden are left out here too. History starts when this version of Kestryl first ran.',
    ])}
    <div class="days">${chips || '<span class="muted">No days yet.</span>'}</div>`;
  if (!h) { keepOpen($('#history'), head + `<div class="empty">${esc(state.histErr || 'No history yet.')}</div>`); return; }
  const progs = h.programs || [];
  const rows = progs.map(p => {
    const open = state.histOpen.has(p.key);
    const sub = open ? `<tr class="subrows"><td colspan="6"><table class="grid inner"><thead><tr><th>Destination</th><th>Port</th><th class="r">Sent</th><th class="r">Received</th><th class="r">00–06</th><th>First – last</th></tr></thead><tbody>
      ${p.rows.map(r => `<tr><td class="wrap">${esc(r.dest)}${r.ip && r.ip !== r.dest ? ` <span class="sub">${esc(r.ip)}</span>` : ''}${r.inb ? ` <span class="tag ${r.lan ? '' : 'med'}">connected in</span>` : ''}${r.lan ? ' <span class="sub">local network</span>' : ''}</td>
        <td class="num">${r.port || ''}${r.inb && SVC[r.port] ? ` <span class="sub">${SVC[r.port]}</span>` : ''}</td><td class="r num">${fmtB(r.out)}</td><td class="r num">${fmtB(r.in)}</td><td class="r num ${r.night ? 'live' : 'zero'}">${r.night ? fmtB(r.night) : '–'}</td>
        <td class="num muted">${clock(r.first).slice(0, 5)} – ${clock(r.last).slice(0, 5)}</td></tr>`).join('')}
      ${p.dests > p.rows.length ? `<tr><td colspan="6" class="sub">…and ${p.dests - p.rows.length} smaller destinations</td></tr>` : ''}</tbody></table></td></tr>` : '';
    return `<tr class="click ${open ? 'sel' : ''}" data-key="${esc(p.key)}"><td><span class="pname">${esc(p.name)}</span>${p.incoming ? ` <span class="tag">${p.incoming} incoming</span>` : ''}<div class="sub ell" style="max-width:420px;display:block">${esc(p.key)}</div></td>
      <td class="r num">${fmtB(p.out)}</td><td class="r num">${fmtB(p.in)}</td><td class="r num ${p.night ? 'live' : 'zero'}">${p.night ? fmtB(p.night) : '–'}</td><td class="r num">${p.dests}</td>
      <td class="num muted">${clock(p.first).slice(0, 5)} – ${clock(p.last).slice(0, 5)}</td></tr>${sub}`;
  }).join('');
  const inb = h.inbound || [];
  const night = h.hours.slice(0, 6).reduce((a, x) => a + x[0], 0);
  keepOpen($('#history'), head + `
    <h2>${esc(new Date(h.day + 'T00:00:00').toLocaleDateString([], { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' }))}</h2>
    <p class="lead">${fmtB(h.out)} sent · ${fmtB(h.in)} received · ${plural(progs.length, 'program')} · ${plural(inb.length, 'incoming connection')}${night ? ` · ${fmtB(night)} sent between midnight and 6 am` : ''}</p>
    <div class="panel charts">
      <div class="ph">Sent per hour<small>by program · grey hours are midnight to 6 am</small><div class="grow"></div><div class="legend">${phLegend(h.prog_hours || [])}</div></div>
      <svg class="bars" id="hist-bars"></svg>
      <div class="ph second">Received per hour</div>
      <svg class="bars low" id="hist-recv"></svg>
    </div>
    <h2>Programs</h2>
    <div class="box"><table class="grid" id="hist-progs"><thead><tr><th>Program</th><th class="r">Sent</th><th class="r">Received</th><th class="r">00–06</th><th class="r">Destinations</th><th>First – last</th></tr></thead><tbody>
      ${rows || '<tr><td colspan="6" class="empty">Nothing recorded that day.</td></tr>'}</tbody></table></div>
    <h2>Connections other devices made to this PC</h2>
    ${inb.length ? `<div class="box"><table class="grid"><thead><tr><th>From</th><th>Program</th><th>Port</th><th class="r">Sent</th><th class="r">Received</th><th>First – last</th></tr></thead><tbody>
      ${inb.map(r => `<tr><td class="num">${esc(r.dest)}${r.lan ? ' <span class="sub">local network</span>' : ' <span class="tag med">internet</span>'}</td><td>${esc(r.name)}</td><td class="num">${r.port} <span class="sub">${esc(SVC[r.port] || '')}</span></td>
        <td class="r num">${fmtB(r.out)}</td><td class="r num">${fmtB(r.in)}</td><td class="num muted">${clock(r.first).slice(0, 5)} – ${clock(r.last).slice(0, 5)}</td></tr>`).join('')}</tbody></table></div>`
      : '<p class="muted">None that day.</p>'}`);
  const today = h.day === new Date().toLocaleDateString('sv-SE') ? new Date().getHours() : null;
  if ($('#hist-bars')) stackBars($('#hist-bars'), h.prog_hours || [], today, true);
  if ($('#hist-recv')) stackBars($('#hist-recv'), [{ key: '', name: 'Received', v: h.hours.map(x => x[1]) }], today, true, cssv('--s5'));
}

$('#history').onclick = e => {
  const d = e.target.closest('button[data-day]');
  if (d) return loadHistory(d.dataset.day);
  const tr = e.target.closest('tr[data-key]');
  if (tr) {
    const k = tr.dataset.key;
    state.histOpen.has(k) ? state.histOpen.delete(k) : state.histOpen.add(k);
    renderHistory();
  }
};

// ---------------------------------------------------------------- places (where data went)

async function loadPlaces(day) {
  if (day !== undefined && day !== state.placesDay) state.placesSel = null;
  if (day !== undefined) state.placesDay = day;
  state.placesAt = Date.now();
  try { state.histDays = await invoke('history_days'); } catch (e) { /* keep the old list */ }
  try { state.places = await invoke('data_map', { day: state.placesDay }); state.placesErr = ''; } catch (e) { state.places = null; state.placesErr = String(e); }
  if (state.tab === 'places') renderPlaces();
}

// The world, each country shaded by how much was sent there (log scale), home outlined.
function mapSvg(cs, home, sel) {
  const by = new Map(cs.filter(c => c.key !== '??').map(c => [c.key, c]));
  const max = Math.max(1, ...[...by.values()].map(c => c.out));
  const op = c => (c.out ? 0.25 + 0.75 * Math.log(1 + c.out) / Math.log(1 + max) : 0.15).toFixed(2);
  const pop = (cc, c) => esc(`${ccName(cc)}${cc === home ? ' (your country)' : ''}\n${c ? `${fmtB(c.out)} sent, ${fmtB(c.in)} received` : 'Nothing sent here'}`);
  let land = '', dots = '', rings = '';
  for (const [cc, w] of Object.entries(WORLD.c)) {
    const c = by.get(cc);
    const attrs = `data-cc="${cc}" data-pop="${pop(cc, c)}" class="${c ? 'on' : ''}"${c ? ` style="fill:var(--accent);fill-opacity:${op(c)}"` : ''}`;
    if (w.d) {
      land += `<path d="${w.d}" ${attrs}/>`;
      if (cc === home || cc === sel) rings += `<path d="${w.d}" class="ring ${cc === sel ? 'sel' : 'home'}"/>`;
    } else if (c || cc === home) {
      dots += `<circle cx="${w.x}" cy="${w.y}" r="${c ? 4.5 : 3}" ${attrs}/>`;
      if (cc === home || cc === sel) rings += `<circle cx="${w.x}" cy="${w.y}" r="6.5" class="ring ${cc === sel ? 'sel' : 'home'}"/>`;
    }
  }
  return `<svg class="world" viewBox="0 0 ${WORLD.w} ${WORLD.h}" role="img" aria-label="World map of where data was sent">${land}${dots}${rings}</svg>`;
}

function placeRow(x, kind, max, home) {
  const key = `${kind}:${x.key}`;
  const open = state.placesSel === key;
  const name = kind === 'c' ? ccName(x.key) : x.key === 'Unknown' ? 'Unknown company' : x.key;
  const tags = (kind === 'c' && x.key === home ? ' <span class="tag">your country</span>' : '') +
    (x.host ? ` <span class="tag hint" data-pop="${esc(HOST_NOTE)}">hosting company</span>` : '') +
    (x.key === '??' || x.key === 'Unknown' ? ' <span class="tag hint" data-pop="The database has no entry for these addresses: very new, rarely used or private ones.">not in the database</span>' : '');
  const withText = kind === 'c' ? x.with.filter(k => k !== 'Unknown') : x.with.filter(k => k !== '??').map(ccName);
  const det = open ? `<div class="pdet">
      <div><span class="muted">Sites:</span> ${x.sites.map(esc).join(', ') || '–'}${x.n_sites > x.sites.length ? ` <span class="muted">and ${x.n_sites - x.sites.length} more</span>` : ''}</div>
      <div><span class="muted">Programs:</span> ${x.progs.map(p => `${esc(friendly({ name: p.name, exe: p.key }))} <span class="num muted">${fmtB(p.out)}</span>`).join(', ')}${x.n_progs > x.progs.length ? ` <span class="muted">and ${x.n_progs - x.progs.length} more</span>` : ''}</div>
      ${withText.length ? `<div><span class="muted">${kind === 'c' ? 'Companies there' : 'Its servers were in'}:</span> ${withText.map(esc).join(', ')}</div>` : ''}</div>` : '';
  return `<div class="prow ${open ? 'sel' : ''}" data-pk="${esc(key)}">
    <div class="pn1"><b>${esc(name)}</b>${tags}</div>
    <div class="num">${fmtB(x.out)} <span class="muted">sent</span> <span class="adv muted">· ${fmtB(x.in)} received</span></div>
    <div class="pbar"><i style="width:${Math.max(1, x.out / max * 100).toFixed(1)}%"></i></div>
    <div class="ps">${esc(x.sites.slice(0, 3).join(', '))}${x.n_sites > 3 ? ` +${x.n_sites - 3}` : ''} · ${plural(x.n_progs, 'program')}</div>${det}</div>`;
}

function renderPlaces() {
  const m = state.places;
  const s = state.settings || {};
  const g = (m && m.geo) || s.geo || {};
  const home = (m && m.home) || s.home || '';
  const cur = m ? m.day : state.placesDay;
  const chips = (state.histDays || []).map(d => `<button class="${d.day === cur ? 'on' : ''}" data-day="${d.day}"><b>${dayLabel(d.day)}</b><small>${fmtB(d.out)} sent</small></button>`).join('');
  let html = `<h2>Where your data went</h2>
    <p class="lead">Every address your programs sent data to, placed by country and by the company that runs the server. Worked out on this PC from a free database: nothing is looked up online.</p>
    ${help('places', [
      'The map shows where the <b>servers</b> are, not where the company is from. Big services have servers everywhere and you usually reach one nearby, so seeing other countries is normal.',
      '<b>Hosting companies</b> (Amazon, Cloudflare, Akamai, Microsoft Azure…) run servers for thousands of other sites. Their name says whose computer it is; the site names under them tell you who it really was.',
      '<b>Worth a look</b>: a country you have nothing to do with, reached by a program you do not know, especially if it is unsigned or came from a download. Click a country or company to see which programs and sites it was.',
      'Click a day to see an earlier one; days are kept for 30 days. Your local network and trusted destinations whose traffic is hidden are left out.',
    ])}
    <div class="days">${chips || '<span class="muted">No days yet.</span>'}</div>`;
  if (!g.ready && !g.demo) html += `<div class="banner warn" style="margin:8px 0 12px"><span>${g.err ? `The country database could not be downloaded: ${esc(g.err)}` : 'The country and company database is not downloaded yet (about 12 MB, then once a month).'}</span><div class="grow"></div><button class="btn sm primary" data-pa="geo">Download now</button></div>`;
  if (!m) { setHtml($('#places'), html + `<div class="empty">${esc(state.placesErr || 'Loading…')}</div>`); return; }
  const cs = m.countries || [], os = m.orgs || [];
  const nC = cs.filter(c => c.key !== '??').length, nO = os.filter(o => o.key !== 'Unknown').length;
  const maxC = Math.max(1, ...cs.map(c => c.out)), maxO = Math.max(1, ...os.map(o => o.out));
  const sel = state.placesSel && state.placesSel.startsWith('c:') ? state.placesSel.slice(2) : '';
  html += `<p class="lead" style="margin-top:6px">${fmtB(m.out)} sent to ${plural(nC, 'country', 'countries')} and ${plural(nO, 'company', 'companies')}${home ? `. Your country: ${esc(ccName(home))}` : ''}.</p>
    <div class="panel map">${mapSvg(cs, home, sel)}
      <div class="legend"><span><i style="background:var(--accent);opacity:.3"></i>a little</span><span><i style="background:var(--accent)"></i>the most</span>${home ? '<span><i class="lg-home"></i>your country</span>' : ''}<div class="grow"></div><span class="muted">${esc(g.attribution || '')}</span></div></div>
    <div class="pgrid">
      <div class="panel plist"><div class="sech">Countries</div>${cs.map(c => placeRow(c, 'c', maxC, home)).join('') || '<div class="empty">Nothing sent to the internet this day.</div>'}</div>
      <div class="panel plist"><div class="sech">Companies</div>${os.map(o => placeRow(o, 'o', maxO, home)).join('') || '<div class="empty">Nothing sent to the internet this day.</div>'}</div>
    </div>`;
  keepOpen($('#places'), html);
}

$('#places').onclick = e => {
  const d = e.target.closest('button[data-day]');
  if (d) return loadPlaces(d.dataset.day);
  if (e.target.closest('[data-pa="geo"]')) return act('geo_refresh', {}, e.target.closest('button')).then(() => setTimeout(loadPlaces, 20000));
  const cc = e.target.closest('[data-cc]');
  const row = e.target.closest('[data-pk]');
  const key = cc ? `c:${cc.dataset.cc}` : row ? row.dataset.pk : null;
  if (!key) return;
  if (e.target.closest('.pdet')) return;
  state.placesSel = state.placesSel === key ? null : key;
  renderPlaces();
  if (cc) { const r = $(`#places [data-pk="${CSS.escape(key)}"]`); if (r) r.scrollIntoView({ block: 'nearest', behavior: 'smooth' }); }
};

// ---------------------------------------------------------------- HTTPS decryption

async function loadDecrypt() {
  const D = state.dec;
  try { D.st = await invoke('decrypt_state'); } catch (e) { D.st = { err: String(e) }; }
  if (!D.reveal) { try { D.list = await invoke('decrypt_entries', { password: null }); } catch (e) { /* keep */ } }
  if (state.tab === 'decrypt') renderDecrypt();
}

const decProgs = () => {
  const seen = new Set();
  return ((state.snap && state.snap.procs) || [])
    .filter(p => p.exe && !p.own && !p.exited && !seen.has(p.exe.toLowerCase()) && seen.add(p.exe.toLowerCase()))
    .sort((a, b) => (b.internet - a.internet) || friendly(a).localeCompare(friendly(b)));
};

function renderDecrypt() {
  const D = state.dec;
  const st = D.st;
  const box = $('#decrypt');
  if (!st) { box.innerHTML = '<div class="empty">Loading…</div>'; return; }
  if (!$('#dec-pw')) {
    box.innerHTML = `<h2>Read what one program sends over HTTPS</h2>
      <p class="lead">Almost every program encrypts what it sends (HTTPS), so normally nobody can look inside, Kestryl included. If you suspect a program, Kestryl can open its encrypted traffic for a few minutes and show you what it really sends: which pages, which forms, which data.</p>
      ${help('dec-how', [
        '<b>How it works</b>: Kestryl makes a one-time certificate, adds it to Windows for the session only, and sets itself as Windows\' proxy. The chosen program\'s connections are opened, recorded and passed on; every other program goes through untouched.',
        '<b>Locked down</b>: it needs administrator rights and your decryption password. The password is stored only as a slow, salted fingerprint (Argon2id). Five wrong tries lock it for 10 minutes, and every try, start and stop is recorded as an alert.',
        '<b>Short and visible</b>: one program, at most 30 minutes, with a red banner on every page while it runs. When it stops (or Kestryl quits or crashes and starts again) the certificate is deleted and your proxy setting is put back.',
        '<b>Nothing kept</b>: what is recorded stays in memory only, never on disk. Passwords, cookies and tokens in it are hidden until you enter the password again.',
        '<b>Limits</b>: works for programs that use Windows\' proxy setting (browsers and most apps). Programs that ignore it are not seen; programs that only trust their own server certificate (banking apps, some updaters) refuse the connection, and that refusal is listed.',
      ])}
      <div class="panel sec" id="dec-pw"></div>
      <div class="panel sec" id="dec-go"></div>
      <div class="panel sec" id="dec-log"></div>`;
    D.sig = '';
  }
  const locked = st.locked_until > Date.now();
  const can = st.elevated || st.sim;
  const sess = st.session;
  // Password and start form: rebuilt only when their state changes, so typing is never lost.
  const sig = [st.set, locked, can, sess ? sess.id : 0].join('|');
  if (sig !== D.sig) {
    D.sig = sig;
    const why = !can ? 'Needs administrator rights: use "Restart as administrator" at the top.' : locked ? `Locked after 5 wrong passwords until ${clockShort(st.locked_until)}.` : '';
    $('#dec-pw').innerHTML = st.set
      ? `<div class="sech">1. Decryption password <span class="tag ok">set</span></div>
        <details class="fold" style="margin:0 18px 12px"><summary>Change the password</summary>
          <div class="row" style="margin-top:10px"><input type="password" id="dec-old" placeholder="Current password" autocomplete="off"><input type="password" id="dec-n1" placeholder="New password" autocomplete="off"><input type="password" id="dec-n2" placeholder="New password again" autocomplete="off"><button class="btn" id="dec-setpw">Change</button></div></details>`
      : `<div class="sech">1. Set a decryption password</div>
        <p class="sd">Asked for every time decryption starts and to show hidden values. At least 8 characters, not only digits. Choose one only you know; it is not your Windows password.</p>
        <div class="addrow"><input type="password" id="dec-n1" placeholder="New password" autocomplete="off"><input type="password" id="dec-n2" placeholder="Same password again" autocomplete="off"><button class="btn primary" id="dec-setpw" ${can ? '' : 'disabled'}>Set password</button></div>
        ${why && !can ? `<p class="note" style="margin:0 18px 12px">${why}</p>` : ''}`;
    if (sess) {
      $('#dec-go').innerHTML = `<div class="sech">2. Decrypting now</div>
        <div class="srow"><div><b>${esc(sess.name)}</b><small class="mono adv">${esc(sess.exe)}</small><small>Started ${clockShort(sess.start)} · stops by itself at ${clockShort(sess.until)} · <b class="num" id="dec-left"></b> left</small></div>
          <button class="btn dangerf" id="dec-stop">Stop now</button></div>`;
    } else {
      const ps = decProgs();
      const pick = D.pick && ps.some(p => p.exe.toLowerCase() === D.pick) ? D.pick : '';
      $('#dec-go').innerHTML = `<div class="sech">2. Choose a program</div>
        <p class="sd">Kestryl closes the program's open connections so it reconnects through Kestryl. Use the program during the session so it actually sends something.</p>
        <div class="srow"><div><b>Program</b><small>Programs running now; the ones using the internet first</small></div>
          <div class="ctl"><select id="dec-exe" style="max-width:360px"><option value="">Choose…</option>${ps.map(p => `<option value="${esc(p.exe)}" data-name="${esc(p.name)}" ${p.exe.toLowerCase() === pick ? 'selected' : ''}>${esc(friendly(p))}${friendly(p) !== p.name ? ` (${esc(p.name)})` : ''}${p.internet ? '' : ' · offline'}</option>`).join('')}</select>
          <button class="btn sm" id="dec-reload" title="Refresh the list">&#x21bb;</button></div></div>
        <div class="srow"><div><b>For how long</b><small>It stops by itself after this</small></div>
          <div class="ctl"><select id="dec-min">${[5, 10, 15, st.max || 30].map(m => `<option value="${m}" ${m === 10 ? 'selected' : ''}>${m} minutes</option>`).join('')}</select></div></div>
        <div class="srow"><div><b>Decryption password</b><small>${st.set ? 'The password from step 1' : 'Set one in step 1 first'}</small></div>
          <div class="ctl"><input type="password" id="dec-pass" style="width:220px" autocomplete="off" ${st.set ? '' : 'disabled'}></div></div>
        ${why ? `<p class="note" style="margin:0 18px 12px">${why}</p>` : ''}
        <div class="sfoot"><button class="btn dangerf" id="dec-start" ${st.set && can && !locked ? '' : 'disabled'}>Start decrypting</button></div>`;
    }
    wireDecrypt();
  }
  if (sess && $('#dec-left')) $('#dec-left').textContent = mmss(sess.until - Date.now());
  renderDecLog();
}

function renderDecLog() {
  const D = state.dec;
  const list = D.list || [];
  const reqs = list.filter(x => !x.note);
  const hidden = list.reduce((a, x) => a + (x.hidden || 0), 0);
  const row = x => {
    if (x.note) return `<div class="dent note"><div class="l1"><span class="num muted">${clock(x.t)}</span><span>${esc(x.name)} → ${esc(x.host)}${x.port && x.port !== 443 ? ':' + x.port : ''}</span><span>${esc(x.note)}</span></div></div>`;
    const open = D.open.has(x.id);
    const st = x.status ? `<span class="tag ${x.status >= 400 ? 'med' : ''}">${x.status}</span>` : x.done ? '' : '<span class="tag">waiting</span>';
    const det = open ? `<div class="dd">
        ${x.query ? `<div class="sub">Address parameters</div><pre class="dump">${esc(x.query)}</pre>` : ''}
        ${x.body ? `<div class="sub">Sent (${esc(x.kind)}, ${fmtB(x.size)})</div><pre class="dump">${esc(x.body)}</pre>` : ''}
        <div class="sub">Request headers</div><table class="hdr">${(x.headers || []).map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join('')}</table>
        ${x.status ? `<div class="sub" style="margin-top:6px">Answer: ${x.status}${x.resp_type ? ', ' + esc(x.resp_type) : ''}, ${fmtB(x.resp_size)}</div>` : ''}</div>` : '';
    return `<div class="dent ${open ? 'open' : ''}" data-did="${x.id}"><div class="l1"><span class="num muted">${clock(x.t)}</span><span class="m">${esc(x.method)}</span>
      <span class="u">${x.tls ? '' : '<span class="tag med">not encrypted</span> '}${esc(x.host)}${esc(x.path)}</span>${st}
      ${x.size ? `<span class="num">${fmtB(x.size)} sent</span>` : ''}${x.kind && x.kind !== 'none' ? `<span class="sub">${esc(x.kind)}</span>` : ''}
      ${x.hidden ? `<span class="tag hint" data-pop="Passwords, cookies or tokens are hidden. Press Show hidden values and enter the password to see them.">${x.hidden} hidden</span>` : ''}</div>${det}</div>`;
  };
  setHtml($('#dec-log'), `<div class="sech">3. What it sent <small class="muted" style="font-weight:400">${plural(reqs.length, 'request')}, newest first. Click one for details.</small></div>
    <div class="addrow">${D.reveal ? '<button class="btn sm" data-dl="hide">Hide passwords and cookies</button>' : `<button class="btn sm" data-dl="reveal" ${hidden ? '' : 'disabled'}>Show hidden values…</button>`}
      <button class="btn sm" data-dl="clear" ${list.length ? '' : 'disabled'}>Clear</button>${D.reveal ? '<span class="tag high">showing secrets</span>' : ''}</div>
    ${list.length ? `<div class="dlist">${list.map(row).join('')}</div>` : '<div class="empty">Nothing recorded yet.</div>'}`);
}

function wireDecrypt() {
  const D = state.dec;
  const setpw = $('#dec-setpw');
  if (setpw) setpw.onclick = async e => {
    const n1 = $('#dec-n1').value, n2 = $('#dec-n2').value, old = $('#dec-old') ? $('#dec-old').value : '';
    if (n1 !== n2) return flash('The two new passwords are not the same.', true);
    if (await act('decrypt_set_password', { old, new: n1 }, e.currentTarget)) { D.sig = ''; loadDecrypt(); }
  };
  const go = $('#dec-start');
  if (go) go.onclick = async e => {
    const sel = $('#dec-exe');
    const exe = sel.value;
    if (!exe) return flash('Choose a program first.', true);
    const name = sel.selectedOptions[0].dataset.name;
    const btn = e.currentTarget;
    btn.disabled = true;
    try {
      await invoke('decrypt_start', { exe, name, minutes: +$('#dec-min').value, password: $('#dec-pass').value });
      flash(`Decrypting ${name}. Use it now; what it sends shows up below.`);
      D.pick = '';
    } catch (err) { flash(String(err), true); btn.disabled = false; }
    D.sig = '';
    tick();
    loadDecrypt();
  };
  const stop = $('#dec-stop');
  if (stop) stop.onclick = async e => { if (await act('decrypt_stop', {}, e.currentTarget)) { D.sig = ''; tick(); loadDecrypt(); } };
  const rl = $('#dec-reload');
  if (rl) rl.onclick = () => { D.pick = ($('#dec-exe').value || '').toLowerCase(); D.sig = ''; renderDecrypt(); };
  if ($('#dec-exe')) $('#dec-exe').onchange = e => (D.pick = e.target.value.toLowerCase());
}

$('#decrypt').addEventListener('click', async e => {
  const D = state.dec;
  const b = e.target.closest('[data-dl]');
  if (b) {
    if (b.dataset.dl === 'reveal') {
      const pw = await askPassword('Show hidden values?', 'Passwords, cookies and tokens the program sent will be shown on screen. Enter the decryption password.', 'Show');
      if (!pw) return;
      try { D.list = await invoke('decrypt_entries', { password: pw }); D.reveal = true; renderDecLog(); } catch (err) { flash(String(err), true); }
    }
    if (b.dataset.dl === 'hide') { D.reveal = false; loadDecrypt(); }
    if (b.dataset.dl === 'clear' && (await ask('Clear the recording?', 'Everything recorded so far is deleted from memory.', 'Clear'))) { await invoke('decrypt_clear'); D.reveal = false; D.open.clear(); loadDecrypt(); }
    return;
  }
  const r = e.target.closest('.dent[data-did]');
  if (r && !e.target.closest('.dd')) {
    const id = +r.dataset.did;
    D.open.has(id) ? D.open.delete(id) : D.open.add(id);
    renderDecLog();
  }
});

// ---------------------------------------------------------------- peek

const PEEK = { plain: ['high', 'Not encrypted'], custom: ['med', 'Own encryption'], unknown: ['med', 'Unknown protocol'], encrypted: ['ok', 'Encrypted'], empty: ['', 'No data'] };

function peekSheet(ip, port, name, domain) {
  $('#sheet').hidden = false;
  $('#sheet-body').innerHTML = `<h2 class="t">Peek at this traffic</h2>
    <div class="sub">${esc(name || 'Program')} ↔ ${esc(domain || ip)}${domain ? ` <span class="mono">${esc(ip)}</span>` : ''}, port ${port}</div>
    ${help('peek', [
      'Kestryl records this connection\'s packets for a few seconds with Windows\' own Packet Monitor (pktmon), then explains what they are. Use the program during the capture so it actually sends something.',
      '<b>Encrypted</b> (HTTPS, QUIC, SSH): normal. Nobody can read it, Kestryl included; you see the real server name and encryption version instead.',
      '<b>Not encrypted</b>: the contents are shown as sent. Only the login to the server itself (FTP/mail password, Authorization header, cookies) is blanked on screen.',
      '<b>Own encryption</b>: random-looking data on a protocol that is not standard. Games, calls and VPNs may do this; malware control channels very often do.',
      'Needs administrator rights. Nothing is decrypted or kept: the capture file is deleted right after.',
    ], 'What this does')}
    <div class="row" style="margin-top:12px">Capture for <select id="pk-secs"><option value="10">10 seconds</option><option value="20" selected>20 seconds</option><option value="40">40 seconds</option></select>
      <button class="btn primary" id="pk-go">Start</button></div>
    <div id="pk-out"></div>`;
  $('#pk-go').onclick = async e => {
    const btn = e.currentTarget;
    const secs = +$('#pk-secs').value;
    btn.disabled = true;
    let left = secs;
    const out = $('#pk-out');
    out.innerHTML = `<p class="note">Capturing… <b class="num" id="pk-left">${left}</b> s left. Use ${esc(name || 'the program')} now.</p>`;
    const timer = setInterval(() => { left = Math.max(0, left - 1); const el = $('#pk-left'); if (el) el.textContent = left; }, 1000);
    try { renderPeek(await invoke('peek', { ip, port, secs })); }
    catch (err) { out.innerHTML = `<p class="err-text">${esc(err)}</p>`; }
    finally { clearInterval(timer); btn.disabled = false; }
  };
}

function renderPeek(r) {
  const [cls, label] = PEEK[r.verdict] || ['', r.verdict];
  const pre = (t, title) => (t ? `<div class="sub" style="margin-top:8px">${title}</div><pre class="dump">${esc(t)}</pre>` : '');
  $('#pk-out').innerHTML = `
    <div class="peek-sum"><span class="tag ${cls}">${esc(label)}</span> ${esc(r.summary)}</div>
    <div class="sub">${r.packets} packets · ${fmtB(r.out)} sent · ${fmtB(r.in)} received · ${r.secs} s${r.demo ? ' · simulated capture (demo)' : ''}</div>
    ${(r.convs || []).map(c => { const [cc, cl] = PEEK[c.verdict] || ['', c.verdict]; return `<div class="peek-conv">
      <div class="l1"><b>${esc(c.proto.toUpperCase())} ${c.rport}</b> <span class="sub">from local port ${c.lport}</span> <span class="tag ${cc}">${esc(cl)}</span>
        <span class="num muted">${fmtB(c.out)} out · ${fmtB(c.in)} in</span></div>
      <p>${esc(c.summary)}</p>
      ${c.sni || c.tls || c.alpn ? `<dl class="kv"><dt>Server name</dt><dd class="mono">${esc(c.sni || '–')}</dd>${c.tls ? `<dt>Encryption</dt><dd>TLS ${esc(c.tls)}</dd>` : ''}${c.alpn ? `<dt>Protocol</dt><dd>${esc(c.alpn)}</dd>` : ''}</dl>` : ''}
      ${c.names && c.names.length ? pre(c.names.join('\n'), 'Names looked up') : ''}
      ${pre(c.text_out, 'Sent (as text)')}${pre(c.text_in, 'Received (as text)')}${pre(c.hex, 'First bytes')}
    </div>`; }).join('')}
    <p class="note">Peek never decrypts: encrypted traffic stays unreadable, to Kestryl and to anyone on the way. Only traffic that was never encrypted can be shown. To read inside one program's HTTPS, use the Decrypt page (Advanced view, needs your decryption password). The login to the server itself (FTP/mail passwords, Authorization headers, cookies) is blanked; everything else is shown exactly as it was sent, including any of your data inside it.</p>`;
}

// ---------------------------------------------------------------- theme

// Kestryl is everyone's theme until they pick another one in Settings (config.rs DEFAULT_THEME).
const THEMES = [['kestryl', 'Kestryl', ['ks']], ['dark', 'Dark', ['dk']], ['light', 'Light', ['lt']], ['system', 'Follow Windows', ['lt', 'dk']]];
const lightQ = matchMedia('(prefers-color-scheme: light)');
function applyTheme(t) {
  state.theme = ['dark', 'light', 'kestryl', 'system'].includes(t) ? t : 'kestryl';
  const light = state.theme === 'light' || (state.theme === 'system' && lightQ.matches);
  document.documentElement.dataset.theme = state.theme === 'kestryl' ? 'kestryl' : light ? 'light' : 'dark';
}
lightQ.addEventListener('change', () => { applyTheme(state.theme); if (state.tab === 'status') renderStatus(); });
invoke('settings').then(s => { state.settings = s; applyTheme(s.theme); applyView(s.advanced); }).catch(() => applyTheme('kestryl'));
applyTheme('kestryl');

// ---------------------------------------------------------------- simple / advanced view

// Simple hides the network-engineer pages and details (addresses, ports, command lines,
// hashes); everything marked .adv in the HTML. Nothing is re-rendered: CSS does it.
function applyView(adv) {
  state.adv = !!adv;
  document.body.classList.toggle('simple', !state.adv);
  $$('#view button').forEach(b => b.classList.toggle('on', (b.dataset.view === 'advanced') === state.adv));
  const cur = $(`#tabs button[data-tab="${state.tab}"]`);
  if (!state.adv && cur && cur.classList.contains('adv')) switchTab('status');
}
$('#view').onclick = e => {
  const b = e.target.closest('button[data-view]');
  if (!b) return;
  const adv = b.dataset.view === 'advanced';
  if (adv === state.adv) return;
  applyView(adv);
  invoke('set_view', { advanced: adv }).catch(err => flash(String(err), true));
  if (state.settings) state.settings.advanced = adv;
};

// ---------------------------------------------------------------- tabs + loop

function switchTab(t) {
  state.tab = t;
  $('#page-title').textContent = TITLES[t] || '';
  $('#page-sub').textContent = pageSub();
  if (t !== 'status') setHtml($('#head-acts'), '');
  $$('#tabs button[data-tab]').forEach(b => b.classList.toggle('on', b.dataset.tab === t));
  $$('main > section').forEach(s => s.classList.toggle('on', s.id === 'tab-' + t));
  if (t === 'alerts') loadAlerts(true);
  if (t === 'blocked') { renderBlocked(); loadRules(); loadAnalytics(); }
  if (t === 'places') { renderPlaces(); loadPlaces(); }
  if (t === 'decrypt') { state.dec.sig = ''; loadDecrypt(); }
  if (t === 'settings') {
    loadSettings();
    invoke('autostart', { on: null }).then(r => { state.autostart = r.on; if (state.tab === 'settings') renderSettings(); }).catch(() => {});
  }
  if (t === 'network') { renderNetwork(); if (!state.netExtra) loadNetExtra(); }
  if (t === 'status') { renderStatus(); loadStatus(true); }
  if (t === 'history') { renderHistory(); loadHistory(); }
  tick();
}
$('#tabs').onclick = e => { const b = e.target.closest('button[data-tab]'); if (b) switchTab(b.dataset.tab); };

// Menu with labels, or icons only (hover shows the name). Remembered on this PC.
function setMini(on) {
  document.body.classList.toggle('mini', on);
  $('#mini-btn .ic').innerHTML = on ? '&#xE8A0;' : '&#xE89F;';
}
$('#mini-btn').onclick = () => {
  const on = !document.body.classList.contains('mini');
  setMini(on);
  try { localStorage.setItem('kestryl-mini', on ? '1' : '0'); } catch { /* storage off: still works for this session */ }
};
try { setMini(localStorage.getItem('kestryl-mini') === '1'); } catch { /* storage off */ }

let ticking = false;
async function tick() {
  if (ticking) return;
  ticking = true;
  try {
    state.snap = await invoke('snapshot');
    feedGraph(state.snap);
    renderTop();
    if (document.hidden) return;
    if (state.tab === 'status') await loadStatus();
    else if (state.tab === 'activity') {
      if (state.snapN++ % 3 === 0) await loadAlerts();
      renderGraph();
      renderActivity();
      if (state.sel == null) renderSide();
      await renderDetailFlows();
    }
    else if (state.tab === 'connections') await renderConnections();
    else if (state.tab === 'alerts') await loadAlerts();
    else if (state.tab === 'dns') await renderDns();
    else if (state.tab === 'network') await renderNetwork();
    else if (state.tab === 'decrypt') await loadDecrypt();
    else if (state.tab === 'places' && Date.now() - state.placesAt > 30000) await loadPlaces();
  } catch (e) {
    console.error(e);
  } finally {
    ticking = false;
  }
}
setInterval(tick, 1000);
setInterval(loadRules, 30000);
setInterval(() => { if (state.tab === 'history' && !document.hidden) loadHistory(); }, 30000);
tick();
loadRules();
loadAnalytics();
loadStatus(true);
