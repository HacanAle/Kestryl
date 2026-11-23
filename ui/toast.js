'use strict';
const { invoke } = window.__TAURI__.core;
const win = window.__TAURI__.window.getCurrentWindow();
const $ = s => document.querySelector(s);
const SEV = { 3: 'High risk', 2: 'Medium risk', 1: 'Low risk' };
const fmtB = b => (b >= 1048576 ? (b / 1048576).toFixed(1) + ' MB' : b >= 1024 ? Math.round(b / 1024) + ' KB' : b + ' B');

let cur = null;
let timer = null;
let hover = false;

function arm(ms = 15000) {
  clearTimeout(timer);
  timer = setTimeout(() => (hover ? arm(3000) : win.hide()), ms);
}

// kestryl (default) | dark | light | system.
function applyTheme(t) {
  if (!['dark', 'light', 'kestryl', 'system'].includes(t)) t = 'kestryl';
  const light = t === 'light' || (t === 'system' && matchMedia('(prefers-color-scheme: light)').matches);
  document.documentElement.dataset.theme = t === 'kestryl' ? 'kestryl' : light ? 'light' : 'dark';
}

function render(p) {
  if (p && p.theme) applyTheme(p.theme);
  if (!p || !p.alert) return;
  const a = (cur = p.alert);
  $('#t').className = 't s' + a.sev;
  // Camera / microphone notices from apps you use for calls: not a risk rating.
  const notice = a.rule === 'cam_mic_use';
  $('#sev').textContent = notice ? (a.key.includes('|microphone') ? 'Microphone on' : 'Camera on') : a.rule === 'update' ? 'Update' : SEV[a.sev] || 'Alert';
  $('#more').textContent = p.more ? `+${p.more} more` : 'Kestryl';
  $('#title').textContent = a.title;
  const dest = a.domain || a.ip;
  $('#meta').textContent = `${a.name}${dest ? ' → ' + dest + (a.port ? ':' + a.port : '') : ''}${a.bytes_out ? ' · ' + fmtB(a.bytes_out) : ''}`;
  $('#actions').innerHTML = `${a.exe && !notice ? '<button class="btn dangerf" id="block">Block app</button>' : ''}<button class="btn" id="details">Details</button>`;
  if (a.exe) $('#block').onclick = block;
  $('#details').onclick = details;
  arm();
}

async function block() {
  const b = $('#block');
  b.disabled = true;
  let msg;
  try {
    msg = await invoke('toast_action', { id: cur.id, action: 'block' });
  } catch (e) {
    msg = String(e);
  }
  $('#actions').innerHTML = `<span class="msg"></span>`;
  $('#actions .msg').textContent = msg;
  arm(6000);
}

async function details() {
  await invoke('toast_action', { id: cur.id, action: 'details' });
  win.hide();
}

$('#x').onclick = () => win.hide();
document.body.onmouseenter = () => (hover = true);
document.body.onmouseleave = () => (hover = false);
window.__TAURI__.event.listen('toast', e => render(e.payload));
window.__TAURI__.event.listen('theme', e => applyTheme(e.payload));
invoke('toast_current').then(render);
