'use strict';
// Opening animation (#splash in index.html, styles at the end of app.css). Plays once per start, the
// first time the window is actually on screen. A start at login (--hidden) keeps it waiting until the
// window is opened from the tray: WebView2 reports a hidden window's page as "visible", so the window
// itself is asked, and opening it (show_main: show + focus) starts the animation. A click skips it;
// the element is removed when it has faded out.
(() => {
  const el = document.getElementById('splash');
  if (!el) return;
  const remove = () => el.remove();
  const play = () => {
    if (el.classList.contains('go')) return;
    el.classList.add('go');
    el.addEventListener('animationend', e => { if (e.target === el) remove(); });
    el.addEventListener('click', () => el.classList.add('skip'));
    setTimeout(remove, 4000);
  };
  const win = window.__TAURI__ && window.__TAURI__.window.getCurrentWindow();
  if (!win) return play();
  win.isVisible().then(shown => {
    if (shown) return play();
    addEventListener('focus', play, { once: true });
    win.onFocusChanged(e => { if (e.payload) play(); }).catch(() => {});
  }).catch(play);
})();
