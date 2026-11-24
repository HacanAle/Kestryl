// Runs in <head> before anything is drawn: the last theme the app showed (app.js/toast.js save
// it), else Windows' light/dark mode, so the window never flashes the wrong colours.
'use strict';
(() => {
  let t = null;
  try { t = localStorage.getItem('kestryl-theme'); } catch (e) { /* storage blocked */ }
  if (!['dark', 'light', 'kestryl'].includes(t)) t = matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  document.documentElement.dataset.theme = t;
})();
