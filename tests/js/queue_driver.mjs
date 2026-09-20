// Drives the real report page (report.html inline JS) in jsdom against a live
// HScanner server. Clicks "Scan this file" on the first CLICKS eligible files,
// GAP_MS apart, and prints one JSON line per progress-card change.
//
// Env: BASE (http://127.0.0.1:PORT), REPORT_ID, CLICKS, GAP_MS, PRE_WAIT_MS, START,
// CANCEL_AFTER_MS (click "Cancel" that long after the last click; 0 = never).
// Used by tests/test_report_page_queue_js.py — not a standalone tool.
import {JSDOM} from 'jsdom';
import {EventSource as NodeEventSource} from 'eventsource';

const BASE = process.env.BASE;
const REPORT_ID = process.env.REPORT_ID;
const CLICKS = parseInt(process.env.CLICKS || '3', 10);
const GAP_MS = parseInt(process.env.GAP_MS || '200', 10);
const PRE_WAIT_MS = parseInt(process.env.PRE_WAIT_MS || '0', 10);
const START = parseInt(process.env.START || '0', 10);  // skip the first START buttons
const CANCEL_AFTER_MS = parseInt(process.env.CANCEL_AFTER_MS || '0', 10);  // 0 = never
const TIMEOUT_MS = parseInt(process.env.TIMEOUT_MS || '30000', 10);
const abs = (u) => (String(u).startsWith('http') ? String(u) : BASE + String(u));

const html = await (await fetch(`${BASE}/reports/${REPORT_ID}`)).text();
const dom = new JSDOM(html, {
  url: `${BASE}/reports/${REPORT_ID}`,
  runScripts: 'outside-only',
  pretendToBeVisual: true,
});
const {window} = dom;
// jsdom gaps: no CSS.escape, no EventSource, fetch has no origin to resolve against.
window.CSS = {escape: (s) => String(s).replace(/[^a-zA-Z0-9_-]/g, (c) => '\\' + c)};
window.fetch = (u, o) => fetch(abs(u), o);
window.EventSource = class extends NodeEventSource {
  constructor(u, o) { super(abs(u), o); }
};
for (const script of window.document.querySelectorAll('script:not([src])')) {
  window.eval(script.textContent);
}

const doc = window.document;
const t0 = Date.now();
const emit = (label) => {
  const rec = {
    t: Date.now() - t0,
    label,
    hidden: doc.getElementById('upload-progress').hidden,
    title: doc.getElementById('upload-progress-title').textContent,
    count: doc.getElementById('upload-progress-count').textContent,
    bar: doc.getElementById('upload-progress-bar').style.width || '0%',
    detail: doc.getElementById('upload-progress-detail').textContent,
  };
  console.log(JSON.stringify(rec));
  return rec;
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

await sleep(PRE_WAIT_MS);
const buttons = [...doc.querySelectorAll('.btn-scan')].slice(START, START + CLICKS);
emit('before');
for (let i = 0; i < buttons.length; i++) {
  buttons[i].dispatchEvent(new window.MouseEvent('click', {bubbles: true}));
  await sleep(30);
  emit(`click:${i}`);
  await sleep(GAP_MS);
}
if (CANCEL_AFTER_MS > 0) {
  await sleep(CANCEL_AFTER_MS);
  doc.getElementById('cancel-upload').dispatchEvent(new window.MouseEvent('click', {bubbles: true}));
  await sleep(30);
  emit('cancel');
}
let last = '';
const deadline = Date.now() + TIMEOUT_MS;
while (Date.now() < deadline) {
  await sleep(100);
  const rec = {
    title: doc.getElementById('upload-progress-title').textContent,
    count: doc.getElementById('upload-progress-count').textContent,
    detail: doc.getElementById('upload-progress-detail').textContent,
  };
  const key = JSON.stringify(rec);
  if (key !== last) { emit('poll'); last = key; }
  if (rec.detail === 'Queue complete.') break;
}
emit('final');
process.exit(0);
