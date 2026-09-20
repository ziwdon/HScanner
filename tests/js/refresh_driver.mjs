// Drives the real report page (report.html inline JS) in jsdom against a live
// HScanner server, then simulates a browser refresh: page 1 clicks "Scan this
// file" on the first CLICKS eligible files and is closed after PAGE1_MS; page 2
// loads the same report URL and is observed until "Queue complete." (or timeout).
// Prints one JSON line per observation with the card, buttons, and statuses.
//
// Env: BASE (http://127.0.0.1:PORT), REPORT_ID, CLICKS, PAGE1_MS, TIMEOUT_MS.
// Used by tests/test_report_page_queue_js.py — not a standalone tool.
import {JSDOM} from 'jsdom';
import {EventSource as NodeEventSource} from 'eventsource';

const BASE = process.env.BASE;
const REPORT_ID = process.env.REPORT_ID;
const CLICKS = parseInt(process.env.CLICKS || '4', 10);
const PAGE1_MS = parseInt(process.env.PAGE1_MS || '1000', 10);
const TIMEOUT_MS = parseInt(process.env.TIMEOUT_MS || '30000', 10);
const abs = (u) => (String(u).startsWith('http') ? String(u) : BASE + String(u));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const t0 = Date.now();

async function loadPage() {
  const html = await (await fetch(`${BASE}/reports/${REPORT_ID}`)).text();
  const dom = new JSDOM(html, {
    url: `${BASE}/reports/${REPORT_ID}`,
    runScripts: 'outside-only',
    pretendToBeVisual: true,
  });
  const {window} = dom;
  const sources = new Set();
  // jsdom gaps: no CSS.escape, no EventSource, fetch has no origin to resolve against.
  window.CSS = {escape: (s) => String(s).replace(/[^a-zA-Z0-9_-]/g, (c) => '\\' + c)};
  window.fetch = (u, o) => fetch(abs(u), o);
  window.EventSource = class extends NodeEventSource {
    constructor(u, o) { super(abs(u), o); sources.add(this); }
  };
  for (const script of window.document.querySelectorAll('script:not([src])')) {
    window.eval(script.textContent);
  }
  // "Closing the tab": drop every SSE connection and tear the DOM down.
  const close = () => { for (const es of sources) es.close(); window.close(); };
  return {window, doc: window.document, close};
}

function snapshot(doc, page, label, print = true) {
  const buttons = {};
  const statuses = {};
  for (let i = 0; i < CLICKS; i++) {
    const button = doc.querySelector(`.btn-scan[data-index="${i}"]`);
    buttons[i] = button ? (button.disabled ? 'disabled' : 'enabled') : 'gone';
    const status = doc.querySelector(`.scan-status[data-index="${i}"]`);
    statuses[i] = status ? status.textContent : null;
  }
  const rec = {
    t: Date.now() - t0,
    page,
    label,
    hidden: doc.getElementById('upload-progress').hidden,
    title: doc.getElementById('upload-progress-title').textContent,
    count: doc.getElementById('upload-progress-count').textContent,
    detail: doc.getElementById('upload-progress-detail').textContent,
    buttons,
    statuses,
  };
  if (print) console.log(JSON.stringify(rec));
  return rec;
}

// Page 1: queue CLICKS files, then "close the tab".
const page1 = await loadPage();
await sleep(300);  // let reconnectPerFileScans() resolve first
const buttons = [...page1.doc.querySelectorAll('.btn-scan')].slice(0, CLICKS);
for (const button of buttons) {
  button.dispatchEvent(new page1.window.MouseEvent('click', {bubbles: true}));
  await sleep(30);
}
await sleep(PAGE1_MS);
snapshot(page1.doc, 1, 'before-refresh');
page1.close();

// Page 2: reload and watch until the queue drains.
const page2 = await loadPage();
await sleep(300);
snapshot(page2.doc, 2, 'after-refresh');
let last = '';
const deadline = Date.now() + TIMEOUT_MS;
while (Date.now() < deadline) {
  await sleep(100);
  const rec = snapshot(page2.doc, 2, 'poll', false);
  const key = JSON.stringify([rec.title, rec.count, rec.detail, rec.buttons, rec.statuses]);
  if (key !== last) { console.log(JSON.stringify(rec)); last = key; }
  if (rec.detail === 'Queue complete.') break;
}
await sleep(300);
snapshot(page2.doc, 2, 'final');
page2.close();
process.exit(0);
