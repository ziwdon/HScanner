// Drives the real report page (report.html inline JS) in jsdom against a live
// HScanner server and prints JSON snapshots of the Needs-attention section's
// groups, pills and chips: `initial`, then `after-pill` (if PILL is set), then
// `after-scan` (if SCAN_SELECTOR is set) once the per-file queue completes.
//
// Env: BASE (http://127.0.0.1:PORT), REPORT_ID, PILL (filter key to press, '' = none),
// SCAN_SELECTOR (CSS selector of the "Scan this file" button to click, '' = none),
// PRE_WAIT_MS. Used by tests/test_issue14_needs_attention_live_updates.py.
import {JSDOM} from 'jsdom';
import {EventSource as NodeEventSource} from 'eventsource';

const BASE = process.env.BASE;
const REPORT_ID = process.env.REPORT_ID;
const PILL = process.env.PILL || '';
const SCAN_SELECTOR = process.env.SCAN_SELECTOR || '';
const PRE_WAIT_MS = parseInt(process.env.PRE_WAIT_MS || '400', 10);
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
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const click = (el) => el.dispatchEvent(new window.MouseEvent('click', {bubbles: true}));
const count = (el) => el.querySelector(':scope > .group-head .count')?.textContent ?? null;
const emit = (label) => {
  const section = doc.getElementById('needs-attention');
  const rec = {label, section: null};
  if (section) {
    rec.section = {
      hidden: section.hidden,
      count: section.querySelector(':scope > .section-head .count')?.textContent ?? null,
      pressed: section.querySelector('.filter-pill[aria-pressed="true"]')?.dataset.filter ?? null,
      chips: Object.fromEntries([...section.querySelectorAll('.risk-chip')].map(
        (c) => [c.dataset.filter, c.querySelector('b').textContent])),
      groups: [...section.querySelectorAll(':scope > details.group')].map((g) => ({
        key: g.dataset.group,
        hidden: g.hidden,
        open: g.open,
        count: count(g),
        subgroups: [...g.querySelectorAll(':scope > details.group.subgroup')].map((s) => ({
          key: s.dataset.subgroup,
          hidden: s.hidden,
          count: count(s),
          cards: s.querySelectorAll('details.file').length,
          note: s.querySelector(':scope > .note')?.textContent.trim() ?? null,
        })),
      })),
    };
  }
  console.log(JSON.stringify(rec));
};

await sleep(PRE_WAIT_MS);
emit('initial');
if (PILL) {
  click(doc.querySelector(`.filter-pill[data-filter="${PILL}"]`));
  emit('after-pill');
}
if (SCAN_SELECTOR) {
  click(doc.querySelector(SCAN_SELECTOR));
  const deadline = Date.now() + TIMEOUT_MS;
  while (Date.now() < deadline) {
    await sleep(100);
    if (doc.getElementById('upload-progress-detail').textContent === 'Queue complete.') break;
  }
  emit('after-scan');
}
process.exit(0);
