# Frontend per-file scan queue Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Clicking "Scan this file" on multiple files queues them all in the frontend. The progress card shows "Processing N of M". Files are processed sequentially. No backend changes.

**Architecture:** New frontend JS state (`perFileQueue`, `perFileQueueRunning`, `perFileQueueDone`, `perFileQueueTotal`) in `report.html`. The `.btn-scan` click handler pushes onto the queue instead of calling `scanFile` directly. A `drainPerFileQueue` function processes one file at a time, calling `scanFile` and advancing on completion. The cancel button also clears the per-file queue.

**Tech Stack:** Python 3.11+, FastAPI, Jinja2 templates with inline JS, pytest, Ruff. No JS test harness.

## Global Constraints

- venv at `.venv` is canonical. Test: `pytest`. Lint: `.venv/bin/ruff check .`.
- No backend changes. The `/reports/{id}/files/{index}/scan` endpoint and `FileScanManager` are unchanged.
- No JS unit-test harness. New JS behavior is verified by manual smoke + existing backend tests.
- Security invariants from `CLAUDE.md` are non-negotiable.

---

## File Structure

- **Modify** `src/hscanner/web/templates/report.html:165-507` — new queue state, `drainPerFileQueue`, `runQueuedScan`, click handler change, cancel handler change, CSS cache-buster bump.
- **Modify** `src/hscanner/web/templates/base.html:7` — CSS cache-buster `v=12` → `v=13`.
- **Modify** `tests/test_web.py` — update cache-buster assertions `v=12` → `v=13`.

---

## Task 1: Frontend per-file scan queue

**Files:**
- Modify: `src/hscanner/web/templates/report.html:165-507`
- Modify: `src/hscanner/web/templates/base.html:7`
- Modify: `tests/test_web.py` (cache-buster assertions)

- [ ] **Step 1: Add queue state variables**

Open `src/hscanner/web/templates/report.html`. Find the block of `let` declarations near line 172 (after `let batchSource = null;`). Add:

```js
let perFileQueue = [];
let perFileQueueRunning = false;
let perFileQueueDone = 0;
let perFileQueueTotal = 0;
```

- [ ] **Step 2: Add `drainPerFileQueue` and `runQueuedScan` functions**

After the `scanFile` function's closing brace (around line 453), add:

```js
function drainPerFileQueue() {
  if (perFileQueueRunning) return;
  if (perFileQueue.length === 0) {
    if (perFileQueueTotal > 0) {
      setUploadProgress(
        perFileQueueDone,
        perFileQueueTotal,
        'Queue complete.',
        'Per-file upload queue',
      );
    }
    perFileQueueDone = 0;
    perFileQueueTotal = 0;
    return;
  }
  const item = perFileQueue.shift();
  perFileQueueRunning = true;
  if (perFileQueueTotal === 0) {
    perFileQueueTotal = perFileQueue.length + 1;
    perFileQueueDone = 0;
  }
  runQueuedScan(item);
}

function runQueuedScan(item) {
  const {index, button, statusEl, path} = item;
  const pos = perFileQueueDone + 1;
  setUploadProgress(
    perFileQueueDone,
    perFileQueueTotal,
    `${path} · queued`,
    `Per-file upload queue (${pos} of ${perFileQueueTotal})`,
  );
  scanFile(index, statusEl, {
    onState: (state) => setUploadProgress(
      perFileQueueDone,
      perFileQueueTotal,
      `${path} · ${state}`,
      `Per-file upload queue (${pos} of ${perFileQueueTotal})`,
    ),
    onError: (reason) => setUploadProgress(
      perFileQueueDone,
      perFileQueueTotal,
      `${path} · ${reason}`,
      `Per-file upload queue (${pos} of ${perFileQueueTotal})`,
    ),
  }).then((result) => {
    perFileQueueDone += 1;
    if (result === 'done') {
      setUploadProgress(
        perFileQueueDone,
        perFileQueueTotal,
        `${path} · completed`,
        `Per-file upload queue (${perFileQueueDone} of ${perFileQueueTotal})`,
      );
    } else {
      button.disabled = false;
    }
    perFileQueueRunning = false;
    drainPerFileQueue();
  });
}
```

- [ ] **Step 3: Replace the `.btn-scan` click handler**

Find the existing `.btn-scan` click handler (around line 489). Replace it entirely:

```js
document.addEventListener('click', (event) => {
  const button = event.target.closest('.btn-scan');
  if (!button) return;
  const index = button.dataset.index;
  if (perFileQueue.some((item) => item.index === index)) return;
  const path = filePath(index) || `file ${index}`;
  const statusEl = document.querySelector(`.scan-status[data-index="${index}"]`);
  button.disabled = true;
  if (statusEl) statusEl.textContent = 'queued…';
  perFileQueue.push({index, button, statusEl, path});
  drainPerFileQueue();
});
```

- [ ] **Step 4: Update the cancel handler to also clear the per-file queue**

Find the `cancelUpload.addEventListener('click', ...)` handler (around line 526). At the **top** of the handler body, before the `if (!activeBatchJobId)` check, add:

```js
  if (perFileQueue.length > 0 || perFileQueueRunning) {
    perFileQueue = [];
    setUploadProgress(
      perFileQueueDone,
      perFileQueueTotal,
      'Cancelling after current file finishes…',
      'Per-file upload queue',
    );
    return;
  }
```

- [ ] **Step 5: Bump CSS cache-buster**

Open `src/hscanner/web/templates/base.html`. Change `app.css?v=12` to `app.css?v=13`.

- [ ] **Step 6: Update cache-buster test assertions**

Open `tests/test_web.py`. Update the two assertions from `app.css?v=12` to `app.css?v=13` (around lines 183 and 592).

- [ ] **Step 7: Run the full test suite**

Run: `.venv/bin/python -m pytest`
Expected: all PASS (557+ tests; the JS change is not exercised by Python tests, but the cache-buster test must pass).

- [ ] **Step 8: Lint**

Run: `.venv/bin/ruff check .`
Expected: clean.

- [ ] **Step 9: Commit**

```bash
git add src/hscanner/web/templates/report.html src/hscanner/web/templates/base.html tests/test_web.py
git commit -m "Report template: frontend per-file scan queue

Clicking 'Scan this file' on multiple files now queues them in the
frontend instead of immediately POSTing each (which produced 409s).
The progress card shows 'Per-file upload queue (N of M)' and
processes files one at a time, matching the backend's existing
serialization. Cancel clears the remaining queue. CSS cache-buster
bumped to v=13."
```

---

## Task 2: Manual smoke verification

- [ ] **Step 1: Start the web app**

```bash
HS_API_KEY_VIRUSTOTAL=test-key .venv/bin/python -m uvicorn hscanner.web.app:create_app --factory --host 127.0.0.1 --port 8765
```

- [ ] **Step 2: Scan a folder with 3-4 priority files**

Open `http://127.0.0.1:8765`. Scan a folder with 3-4 `.sh` or `.py` files.

- [ ] **Step 3: Click "Scan this file" on 3 files in rapid succession**

Click the per-file scan button on three different files, one after another, within ~1 second.

Expected:
- All three buttons disable immediately.
- The progress card shows "Per-file upload queue (1 of 3) · file1.sh · queued".
- No 409 errors appear.
- Files process one at a time: card advances to "2 of 3", "3 of 3".
- Summary tiles update after each file completes.
- After all three complete, the card shows "Queue complete."

- [ ] **Step 4: Test cancel**

Queue 3 files. While the first is scanning, click Cancel.

Expected:
- The progress card shows "Cancelling after current file finishes…".
- The current file completes; the remaining two are dequeued.
- Their buttons re-enable.

- [ ] **Step 5: Test single-file scan (common case)**

Click "Scan this file" on a single file.

Expected: progress card shows "Per-file upload queue (1 of 1)" — clear and consistent.

---

## Verification (whole-plan)

After Task 2:

- `pytest` passes (557+ tests).
- `ruff check .` clean.
- `git diff --check` clean.
- Manual smoke confirms the queue processes all clicked files with live progress and tile updates.
- No backend changes; no 409 errors during sequential per-file scans.