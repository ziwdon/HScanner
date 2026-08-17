# Frontend per-file scan queue — design

Status: design. Frontend-only fix; no backend API or schema changes.

## Motivation

When the user clicks "Scan this file" on several files in rapid
succession:

- Each click immediately POSTs to `/reports/{id}/files/{index}/scan`.
- The first POST returns 202 and starts the scan; subsequent POSTs
  return **409** ("a scan is already in progress") because
  `FileScanManager.enqueue` raises `JobBusy` when a scan is already
  running (the manager serializes via an `asyncio.Lock`).
- The progress card at the top of the list is overwritten by each
  click (`setUploadProgress(0, 1, …)`), so it always shows a queue of
  1. The first file's progress is lost when the second click
  overwrites the card.
- The 409-rejected clicks re-enable their buttons but the user sees
  no indication that the files were not queued.
- The page-top summary tiles do not update for 409-rejected scans
  (Task 2 fixed the `done` path, but 409-rejected scans never reach
  `done`).

From the user's perspective: "the scan progress card always shows a
queue of 1" and "only the last clicked file gets scanned" (actually
the first, but the progress card shows the last clicked file's name
before the 409 rejection).

## Goals

- Clicking "Scan this file" on multiple files queues them all. The
  progress card shows the queue position (e.g. "Processing 1 of 3 ·
  tool.sh · uploading…").
- Files are processed sequentially (one at a time), matching the
  backend's existing serialization. No parallel scans.
- When one file completes, the next file in the queue is POSTed
  automatically.
- The progress card shows the overall queue progress (done / total)
  and the current file's state.
- The page-top summary tiles update after each file completes (already
  wired by Task 2; the queue ensures every clicked file eventually
  reaches `done`).
- The per-file button is disabled while the file is queued or
  scanning; it re-enables only if the scan fails.
- The user can cancel the queue (the existing cancel button clears
  remaining queued files and lets the current file finish).

## Non-goals

- Backend API changes. The `/reports/{id}/files/{index}/scan`
  endpoint and the `FileScanManager` serialization are unchanged.
- Parallel scanning. The backend serializes; the frontend queue
  respects that.
- Changing the batch (`scan-unverified`) path. That path already has
  its own queue and progress display.
- Persisting the queue across page refreshes (that is Task 5's scope).

## Design

### Frontend queue state

New module-level state in `report.html`'s inline JS:

```js
let perFileQueue = [];       // array of {index, button, statusEl, path}
let perFileQueueRunning = false;
```

### Click handler change

The `.btn-scan` click handler currently calls `scanFile` directly. It
will instead push the file onto `perFileQueue` and call
`drainPerFileQueue()`:

```js
document.addEventListener('click', (event) => {
  const button = event.target.closest('.btn-scan');
  if (!button) return;
  const index = button.dataset.index;
  // Prevent double-queuing the same file.
  if (perFileQueue.some((item) => item.index === index)) return;
  const path = filePath(index) || `file ${index}`;
  const statusEl = document.querySelector(`.scan-status[data-index="${index}"]`);
  button.disabled = true;
  if (statusEl) statusEl.textContent = 'queued…';
  perFileQueue.push({index, button, statusEl, path});
  drainPerFileQueue();
});
```

### Queue drain

`drainPerFileQueue` processes one file at a time. When the current
file finishes (`done` or `error`), it processes the next:

```js
function drainPerFileQueue() {
  if (perFileQueueRunning) return;
  const item = perFileQueue.shift();
  if (!item) return;
  perFileQueueRunning = true;
  const total = perFileQueue.length + 1; // remaining + current
  const done = perFileQueueTotalStarted - perFileQueue.length - 1; // see below
  runQueuedScan(item, done, total);
}
```

Actually, simpler: track `perFileQueueDone` and
`perFileQueueTotal` as counters that are set when the queue starts
draining:

```js
let perFileQueueDone = 0;
let perFileQueueTotal = 0;

function drainPerFileQueue() {
  if (perFileQueueRunning) return;
  if (perFileQueue.length === 0) {
    perFileQueueRunning = false;
    perFileQueueDone = 0;
    perFileQueueTotal = 0;
    // Hide the progress card after a short delay so the user sees "completed".
    return;
  }
  const item = perFileQueue.shift();
  perFileQueueRunning = true;
  if (perFileQueueTotal === 0) {
    perFileQueueTotal = perFileQueue.length + 1; // remaining + current
    perFileQueueDone = 0;
  }
  runQueuedScan(item);
}

function runQueuedScan(item) {
  const {index, button, statusEl, path} = item;
  setUploadProgress(
    perFileQueueDone,
    perFileQueueTotal,
    `${path} · queued`,
    `Per-file upload queue (${perFileQueueDone + 1} of ${perFileQueueTotal})`,
  );
  scanFile(index, statusEl, {
    onState: (state) => setUploadProgress(
      perFileQueueDone,
      perFileQueueTotal,
      `${path} · ${state}`,
      `Per-file upload queue (${perFileQueueDone + 1} of ${perFileQueueTotal})`,
    ),
    onError: (reason) => setUploadProgress(
      perFileQueueDone,
      perFileQueueTotal,
      `${path} · ${reason}`,
      `Per-file upload queue (${perFileQueueDone + 1} of ${perFileQueueTotal})`,
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
      button.disabled = false; // re-enable so the user can retry
    }
    perFileQueueRunning = false;
    // If queue is done, show a final "queue complete" message.
    if (perFileQueueDone >= perFileQueueTotal) {
      setUploadProgress(
        perFileQueueDone,
        perFileQueueTotal,
        'Queue complete.',
        'Per-file upload queue',
      );
      perFileQueueDone = 0;
      perFileQueueTotal = 0;
    } else {
      drainPerFileQueue(); // process next
    }
  });
}
```

### Cancel button

The existing `cancelUpload` button is wired to the batch path only
(`activeBatchJobId`). For the per-file queue, the cancel button will
also clear `perFileQueue` (remaining files are dequeued; the current
file finishes). Add to the `cancelUpload` click handler:

```js
if (perFileQueue.length > 0 || perFileQueueRunning) {
  perFileQueue = [];
  // The current file finishes; when it does, drain finds an empty queue.
  setUploadProgress(
    perFileQueueDone,
    perFileQueueTotal,
    'Cancelling after current file finishes…',
    'Per-file upload queue',
  );
  return;
}
```

### Progress card title

The progress card title changes from "Single file upload" to
"Per-file upload queue (N of M)" when more than one file is queued.
For a single-file click (the common case), it shows "Per-file upload
queue (1 of 1)" — clear and consistent.

### Button re-enable logic

- While queued: button stays disabled (set in the click handler).
- While scanning: button stays disabled.
- On `done`: button stays disabled (the file is now scanned; the card
  shows "No detections" / "Infected" / etc. with no scan button).
- On `error`: button re-enables so the user can retry.

This matches the existing single-file behavior — the only change is
that the button is disabled *while queued* in addition to *while
scanning*.

## Acceptance criteria

1. Clicking "Scan this file" on three files in rapid succession queues
   all three. The progress card shows "Per-file upload queue (1 of
   3)" and processes them one at a time.
2. As each file completes, the progress card advances ("2 of 3", "3
   of 3") and the page-top summary tiles update (Scanned increments,
   Needs attention decrements).
3. No 409 errors are produced because the frontend does not POST the
   next file until the previous one completes.
4. Clicking "Scan this file" on a file that is already queued is a
   no-op (the file is not double-queued).
5. Clicking Cancel clears the remaining queue; the current file
   finishes; the progress card shows "Cancelling after current file
   finishes…" then hides or shows "Queue complete."
6. A single-file scan (the common case) shows "Per-file upload queue
   (1 of 1)" — clear and consistent.

## Testing

No JS test harness exists. The fix is verified by:

- **Manual smoke test** (documented in the plan): click "Scan this
  file" on 3 files in rapid succession; confirm the queue processes
  all three with live progress and tile updates.
- **Existing backend tests** still pass (no backend changes).
- **No new automated tests** — the fix is pure JS behavior with no
  backend contract change.

## Open questions

None — design is complete for task 3.