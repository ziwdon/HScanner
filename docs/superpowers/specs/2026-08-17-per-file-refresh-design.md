# Per-file scan progress survives page refresh — design

Status: design. Small backend endpoint + frontend reconnect.

## Motivation

When a file is being uploaded and scanned (per-file scan), refreshing
the page loses the progress card. The backend's `FileScanManager`
still has the running job, but the frontend has no way to discover it
after a refresh.

The batch path already solves this: `GET /reports/{id}/scan-unverified/
active` returns the active batch job, and `reconnectActiveBatch()` on
page load reconnects to its SSE stream. The per-file path has no
equivalent.

## Fix

1. **Backend**: add `active_jobs_for_report(report_id)` to
   `FileScanManager` — returns all non-terminal `FileScanJob`s for the
   given report.
2. **Backend**: add `GET /reports/{id}/files/scan/active` endpoint —
   returns `{active: true, jobs: [{job_id, index, state}]}` for each
   active per-file scan job.
3. **Frontend**: add `reconnectPerFileScans()` — called on page load,
   calls the endpoint, and for each active job, opens an SSE stream to
   `/reports/{id}/files/{index}/scan/events` (the existing endpoint),
   wiring the same `scanFile` callback that handles `done`/`error`.

The frontend per-file queue (files clicked but not yet POSTed) is lost
on refresh — those are frontend-only state. The currently-running
backend job survives and is reconnected. After it completes, the user
can re-click remaining files.

## Acceptance

1. During a per-file scan, refreshing the page shows the progress card
   with the current file's state.
2. When the reconnected scan completes, the file card updates and
   summary tiles update (same as without refresh).
3. `pytest` passes, `ruff check .` clean.