# Live count updates after per-file and batch scans Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** After a per-file scan completes, the report page updates the old/new group, subgroup, risk-chip, and summary-tile counts live. The same live updates apply during batch progress (the final reload stays as a backstop).

**Architecture:** Backend adds a `summary` field to the single-file terminal SSE payload (one line in `_file_terminal_payload`, using the existing `_summary_payload` helper). Frontend gains a new `updateGroupCounts(section)` JS helper that recomputes every group/subgroup/risk-chip count from the live DOM, and `applyFileUpdate` calls it for both the previous and destination sections. The single-file `scanFile` JS calls `updateSummaryTiles(data.summary)` on the terminal `done` event, matching the batch path's existing behavior.

**Tech Stack:** Python 3.11+, FastAPI, Jinja2 templates with inline JS, pytest + pytest-asyncio, Ruff. No JS test harness exists.

## Global Constraints

- venv at `.venv` is canonical — install with `.venv/bin/python -m pip` only (per `CLAUDE.md` Pop!_OS note).
- Test command: `pytest` (with the venv active). Lint: `ruff check .` (run as `.venv/bin/ruff check .`).
- No JS unit-test harness exists. New JS behavior is verified by (a) a backend test asserting the new `summary` field in the single-file terminal payload, and (b) a manual smoke step documented in the plan.
- No backend schema changes. The `summary` field is added to an SSE event payload, not to the persisted report schema.
- No reclassification of existing behavior. The batch path's final `location.reload()` stays as a consistency backstop.
- Security invariants from `CLAUDE.md` are non-negotiable: the summary payload carries only counts, no secrets, no API keys.

---

## File Structure

Files touched by this plan:

- **Modify** `src/hscanner/web/routes.py:528-546` — `_file_terminal_payload` adds `"summary": _summary_payload(report)` to the `done` payload.
- **Modify** `src/hscanner/web/templates/report.html:269-330` — `applyFileUpdate` calls `updateGroupCounts` for previous and destination sections; new `updateGroupCounts` helper.
- **Modify** `src/hscanner/web/templates/report.html:412-453` — `scanFile` calls `updateSummaryTiles(data.summary)` on the terminal `done` event.
- **Modify** `tests/test_web_file_scan.py` — extend the single-file terminal-payload test to assert `summary` is present and has the expected keys.
- **Modify** `src/hscanner/web/templates/base.html:7` — bump CSS cache-buster from `v=11` to `v=12` (the `report.html` JS change is behavior-only, but the template file is served fresh on reload; bumping is harmless and follows the project convention).

---

## Task 1: Backend — add `summary` to the single-file terminal SSE payload

**Files:**
- Modify: `src/hscanner/web/routes.py:528-546`
- Test: `tests/test_web_file_scan.py` (extend an existing test)

**Interfaces:**
- Produces: the single-file terminal SSE `done` event payload includes a `summary` dict with keys `inventoried`, `scanned`, `infected`, `needs_attention`, `uploaded`, `skipped`, `errors` (the same shape `_summary_payload` already returns for the batch path).

- [ ] **Step 1: Write the failing test**

Open `tests/test_web_file_scan.py`. Find the test that asserts the terminal `done` payload shape for a single-file scan (search for `terminal["state"] == "done"` in the single-file path). Add an assertion that `terminal["summary"]` is present and has the expected keys. If no existing test directly asserts the terminal payload's full shape, add a focused new test:

```python
def test_single_file_terminal_payload_includes_summary(tmp_path, monkeypatch):
    """The single-file terminal SSE `done` event includes a `summary` dict
    matching the batch path's shape, so the frontend can update the
    page-top summary tiles without a reload."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.delenv("HS_API_KEY_VIRUSTOTAL", raising=False)

    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "tool.sh").write_text("#!/bin/sh\necho hello\n")

    engine = _FoundClient()
    app, client = _make_app_and_client(vt_factory=lambda engine_id, key: engine)
    report = _seed_report(app, scan_dir)
    idx = _idx(report, "tool.sh")

    resp = client.post(f"/reports/{report.report_id}/files/{idx}/scan")
    assert resp.status_code == 202, resp.text
    with client.stream("GET", f"/reports/{report.report_id}/files/{idx}/scan/events") as s:
        events = _parse_sse("".join(s.iter_text()))

    terminal = events[-1]
    assert terminal["state"] == "done", events
    assert "summary" in terminal, terminal
    summary = terminal["summary"]
    for key in ("inventoried", "scanned", "infected", "needs_attention",
                "uploaded", "skipped", "errors"):
        assert key in summary, (key, summary)
    # The single file was resolved to no_detections, so scanned >= 1
    # and needs_attention should drop relative to the seeded report.
    assert summary["scanned"] >= 1, summary
    assert summary["inventoried"] >= 1, summary
```

Note: `_FoundClient`, `_make_app_and_client`, `_seed_report`, `_idx`, and `_parse_sse` are existing helpers in `tests/test_web_file_scan.py` — reuse them. Check the file for their exact signatures before writing the test.

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_web_file_scan.py::test_single_file_terminal_payload_includes_summary -v`
Expected: FAIL with `AssertionError: 'summary' not in terminal` (or similar).

- [ ] **Step 3: Add `summary` to `_file_terminal_payload`**

Open `src/hscanner/web/routes.py`. Find `_file_terminal_payload` (around line 528). It currently returns a dict ending with `**_live_file_payload(f)`. Add the summary field to the `done` return value:

```python
def _file_terminal_payload(request: Request, report_id: str, index: int, job) -> dict:
    """Build the terminal SSE payload for a file scan job."""
    if job.state == "error":
        return {"state": "error", "error": job.error or "Internal error"}
    report = request.app.state.report_registry.get(report_id)
    f = report.files[index] if report and 0 <= index < len(report.files) else None
    if f is None:
        return {"state": "done"}
    return {
        "state": "done",
        "outcome": f.outcome,
        "outcome_reason": f.outcome_reason,
        "lookup_status": f.lookup_status,
        "upload_status": f.upload_status,
        "flagged": f.detection_ratio.flagged,
        "total_engines": f.detection_ratio.total,
        "permalink": f.permalink,
        "summary": _summary_payload(report),
        **_live_file_payload(f),
    }
```

`_summary_payload` is already defined in the same module (line 846) and already handles `report is None` by returning `{}`. The `report` variable here is guaranteed non-None when `f` is not None (they come from the same lookup), but `_summary_payload`'s guard makes the call safe regardless.

- [ ] **Step 4: Run the test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_web_file_scan.py::test_single_file_terminal_payload_includes_summary -v`
Expected: PASS.

- [ ] **Step 5: Run the full test suite to check for fallout**

Run: `.venv/bin/python -m pytest`
Expected: all existing tests still PASS (the new field is additive; no existing test asserts the absence of `summary`).

- [ ] **Step 6: Lint**

Run: `.venv/bin/ruff check .`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add src/hscanner/web/routes.py tests/test_web_file_scan.py
git commit -m "Routes: add summary to single-file terminal SSE payload

_file_terminal_payload now includes a summary dict (same shape as the
batch path's _summary_payload) so the frontend can update the page-top
summary tiles live after a per-file scan without a reload."
```

---

## Task 2: Frontend — `updateGroupCounts` helper + integration into `applyFileUpdate`

**Files:**
- Modify: `src/hscanner/web/templates/report.html:206-330`

**Interfaces:**
- Produces: `updateGroupCounts(section)` JS function — recomputes group, subgroup, and risk-chip counts from the live DOM; hides empty groups/subgroups.
- Produces: `applyFileUpdate(data)` calls `updateGroupCounts(previousSection)` and `updateGroupCounts(destination)` after the file card is placed and `updateSectionCount` has run.

- [ ] **Step 1: Add the `updateGroupCounts` helper**

Open `src/hscanner/web/templates/report.html`. Find `updateSectionCount` (around line 208). Immediately after its closing brace (before `ensureSection`), add:

```js
function updateGroupCounts(section) {
  if (!section) return;
  section.querySelectorAll(':scope > details.group').forEach((group) => {
    const groupFiles = group.querySelectorAll('details.file').length;
    const groupCount = group.querySelector(':scope > .group-head .count');
    if (groupCount) groupCount.textContent = groupFiles;
    group.querySelectorAll(':scope > details.group.subgroup').forEach((subgroup) => {
      const subgroupFiles = subgroup.querySelectorAll('details.file').length;
      const subgroupCount = subgroup.querySelector(':scope > .group-head .count');
      if (subgroupCount) subgroupCount.textContent = subgroupFiles;
      subgroup.hidden = subgroupFiles === 0;
    });
    group.hidden = groupFiles === 0;
  });
  section.querySelectorAll('.risk-chip').forEach((chip) => {
    const key = chip.dataset.filter;
    const group = section.querySelector(`:scope > details.group[data-group="${CSS.escape(key)}"]`);
    const count = group ? group.querySelectorAll('details.file').length : 0;
    const countEl = chip.querySelector('b');
    if (countEl) countEl.textContent = count;
  });
}
```

- [ ] **Step 2: Call `updateGroupCounts` from `applyFileUpdate`**

In the same file, find `applyFileUpdate` (around line 269). Its final lines currently read:

```js
  updateSectionCount(previousSection);
  updateSectionCount(destination);
  destination.hidden = false;
  const navLink = document.querySelector(`.report-nav a[href="#${destination.id}"]`);
  if (navLink) navLink.hidden = false;
}
```

Replace with:

```js
  updateSectionCount(previousSection);
  updateSectionCount(destination);
  updateGroupCounts(previousSection);
  updateGroupCounts(destination);
  destination.hidden = false;
  const navLink = document.querySelector(`.report-nav a[href="#${destination.id}"]`);
  if (navLink) navLink.hidden = false;
}
```

- [ ] **Step 3: Bump the CSS cache-buster**

Open `src/hscanner/web/templates/base.html`. Change `app.css?v=11` to `app.css?v=12` (line 7).

- [ ] **Step 4: Update the cache-buster test**

Open `tests/test_web.py`. Find the two assertions that check `app.css?v=11` (lines ~183 and ~592). Update both to `app.css?v=12`.

- [ ] **Step 5: Run the full test suite**

Run: `.venv/bin/python -m pytest`
Expected: all PASS. The JS change is not exercised by the Python tests, but the cache-buster test and the existing SSE contract tests must still pass.

- [ ] **Step 6: Lint**

Run: `.venv/bin/ruff check .`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add src/hscanner/web/templates/report.html src/hscanner/web/templates/base.html tests/test_web.py
git commit -m "Report template: live group/subgroup/chip counts after per-file scan

applyFileUpdate now calls a new updateGroupCounts helper that
recomputes every group, subgroup, and risk-chip count from the live
DOM after a file card moves. Empty groups/subgroups hide so the user
does not see stale '(0)' stubs that cannot be expanded. CSS
cache-buster bumped to v=12."
```

---

## Task 3: Frontend — `scanFile` calls `updateSummaryTiles` on the terminal `done` event

**Files:**
- Modify: `src/hscanner/web/templates/report.html:412-453`

**Interfaces:**
- Produces: the single-file `scanFile` JS calls `updateSummaryTiles(data.summary)` after `applyFileUpdate(data)` on the terminal `done` event, matching the batch path's `applyBatchEvent` behavior.

- [ ] **Step 1: Update `scanFile` to call `updateSummaryTiles`**

Open `src/hscanner/web/templates/report.html`. Find `scanFile` (around line 412). Its `es.onmessage` handler currently reads, in the `data.state === 'done'` branch:

```js
        if (data.state === 'done') {
          if (statusEl) statusEl.textContent = 'done - ' + (data.outcome || '').replace('_', ' ');
          applyFileUpdate(data);
          es.close(); resolve('done');
        }
```

Replace with:

```js
        if (data.state === 'done') {
          if (statusEl) statusEl.textContent = 'done - ' + (data.outcome || '').replace('_', ' ');
          applyFileUpdate(data);
          updateSummaryTiles(data.summary);
          es.close(); resolve('done');
        }
```

- [ ] **Step 2: Run the full test suite**

Run: `.venv/bin/python -m pytest`
Expected: all PASS (no JS execution; the Python tests verify the SSE payload contract which already includes `summary` from Task 1).

- [ ] **Step 3: Lint**

Run: `.venv/bin/ruff check .`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add src/hscanner/web/templates/report.html
git commit -m "Report template: scanFile updates summary tiles on done

The single-file scan path now calls updateSummaryTiles(data.summary)
on the terminal done event, matching the batch path. Combined with
the summary field added to the single-file terminal payload, the
page-top Inventoried/Scanned/Infected/Needs attention/Uploaded/
Skipped/Errors tiles update live after a per-file scan without a
reload."
```

---

## Task 4: Manual smoke verification

No automated JS tests exist. This task documents the manual smoke steps that verify the fix end-to-end. It produces no code and no commit; it is a verification gate before the task is declared complete.

- [ ] **Step 1: Start the web app with a test key**

```bash
HS_API_KEY_VIRUSTOTAL=test-key .venv/bin/python -m uvicorn hscanner.web.app:create_app --factory --host 127.0.0.1 --port 8765
```

(Use a throwaway key; the app only needs the env var to enable online scans. If you do not want to hit the real VirusTotal API, inject a stub engine via the test factory instead — but that requires a code path not exposed in the run script. For manual smoke, a real key against a small test folder is acceptable.)

- [ ] **Step 2: Scan a folder with several `.py` files**

Open `http://127.0.0.1:8765` in a browser. Enter a folder path containing 3-4 `.py` files. Click Scan. Wait for the report to render.

Expected: the Needs-attention section shows a `Medium priority` group with a `.py` subgroup containing the files. The `Medium priority` risk chip shows the count. The page-top `Needs attention` tile shows the count.

- [ ] **Step 3: Click "Scan this file" on one `.py` file**

Click the per-file scan button on one of the `.py` file cards. Wait for the scan to complete.

Expected:
- The file's card moves to the No-detections (or Infected) section.
- The `.py` subgroup count in Needs-attention decrements by 1.
- The `Medium priority` group count decrements by 1.
- The `Medium priority` risk chip count decrements by 1.
- The page-top `Scanned` tile increments by 1.
- The page-top `Needs attention` tile decrements by 1.
- If the file was the last in the `.py` subgroup, the subgroup hides.
- If the file was the last in the `Medium priority` group, the group hides.

- [ ] **Step 4: Click "Scan this file" on the remaining `.py` files, one at a time**

Repeat step 3 for each remaining `.py` file. Confirm the counts update live after each scan. After the last `.py` file is scanned, the `Medium priority` group and its `.py` subgroup should be hidden, and the `Medium priority` risk chip should show `0`.

- [ ] **Step 5: Run a batch scan on a fresh folder with mixed tiers**

Scan a folder with a mix of `.sh` (HIGH), `.py` (MEDIUM), and `.json` (LOW_RISK, skipped by default). Click "Upload and scan all unverified". Watch the batch progress.

Expected: as each file completes, the group/subgroup/chip/section/nav counts update live. The summary tiles update live. The final reload at `state === 'done'` still fires as a backstop.

- [ ] **Step 6: Record the smoke result**

If all steps pass, the task is complete. If any step fails, file the specific failure as a follow-up and address it before moving to Task 3 (the next user-reported issue).

---

## Verification (whole-plan)

After Task 4:

- `pytest` passes (full suite, 557+ tests).
- `ruff check .` clean.
- `git diff --check` clean.
- Manual smoke confirms live count updates after per-file and batch scans.
- No backend schema changes; the `summary` field is additive to the SSE payload only.
- The batch path's final `location.reload()` remains as a consistency backstop.