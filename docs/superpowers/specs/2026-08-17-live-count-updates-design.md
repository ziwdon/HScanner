# Live count updates after per-file and batch scans — design

Status: design. Tight, focused fix to the report-page live-update DOM.
No backend changes; no schema changes; no spec dependencies beyond the
existing `_live_file_payload` contract.

## Motivation

After a per-file scan completes, the report page updates the file's card
(`applyFileUpdate` in `report.html`) but does NOT update the counts
displayed around it. The user observes:

- The file's old group and subgroup keep their stale counts (e.g. `.py (3)`
  after all three `.py` files have been scanned and moved out).
- Empty groups/subgroups stay visible with a stale non-zero count and
  cannot be expanded (because they contain zero file cards).
- The risk-distribution chips at the top of the Needs-attention section
  keep their stale counts (e.g. `Medium priority 3` even though all
  medium-tier files have now been resolved).
- The page-top summary tiles (Inventoried / Scanned / Infected / Needs
  attention / Uploaded / Skipped / Errors) do not update.

The batch path masks this with a `location.reload()` 500 ms after the
terminal `done` event, so the user only sees the issue during a
single-file scan. However the same `applyFileUpdate` runs during batch
events, so the live counts drift during the batch too — they just get
papered over at the end.

## Goals

- After a per-file scan completes (single-file path), the old and new
  group, subgroup, risk-chip, and summary-tile counts all update to
  reflect the file's new outcome. Empty groups/subgroups collapse out
  of view (hidden or removed, see Design).
- During a batch scan, the same live count updates apply per event so
  the user sees counts decrement/increment as the batch progresses —
  not only on the final reload. The final reload remains as a
  consistency backstop.
- The single-file `scanFile` path emits a summary payload so its tile
  update is wired the same way as the batch path.
- No backend changes; the existing `_live_file_payload` already
  serializes everything the JS needs.

## Non-goals

- Removing the batch path's final `location.reload()`. It remains as a
  consistency backstop after a long-running batch; the live counts are
  an enhancement, not a replacement.
- Changing the page's URL/anchor or scroll position.
- Re-rendering the entire report from a server-side HTML fragment. The
  fix is a client-side DOM update only, matching the existing
  `applyFileUpdate` pattern.
- Updating the engine-breakdown line or quota-stop banners (those are
  static report-head fields, not live counts).

## Design

### Counted elements

Each Needs-attention section has four count surfaces that must stay
consistent with the underlying `<details class="file">` cards after a
live update:

1. **Subgroup count**: the `<span class="count">N</span>` inside a
   `<details class="group subgroup" data-subgroup="…">` summary.
2. **Group count**: the `<span class="count">N</span>` inside a
   `<details class="group" data-group="…">` summary (the outer tier
   group: `high` / `medium` / `low_risk`).
3. **Risk-distribution chip count**: the `<b>N</b>` inside each
   `<button class="risk-chip" data-filter="…">` at the top of the
   Needs-attention section (one per tier group).
4. **Section count and nav count**: the existing `updateSectionCount`
   already handles these (section-head `<span class="count">` and the
   report-nav `<b>`). Unchanged.

In addition, the page-top **summary tiles** (Inventoried / Scanned /
Infected / Needs attention / Uploaded / Skipped / Errors) must update
on every live file update. The batch path already wires this via
`updateSummaryTiles(data.summary)`; the single-file path does not.

### New helper: `updateGroupCounts(section)`

A single function recomputes every group/subgroup/chip count in a
section from the live DOM. Called by `applyFileUpdate` after the file
card has been placed in its new group AND after the previous section is
known.

```js
function updateGroupCounts(section) {
  if (!section) return;
  // For each top-level group, recompute its count from its descendant
  // file cards (subgroups are nested <details>, so the outer group's
  // file count is the total across all subgroups).
  section.querySelectorAll(':scope > details.group').forEach((group) => {
    const groupFiles = group.querySelectorAll('details.file').length;
    const groupCount = group.querySelector(':scope > .group-head .count');
    if (groupCount) groupCount.textContent = groupFiles;
    // Recompute each subgroup's count from its own descendant cards.
    group.querySelectorAll(':scope > details.group.subgroup').forEach((subgroup) => {
      const subgroupFiles = subgroup.querySelectorAll('details.file').length;
      const subgroupCount = subgroup.querySelector(':scope > .group-head .count');
      if (subgroupCount) subgroupCount.textContent = subgroupFiles;
      // Hide empty subgroups so the user does not see "(0)" stubs that
      // cannot be expanded.
      subgroup.hidden = subgroupFiles === 0;
    });
    // Hide empty groups (and their now-hidden subgroups) so the section
    // collapses cleanly when the last file of a tier leaves.
    group.hidden = groupFiles === 0;
  });
  // Recompute each risk-chip's count from the corresponding group.
  section.querySelectorAll('.risk-chip').forEach((chip) => {
    const key = chip.dataset.filter;
    const group = section.querySelector(`:scope > details.group[data-group="${CSS.escape(key)}"]`);
    const count = group ? group.querySelectorAll('details.file').length : 0;
    const countEl = chip.querySelector('b');
    if (countEl) countEl.textContent = count;
  });
}
```

### Integration into `applyFileUpdate`

`applyFileUpdate` currently calls `updateSectionCount(previousSection)`
and `updateSectionCount(destination)`. It will additionally call
`updateGroupCounts(previousSection)` and `updateGroupCounts(destination)`
after those. `updateGroupCounts` runs AFTER the file card has been
placed in its new group, so the new group's count includes it and the
old group's count excludes it.

### Single-file summary payload

The single-file `scanFile` JS calls `applyFileUpdate(data)` on the
terminal `done` event, where `data` is the SSE payload built by
`_file_terminal_payload`. That payload does NOT currently include a
`summary` field, so `updateSummaryTiles` cannot run.

Two options:

- **(A) Add `summary` to the single-file terminal payload** — backend
  change in `_file_terminal_payload` to include
  `request.app.state.report_registry.get(report_id).summary` (already
  computed on the report). Minimal: one extra dict key, no schema
  change, no new endpoint.
- **(B) Compute summary deltas client-side** — fragile and duplicates
  the canonical summary logic.

**Decision: A.** The backend already has the summary; serializing it
on the terminal event is one line and matches the batch path's
contract (`applyBatchEvent` already calls `updateSummaryTiles(data.summary)`).

### `scanFile` JS calls `updateSummaryTiles`

After `applyFileUpdate(data)` on the `done` event, `scanFile` will
additionally call `updateSummaryTiles(data.summary)` if present. Same
guard pattern as `applyBatchEvent`.

### Batch path

`applyBatchEvent` already calls `applyFileUpdate(data)` and
`updateSummaryTiles(data.summary)`. The only change is that
`applyFileUpdate` now also calls `updateGroupCounts`, so batch events
get live group/subgroup/chip counts as they progress. The final
`location.reload()` at `state === 'done'` remains as a consistency
backstop.

### Empty group/subgroup visibility

Hiding empty groups and subgroups (`hidden = true` on the `<details>`
element) matches the existing pattern for empty sections
(`updateSectionCount` sets `section.hidden = total === 0`). It avoids
the "cannot expand it" symptom — the empty group disappears entirely
rather than lingering with a stale count. The risk-chip for that tier
still shows `0`, which is correct and informative.

### Filter-pill interaction

When a filter pill is active (e.g. "Medium" pressed), the JS currently
sets `g.hidden = !matches` on each group. After `updateGroupCounts`
runs and hides an empty group, a subsequent pill click must still be
able to show a non-empty group. The pill handler already sets
`g.hidden` based on the filter match, so it overrides the
`updateGroupCounts` hide for non-empty groups. Empty groups stay
hidden because the pill handler's `matches` check is AND-ed with the
group's existence — actually, the pill handler sets `g.hidden = !matches`
unconditionally, which would re-show an empty group if its pill is
active. This is acceptable because an empty group with its pill active
is the same as "no files in this tier" — the user sees the group
header with count 0, which is honest. If this proves visually noisy,
a follow-up can add `&& groupFiles > 0` to the pill handler's show
condition; out of scope for this fix.

## Acceptance criteria

1. After a single-file scan that resolves a Needs-attention file to
   No detections:
   - The file's card appears in the No-detections section.
   - The file's old Needs-attention subgroup count decrements (or the
     subgroup hides if it was the last file).
   - The file's old Needs-attention group count decrements (or the
     group hides if it was the last file in that tier).
   - The Needs-attention risk-chip for the old tier decrements (or
     shows 0).
   - The Needs-attention section-head count and nav count decrement.
   - The page-top Scanned tile increments; the Needs-attention tile
     decrements; the No-detections tile increments (if applicable).
2. After a single-file scan that leaves the file in Needs-attention
   (e.g. hash not found and upload not consented), the file's card
   stays in its group; counts do not change (the file did not leave
   the section). The card's content updates (new lookup status, new
   badges).
3. During a batch scan, the same live count updates apply per event.
   The final reload remains as a backstop.
4. Empty groups/subgroups hide after a live update; they do not linger
   with a stale count or an un-expandable state.
5. Existing tests for `applyFileUpdate`, `updateSectionCount`, and the
   batch SSE flow still pass. New tests cover the count-update
   behavior.

## Testing

This is a JS behavior change. The project has no JS test harness
(there is no jest/playwright/etc. configured). The existing
`tests/test_web_file_scan.py` covers the SSE payload contract and the
server-side `_live_file_payload`/`_file_terminal_payload` shapes;
it does NOT execute the JS. New JS behavior is verified by:

- **Backend test for the new `summary` field in the single-file
  terminal payload** (`tests/test_web_file_scan.py` extension):
  asserts the terminal SSE `done` event includes a `summary` dict with
  the expected keys (inventoried, scanned, infected, needs_attention,
  uploaded, skipped, errors, delay_count).
- **Manual smoke test** (documented in the plan, not automated):
  scan a folder with several `.py` files, click "Scan this file" on
  each, and confirm the counts update live.
- **No new JS unit tests** are added because the project has no JS
  test harness. The fix is small enough (one new function, two new
  call sites, one backend payload field) that manual smoke + the
  existing SSE contract tests are sufficient. If a JS harness is added
  later, this fix is a natural first target.

## Open questions

None — design is complete for task 2.