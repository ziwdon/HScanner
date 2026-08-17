# Needs-attention prioritization + flat extension grouping for No detections / Skipped

**Spec date:** 2026-08-12

## Problem

Large scans can produce hundreds of Needs-attention entries (unknown hashes, upload-blocked
files, incomplete engine results) and thousands of No-detections / Skipped entries. Today
every outcome section is a single flat list of `<details class="file">` cards sorted by
relative path, with only No detections and Skipped capped at 500 rows. The result is a wall
of cards that is overwhelming to triage: executables/scripts/archives are mixed with the long
tail of low-risk unknowns, and there is no orientation on which file types dominate the
noise sections.

## Goal

- **Needs attention**: surface the files most worth acting on (executables/scripts/archives
  the Core classifies as `RiskTier.HIGH` or `RiskTier.MEDIUM`) before the long tail of
  low-risk unknowns (`RiskTier.LOW_RISK`), with a one-glance distribution summary and a
  filter toggle to focus on one tier at a time.
- **No detections / Skipped**: orient the user with an alphabetical roster of file
  extensions (each collapsible, collapsed by default) so long inventories don't render
  thousands of DOM nodes up front.
- **Infected / Errors**: unchanged. They are already short, critical surfaces.

## Non-goals

- No new Core classification logic. The View reuses the existing `risk_tier_for` helper and
  derives file extensions from the already-exposed `relative_path` field, exactly like the
  current `build_file_view` already parses `dir`/`name` from `relative_path`.
- No new policy surface (no per-extension risk allowlist).
- No change to JSON / CSV exports. Extension grouping is a presentation concern; the JSON
  payload already exposes `relative_path` and `classification_bucket`, which is sufficient
  for any downstream consumer to reproduce the grouping.
- No change to the standalone HTML export's content (it continues to render the section list
  flat). The interactive filter pills and JS-driven collapsibles are web-report only.
- No change to outcome reasons, summary tiles, navigation entries, or batch-action
  semantics: the same files are Needs attention, the same batch "Upload and scan all
  unverified" is offered, and the count tiles are unchanged.

## Architecture alignment

The report view layer is presentation-only and already parses filename properties from
`relative_path` (existing `dir`/`name` split in `build_file_view`). This change extends that
same presentation-only pattern: it calls `risk_tier_for(ClassificationBucket(...))` from
`hscanner.models` to split the Needs attention list — no risk heuristic is re-implemented in
the view. No Core classification decision moves into the View.

## File extension definition

`extension = basename.rpartition(".")[2].lower()` when the basename contains a `.`;
otherwise `""`. The display title for the empty-extension group is `"(no extension)"`.
Multi-dot filenames take the last dot (`archive.tar.gz` → `"gz"`), mirroring how a user
reads file extensions. Cases:

- `MilfyCity-32.exe` → `"exe"`
- `lib/windows-i686/pythonw.exe` → `"exe"`
- `renpy/style.pxd` → `"pxd"`
- `Makefile` → `""`
- `bin/run.sh` → `"sh"`

## View payload changes (`report_view.py`)

Each section dict gains an optional `groups` list when grouping applies. Sections that do
not group keep the existing flat `files` layout (and `groups` is omitted, not `None` or
empty, so templates can distinguish "no grouping" from "grouping applies").

### `build_file_view`

- Adds `"extension"` (string; `""` for no extension) to the per-file view dict. Derived
  from `file.relative_path` exactly like the existing `dir`/`name` parsing.

### Grouping rules per outcome

- `needs_attention`: split `files` into three groups by `risk_tier` (set by the
  classifier at classify-time on `Classification`; persisted on `ReportFile`):
  - `{"key": "high",     "title": "High priority",   "files": [...], "total": N, "hidden": 0}`
  - `{"key": "medium",   "title": "Medium priority", "files": [...], "total": N, "hidden": 0}`
  - `{"key": "low_risk", "title": "Lower risk",      "files": [...], "total": N, "hidden": 0}`
  - Order: High first, then Medium, then Lower risk. No per-group cap (Needs attention is
    the actionable surface; capping would hide unknowns the user should act on — same
    uncapped behavior as today).
  - The existing section-level `hidden` field stays 0 for backward compatibility with the
    template's existing "Showing first N of M" guard (which won't fire on this section
    anyway).
  - Persisted reports that predate the HIGH/MEDIUM split use
    `risk_tier_for_legacy_bucket(bucket)` to render (worst-case → HIGH) until re-scanned.
- `no_detections` and `skipped`: group by `extension`, sorted alphabetically by key (with
  `""` for "no extension" sorted as the empty string — it appears at the top of the
  alphabetical list, before any dotted extension). Each group:
  - `{"key": "exe", "title": ".exe" (or "(no extension)"), "files": [...], "total": N, "hidden": M}`
  - Per-group interactive cap of 500 rows (`_MAX_SECONDARY_ROWS`, unchanged value). Files
    beyond the cap are not rendered into `group.files`; `hidden` counts them. The note
    `Showing first 500 of N in this group. Use JSON or CSV for the complete list.` appears
    inside the group when `hidden > 0`.
  - The section-level `hidden` field is **preserved with its existing semantics**
    (`len(all_section_files) - len(section.files)`) for the standalone HTML template, which
    continues to use `section.files` (the flat union capped at 500 total — see "Standalone
    HTML export" below). The interactive `report.html` template no longer renders the
    section-level "Showing first X of Y" note for grouped sections; it renders per-group
    notes from `group.hidden` instead.
- `infected` and `error`: no grouping; flat `files` as today. `groups` is omitted.

### Filter pill state for Needs attention

The Needs attention section dict gains a `filters` field:
`[{"key": "all", "label": "All", "pressed": true}, {"key": "high", "label": "High", "pressed": false}, {"key": "medium", "label": "Medium", "pressed": false}, {"key": "low_risk", "label": "Lower risk", "pressed": false}]`.
Template renders these as mutually exclusive pills; JS toggles `aria-pressed` and shows/hides
`[data-group="high"]` / `[data-group="medium"]` / `[data-group="low_risk"]` accordingly.

### Risk-distribution chips for Needs attention

The Needs attention section dict gains a `risk_chips` field:
`[{"key": "high", "label": "High priority", "count": N, "sev": "sev-high"}, {"key": "medium", "label": "Medium priority", "count": M, "sev": "sev-medium"}, {"key": "low_risk", "label": "Lower risk", "count": K, "sev": "sev-low"}]`.
Always visible above the section's groups, just below the batch action. Clicking a chip has
the same effect as the corresponding filter pill.

## Template changes (`report.html`, `_file_card.html`)

- `report.html`:
  - When `section.groups` is present, render one `<details class="group" data-group="...">`
    per group with a `<summary class="group-head">` showing `{{ group.title }} ({{ group.total }})`.
    Inside each group, render file cards via the existing `{% include "_file_card.html" %}`
    with `f = file` (no change to `_file_card.html`).
  - When the group's `hidden > 0`, append `<p class="note">Showing first 500 of {{ group.total }} in this group. Use JSON or CSV for the complete list.</p>` inside the group.
  - When `section.groups` is absent, render the existing flat list (current code path for
    Infected and Errors).
  - For `needs_attention` only: render `risk_chips` and `filters` above the groups. JS at
    the bottom of the template handles the pill/chip toggling; uses CSS `hidden` on
    `[data-group="..."]` rather than re-rendering.
  - The `_file_card.html` include is unchanged.
- `base.html`: bump the `?v=N` cache-buster on `app.css` to force a fresh fetch.

## CSS changes (`app.css`)

- New `.risk-chips` (flex row), `.risk-chip` (inline chip with severity tint via existing
  `--sev-*` tokens), `.filter-pills` (flex row), `.filter-pill[aria-pressed="true"]`
  (active state), `.group-head` (collapsible group header — symmetric with the existing
  `details.file > summary` styling but one level up).
- No new color tokens; reuse the existing palette.

## Standalone HTML export

`standalone_report.html` keeps the current flat rendering (portable export; no JS). The
view payload's new `groups` field is consumed only by the interactive web template. The
standalone template continues to iterate `section.files` (which, for grouped sections, is
now the ungrouped flat list up to the section-level cap — we set the section-level cap to
`_MAX_SECONDARY_ROWS` for grouped sections when rendering for standalone, so the exported
HTML preserves the prior 500-row behavior). Concretely: `build_report_view` always populates
`section.files` for non-grouped sections; for grouped sections, it populates `section.files`
with the flat union (capped at 500 total) **plus** the structured `section.groups` for the
interactive template. The standalone template ignores `groups` and renders the flat `files`
list as it does today — the rendering is unchanged.

## Tests (`tests/test_report_view.py` and `tests/test_report_view_buttons.py`)

Add to `tests/test_report_view.py`:

1. `build_file_view` extension derivation:
   - `foo.exe` → `"exe"`
   - `lib/bar.sh` → `"sh"`
   - `Makefile` → `""`
   - `archive.tar.gz` → `"gz"`
2. Needs attention view payload has `groups` with exactly three entries — `high` first,
   `medium` second, `low_risk` third — and files are correctly split by their persisted
   `risk_tier` (UPLOAD_CANDIDATE / SUSPICIOUS_UPLOAD_BLOCKED → high or medium depending
   on the matched extension; HASH_ONLY → low_risk). Persisted reports that predate the
   HIGH/MEDIUM split render their priority-tier files via
   `risk_tier_for_legacy_bucket` (worst-case → high) until re-scanned.
3. Needs attention view payload exposes `risk_chips` and `filters` with the documented
   shapes and counts.
4. No detections / Skipped view payloads have `groups` ordered alphabetically by extension
   key; the empty-extension group has `key == ""`, `title == "(no extension)"`, and sorts
   first.
5. Per-group cap of 500 honored: a section with 750 .exe files and 200 .sh files has the
   `.exe` group with `total == 750`, `hidden == 250`, `len(files) == 500`.
6. Infected and Errors view payloads have **no** `groups` key (grouping does not apply);
   the flat `files` list is unchanged.
7. `section.files` remains populated for grouped sections and is capped at 500 total for
   backward compatibility with the standalone template.

Existing tests in `tests/test_report_view_buttons.py`, `tests/no_key_persisted.py`,
`tests/test_report_schema.py`, and `tests/test_web*.py` continue to pass.

## Verification

- `pytest` — full suite passing after TDD red/green.
- `ruff check .` — clean.
- `git diff --check` — clean.
- Manual smoke: load a real large scan (e.g. the MilfyCity folder used to find the
  MetaDefender bug) and confirm:
  - Needs attention opens with Priority as the only open group.
  - Toggling the "Lower risk" pill hides the Priority group.
  - No detections and Skipped sections render collapsed alphabetical extension groups.
  - Infected remains a flat list.
  - Standalone HTML export still renders flat.

## Out-of-scope follow-ups (not in this spec)

- Per-extension filter pills for No detections / Skipped (YAGNI today; grouping is enough).
- Surfacing file extensions in the JSON/CSV exports (already derivable from `relative_path`).
- Memory-optimized rendering for sections with > 100k files (deferred until a real
  inventory hits that scale).