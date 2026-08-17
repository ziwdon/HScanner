# Sub-project E — Risk-prioritized scanning & on-demand per-file upload

**Date:** 2026-06-22
**Status:** Design (approved for planning)
**Authoritative parent design:** `docs/superpowers/specs/2026-06-19-vtscanner-design.md`

## Summary

Rework the scan workflow so VirusTotal effort is focused on files that can actually
harm the host, while keeping the local inventory complete. Three coupled changes:

1. **Risk tiers + bypass.** Formalize a two-tier risk model (PRIORITY vs LOW-RISK) on
   top of the existing buckets. A default-on "bypass low-risk files" control hashes
   media/docs locally but skips their VirusTotal lookups, so quota and time go to
   executables and scripts. Priority files are processed first.
2. **Hash-only is the only scan mode.** Remove the folder-level upload checkbox. A scan
   never uploads file contents on its own; it only sends hashes for lookups.
3. **On-demand per-file upload.** In the report, a flagged file that VirusTotal does not
   recognize gets a "Scan this file" button. Clicking it uploads that one file, polls the
   analysis live, and folds the new verdict back into the stored report. A "Scan all
   unverified" button does the same sequentially for every flagged file.

This is one cohesive sub-project; the pieces share the same workflow and data model.

## Goals

- Spend VirusTotal lookups on dangerous-tier files by default; keep a complete local
  inventory (every non-sensitive file still gets a SHA-256).
- Make "unknown but potentially dangerous" files unmistakable in the report and trivially
  uploadable one at a time, with explicit per-file consent.
- Detect Linux-relevant executables robustly: recognized extensions **and** ELF magic
  and shebangs (so extension-less launcher scripts/binaries are caught).
- Preserve every non-negotiable invariant. Sensitive files are never hashed and never
  uploaded, by any path.

## Non-goals (deferred)

- CLI per-file upload (`vtscanner upload <file>`). The CLI gains `--bypass-low-risk` only;
  on-demand upload is a web-only feature for now.
- Re-architecting the report into a live, server-pushed document. The report stays a
  snapshot in the bounded in-memory registry; manual scans mutate that snapshot in place.
- A pre-submit (pre-traversal) cost preview on the scan form. The estimate appears on the
  progress page, before meaningful VT spend, and the scan is cancelable.

## Invariant change (signed off)

The non-negotiable invariant *"Uploads require explicit folder-level consent"* becomes:

> **Uploads require explicit per-file consent.** Nothing is uploaded without a deliberate,
> file-specific action (clicking "Scan this file", or "Scan all unverified" which enqueues
> those specific files). Sensitive-skip rules still win over every later rule, so sensitive
> files are never hashed and never uploaded by any path. Size limits still gate upload
> eligibility.

This is a strictly stronger consent model than folder-level consent. The parent design
spec and `CLAUDE.md` invariant list are updated to match as part of implementation.

## Risk-tier model

The four classification buckets map onto three risk tiers plus the sensitive/skip case
(2026-08-17 update: the single `PRIORITY` tier was split into `HIGH` and `MEDIUM` so the
Needs-attention pill distribution is meaningful in the default report). `risk_tier` is set
**explicitly by the classifier at classify-time** on the `Classification` dataclass (one
source of truth that flows to every persistable result). The legacy helpers
`risk_tier_for_classification` (reads `cls.risk_tier`) and `risk_tier_for_legacy_bucket`
(worst-case HIGH for upload-candidate / suspicious, LOW_RISK for hash_only, SKIPPED for
skipped) preserve backwards compatibility with persisted v1/v2 reports:

- `HIGH` = an extension in `upload_candidate.high_extensions` (OS-shell-runnable / native
  code launchers), the executable bit set on an unrecognized extension, or ELF/shebang
  promotion via `reclassify_with_signals`.
- `MEDIUM` = an extension in `upload_candidate.medium_extensions` (runtime / interpreter
  required), or the suspicious-block rule matching `.pak` with `executable_markers`.
- `LOW_RISK` = bucket == `hash_only` (data, config, markup, docs, media, fonts).
- `SKIPPED` = bucket == `skipped` (sensitive or unsupported).

Because the classifier sets the tier at classify-time, every downstream behavior (report
category, manual-upload button, ordering, bypass, batch endpoint target) follows
automatically once a file is reclassified. Persisted reports that predate the
HIGH/MEDIUM split use `risk_tier_for_legacy_bucket` (worst-case → `HIGH`); re-scan
refreshes the stored tier.

| Bucket (existing)            | `risk_tier` | VT hash lookup        | Manual upload button            |
|------------------------------|-------------|-----------------------|---------------------------------|
| `skipped` (sensitive/low-value) | `SKIPPED` | never                 | never (invariant)               |
| `upload_candidate` extension in `high_extensions` | `HIGH` | always | yes, if no verdict and within size |
| `upload_candidate` extension in `medium_extensions` | `MEDIUM` | always | yes, if no verdict and within size |
| `suspicious_upload_blocked` (priority but oversize, with `tier:''` rule default) | inherits matched extension's tier (HIGH for high_ext, MEDIUM for medium_ext) | always | no → "too large" warning |
| `suspicious_upload_blocked` via `executable_markers` rule (e.g. `.pak`) | `MEDIUM` (rule default) | always | no → upload blocked |
| `hash_only` (media/docs/data/config/markup) | `LOW_RISK` | only when bypass OFF  | no (low-risk)                   |

- "Sensitive" is **deterministic and policy-driven**, not guessed: the `skipped` bucket's
  `filename_patterns`/`extensions` (currently `.env`, `*.pem`, `*.key`, `*secret*`,
  `*secrets*`, and low-value `.txt/.md/.log`). Matching the sensitive rules classifies a
  file `SKIPPED` before any other rule runs. The list is extensible via policy.

- The classifier's catch-all fallback for an unrecognized extension MUST honor
  `matching.default_bucket` (default `hash_only`) rather than unconditionally promoting
  to an upload candidate — this is the invariant that prevents `.json`, `.xml`, `.csv`,
  and other unrecognized data files from being misclassified as `PRIORITY`.

### Priority detection

A regular, non-sensitive file is `HIGH` when **any** of:

- Its extension is in the (expanded) `upload_candidate.high_extensions` set, matched
  **case-insensitively** (so `.AppImage` and `.appimage` both match).
- The executable bit is set (`mode & 0o111`).
- It begins with the ELF magic `\x7fELF` (`elf_magic: true`).
- It begins with a shebang `#!` (`shebang: true`).

ELF/shebang detection is currently declared in `default_policy.yaml` but unimplemented in
`classifier.py`. It requires file *content*, but `classify_file` is pure-metadata and runs
before hashing. This sub-project therefore uses a **two-stage classification**:

1. **Metadata stage (`classify_file`, unchanged shape):** handles sensitive-skip,
   extension matching, and the exec-bit signal — all derivable from `FileRecord` metadata
   (`mode`). Sensitive files become `SKIPPED` here and are never hashed or read.
2. **Content stage (during the hashing pass in `run_local_scan`):** while the file is
   already open to hash it, peek at the first bytes for `\x7fELF` / `#!`. If a metadata
   `hash_only` file shows an ELF/shebang signal, a new `reclassify_with_signals(record,
   classification, signals, policy)` helper in `classifier.py` promotes it — reusing the
   classifier's existing **size-gating** so the result is `upload_candidate`, or
   `suspicious_upload_blocked` when it exceeds the soft/absolute upload limit. The size
   logic stays in the classifier module (no duplication).

Promotion happens before the online loop runs, so bypass, ordering, report category, and
the manual-upload button all see the corrected bucket. Detection of ELF/shebang/exec-bit
also populates local danger signals (below).

The classifier also assigns `MEDIUM` when **any** of:

- Its extension is in the (expanded) `upload_candidate.medium_extensions` set, matched
  **case-insensitively**.
- The suspicious-block rule matches with `executable_markers: true` on a file whose
  original bucket was `hash_only` (e.g. the `.pak` executable-markers rule). The
  suspicious-block rules default to `MEDIUM` when no `tier:` key is set; oversized-only
  rules with `min_size_mb` inherit the matched extension's tier (HIGH for high ext,
  MEDIUM for medium ext), or `HIGH` (worst-case) when no extension matched.

Within the priority set, HIGH files are scheduled before MEDIUM files so the worst
unknowns complete first.

`upload_candidate` is split into two extension sub-lists (replacing the legacy combined
`extensions` list — no currently-listed extension changes tier):

`upload_candidate.high_extensions` (OS-shell-runnable / native code launchers):
`.exe .dll .so .bin .appimage .deb .rpm .msi .run .scr .com .lnk .sh .bash .zsh .bat
.cmd .ps1 .vbs .wsf`

`upload_candidate.medium_extensions` (runtime / interpreter / toolchain required):
`.py .pyc .pyd .rpy .rpym .rpyc .rpymc .rpyb .rpa .pl .rb .js .jar`

Unmatched regular files fall back to `matching.default_bucket` (default `hash_only` /
`LOW_RISK`) unless a priority signal (exec-bit/ELF/shebang) promotes them.

### Local danger signals

`FileResult` and `ReportFile` carry three booleans: `executable_bit`, `shebang`, `elf`.
They render as badges in the report (e.g. `executable · unverified`) so dangerous unknowns
stand out with zero VirusTotal cost. They are presentational and do not change the
risk-label/category taxonomy.

## Scan flow

### Hash-only only

The web `/scan` form drops the `upload_eligible` checkbox. `run_online_scan` is always
called with `upload_consent=False` (already true for the CLI). The `upload_consent`
parameter remains in the Core signature because the on-demand path reuses the same upload
primitives (`upload_file` + `wait_for_analysis`), but no caller passes `True` for a whole
folder.

### Bypass low-risk (default ON)

- Web: a checkbox on the scan form, checked by default —
  *"Bypass low-risk files (hash locally, skip VirusTotal)."*
- CLI: `--bypass-low-risk / --no-bypass-low-risk` (default on).
- `run_online_scan` gains `bypass_low_risk: bool`. When ON, a `LOW_RISK` file is hashed
  locally but its VT lookup is skipped: `vt_state` stays `NOT_QUERIED`, `action` stays
  `HASHED`. `classify_report_result` already routes `LOW_RISK` + `NOT_QUERIED` →
  `FULL_INVENTORY` (not an attention category), which correctly reads as "not checked, low
  risk." Priority files are always looked up regardless of the bypass setting.

### Priority-first ordering

Immediately after the local walk, sort the results list by `(risk_tier PRIORITY first,
then relative path)` before the VT loop. Processing becomes priority-first, so a cancelled
or quota-capped scan has already covered the files that matter. The report builder
re-sorts by category/path for display; SSE `index` values refer to positions in the
(reordered) results list and stay internally consistent.

### Pre-scan cost estimate

The local walk + classification runs synchronously before `SCAN_STARTED` (existing
boundary). The job's first snapshot carries `online_pending` (count of files that will get
a VT lookup, reflecting the bypass setting) and `bypassed` (low-risk files skipped). The
progress page shows a banner immediately, e.g.
*"Checking 42 files on VirusTotal · 318 low-risk bypassed — Cancel anytime."*
Tradeoff: this appears on the progress page after submit, not as a pre-submit preview.
Acceptable because priority files go first, pacing is ~4/min, and the scan is fully
cancelable before meaningful VT spend.

## On-demand per-file upload

### Core primitive — `scan_single_file(...)`

Lives in the Scanner Core (all security logic stays in the Core). Inputs: absolute path,
expected sha256, a VT client, a cache. Behavior:

1. Re-stat and **re-hash** the file (it may have changed or vanished since the scan). If it
   vanished → typed error (`FILE_VANISHED`). If the hash changed, continue with the new hash.
2. Re-check guards in the Core (defense in depth, independent of the UI):
   - tier must be `PRIORITY` and `upload_eligible` true,
   - must not be `SKIPPED`/sensitive,
   - size must be within `absolute_upload_block_mb`.
   On failure → typed rejection with a reason (not eligible / too large / vanished).
3. Try a fresh **hash lookup first** (the file may now be known to VT — cheaper than an
   upload). Only if still `NOT_FOUND`, `upload_file` + `wait_for_analysis`.
4. Cache the resulting payload via the existing `_cache_payload`. Return an updated
   `FileResult` (with `action`, `vt_state`, `analysis_status`, stats, detections set).

### `FileScanManager` (on `app.state`, sibling to `JobManager`)

- Runs single-file upload jobs **serially** (one at a time). Serial is correct for VT
  per-minute pacing and the persistent daily/monthly `QuotaCounter`; "Scan all unverified"
  simply enqueues many. A 600s analysis timeout on one file blocks the queue behind it —
  accepted (VT public pacing is ~4/min anyway).
- Jobs are keyed by `(report_id, file_index)`. A duplicate request for a job already
  queued/running is a no-op that re-attaches to the existing live stream.
- Each job exposes SSE lifecycle states: `queued → uploading → analyzing → done(verdict)`
  or `error(reason)`. Bounded, TTL-based retention like `JobManager`.
- **Concurrency safety:** `FileScanManager` refuses to start while `JobManager` has an
  active folder scan (clear "a scan is in progress" message), so there is only ever one
  VirusTotal consumer at a time and pacing/quota stay honest.

### Registry mutation

`ReportRegistry.update_file(report_id, index, updated_result)`:
- Rebuilds that one `ReportFile` via the existing `_report_file(index, updated_result)`
  builder, `dataclasses.replace`s the frozen `ScanReport.files` tuple, and **recomputes
  `ReportSummary`**.
- **Prerequisite (see Finding in self-review):** `ReportSummary.known_to_vt` currently
  reads `vt_assessment_complete` off the `FileResult`, which the registry does not retain.
  So summary computation is extracted from `build_scan_report` into a standalone
  `compute_summary(files: tuple[ReportFile, ...], metrics) -> ReportSummary`, and
  `ReportFile` gains `assessment_complete: bool` so the summary is derivable from the
  `ReportFile`s alone. `build_scan_report` and `update_file` both call `compute_summary`.
- `request_metrics` / `delay_count` are retained from the original scan; an out-of-band
  manual upload's pacing metrics are not merged into the report-level totals.
- No `schema_version` bump — same shape, updated values (`assessment_complete` is a new
  field but the JSON payload remains backward-compatible additively; if strict versioning
  is preferred this is the one place to reconsider a bump during planning). A page reload
  shows the new verdict; subsequent JSON/HTML/CSV exports include it.

### Endpoints (web layer, thin over the Core)

- `POST /reports/{report_id}/files/{index}/scan` — validate against the registry,
  reconstruct `root / relative_path`, enqueue a `FileScanManager` job. Returns the job
  handle, or a 4xx with a reason (expired report → 404; not eligible / too large /
  vanished → 400/409).
- `GET /reports/{report_id}/files/{index}/scan/events` — SSE live status for that file.
- `POST /reports/{report_id}/scan-unverified` — enqueue every flagged priority-unknown
  file in the report; returns the list of enqueued indices.

### Front-end (inline JS in `report.html`, mirroring the progress-page SSE pattern)

- Each eligible card gets a **Scan this file** button, or a disabled
  **Too large to upload (X > limit)** chip when oversize.
- Click → POST → open the file's SSE → card shows live `uploading… / analyzing…` → on
  `done`, the card's badge / verdict / detection-ratio update in place, and the card's DOM
  node **re-sorts into its new severity group** (updating group counts and the
  `content-visibility` collapsed groups). On `error`, a credential-safe message (never a
  traceback or key), consistent with existing terminal-error handling.
- A **Scan all unverified (N)** button at the top of the attention section drives the
  batch endpoint and shows aggregate progress; per-file cards update as each completes.

### Consent model

Clicking **Scan this file** *is* the explicit, per-file consent to upload — stronger and
more granular than folder-level consent. Sensitive files never expose the button and are
rejected by the Core guard regardless of the UI.

## Architecture / layering

All security-relevant behavior stays in the Scanner Core: tier classification,
ELF/shebang detection, bypass logic, ordering, `scan_single_file` (with its guards), and
cache writes. The web layer (`FileScanManager`, endpoints, registry mutation, SSE, inline
JS) is a thin shell that calls the Core directly. The CLI calls the Core directly for the
scan-side changes (bypass, ordering) and does not gain on-demand upload.

## Data-model changes

- `RiskTier` enum (`PRIORITY` / `LOW_RISK` / `SKIPPED`) exposed as a **derived** helper
  from `ClassificationBucket` (e.g. `risk_tier_for(bucket)` or a `Classification.risk_tier`
  read-only property) — not a separately stored, independently-settable field.
- `FileResult`: add `executable_bit: bool`, `shebang: bool`, `elf: bool`.
- `ReportFile`: add the same three local-signal booleans **and** `assessment_complete: bool`
  (needed so `compute_summary` is derivable from `ReportFile`s alone); all surfaced in
  `report_payload`.
- `ReportSummary` construction extracted to `compute_summary(files, metrics)`, shared by
  `build_scan_report` and `ReportRegistry.update_file`.
- `JobSnapshot`: add `online_pending: int`, `bypassed: int`.
- No `ScanReport.schema_version` change (additive fields only).

## Error handling

- `scan_single_file` returns typed rejections/errors: not eligible, too large, vanished,
  upload failed, analysis timed out — mapped to existing `ErrorCode`s where they fit, new
  ones added to the spec table if needed (no ad-hoc codes).
- The web boundary remains credential-safe: SSE/error payloads never carry a traceback or
  the API key.
- Cache/registry failures stay non-fatal: a manual scan that succeeds with VT but fails to
  cache or to mutate the registry still reports its verdict to the user.

## Testing strategy (TDD, Core-first)

**Core:**
- Tier classification: each extension/exec-bit/ELF/shebang path; sensitive wins over a
  priority extension; case-insensitive extension match; unmatched fallback → LOW_RISK.
- ELF/shebang detection on real byte prefixes; extension-less ELF/shebang → PRIORITY,
  and `reclassify_with_signals` **changes the bucket** to `upload_candidate` (so the file
  becomes `UNKNOWN_BUT_SUSPICIOUS` and button-eligible) or `suspicious_upload_blocked`
  when oversize.
- Bypass: LOW_RISK files skip VT (NOT_QUERIED) only when bypass on; PRIORITY always looked
  up; bypass off restores today's behavior.
- Priority-first ordering of the processing loop.
- `scan_single_file` guards: sensitive → rejected; oversize → rejected; vanished → error;
  hash-changed → uses new hash; found-on-relookup → no upload; not-found → upload + poll.
- `compute_summary` produces identical counts from `ReportFile`s alone as the old inline
  computation did from `FileResult`s (regression guard for the extraction).
- `ReportRegistry.update_file`: rebuilds files tuple and recomputes summary counts (e.g.
  an unknown file gaining a HIGH verdict updates `detections`/`unknown`/`known_to_vt`).

**Web:**
- `/scan` form without the upload checkbox; `bypass_low_risk` plumbed through.
- New endpoints: eligibility 4xx, expired-report 404, SSE state sequence, batch enqueue.
- Concurrency refusal while a folder scan is active.

**Security:**
- Extend `tests/test_no_key_persisted.py` to the new upload/SSE/registry-mutation paths.
- A Core test proving a sensitive file can never be uploaded even via the manual endpoint.

All web tests run network-free via `create_app(vt_client_factory=...)`.

## Files touched (anticipated)

- `src/vtscanner/models.py` — `RiskTier`, `Classification.risk_tier`, local-signal fields.
- `src/vtscanner/policy/default_policy.yaml` — expanded `upload_candidate.extensions`.
- `src/vtscanner/classifier.py` — tier derivation, case-insensitive ext, ELF/shebang.
- `src/vtscanner/hash.py` / scan pass — capture first-bytes signals during hashing.
- `src/vtscanner/scanner.py` — `bypass_low_risk`, priority-first ordering,
  `scan_single_file`.
- `src/vtscanner/report.py` — local-signal fields in `ReportFile`/payload; summary recompute
  helper reused by registry mutation.
- `src/vtscanner/report_view.py` — attention section for unverified-dangerous, badges,
  per-file button / size-warning state, "Scan all unverified".
- `src/vtscanner/web/report_store.py` — `ReportRegistry.update_file`.
- `src/vtscanner/web/jobs.py` — `JobSnapshot` counts; `FileScanManager`.
- `src/vtscanner/web/routes.py` — drop upload checkbox; new endpoints; bypass plumbing.
- `src/vtscanner/web/templates/{index,progress,report}.html` — form control, cost banner,
  buttons + inline SSE JS.
- `src/vtscanner/cli.py` — `--bypass-low-risk/--no-bypass-low-risk`.
- `docs/superpowers/specs/2026-06-19-vtscanner-design.md` + `CLAUDE.md` — invariant wording.
- Tests across the above.

## Acceptance criteria

- With bypass ON (default), a folder of mixed media + scripts produces VT lookups only for
  priority-tier files; media files are hashed and listed but `NOT_QUERIED`.
- An extension-less ELF binary or shebang script is classified PRIORITY and looked up.
- The scan form has no upload checkbox; no folder-level upload occurs in any scan.
- A flagged priority-unknown file in the report shows a working "Scan this file" button;
  clicking uploads + polls live and updates the card's verdict in place, re-sorting it into
  the correct severity group; a reload preserves the new verdict; exports include it.
- An oversize priority-unknown file shows a "too large" warning instead of a button and
  cannot be uploaded.
- A sensitive file never shows the button and is rejected by the Core guard even if its
  endpoint is called directly.
- Per-file uploads run serially and are refused while a folder scan is active; the API key
  never appears in any new response, SSE payload, or export.
- All invariants from the parent design still hold; full test suite and Ruff are clean.
