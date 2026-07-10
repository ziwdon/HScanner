# HScanner

Linux-first local file-triage app: inventory a folder, classify files by policy, enrich
with one or more scan engines (hash-first, consent-gated uploads), and produce an
attention-focused report.
Not an antivirus — a triage tool.

## Status

> **Sub-project H: outcome-focused reports — IMPLEMENTED (2026-06-24).**
>
> **Shipped:** report schema v3 replaces implementation-focused `hashed` / severity /
> `full_inventory` presentation with explicit per-file outcomes (`infected`, `no_detections`,
> `needs_attention`, `skipped`, `error`), stable reasons, independent hash-lookup/upload states,
> user-facing Inventoried/Scanned/Infected/Needs attention/Uploaded/Skipped/Errors metrics,
> mutually exclusive outcome sections, corrected engine labels, Needs-attention batch action at the
> section top, and responsive section navigation. Sensitive and low-risk skip reasons become
> distinct without weakening the no-read/no-upload invariant. JSON/CSV, standalone HTML, live
> progress, CLI exits, combined-engine provenance, and on-demand scans consume the same canonical
> outcome model; local SHA-256 remains technical detail rather than a user outcome.
> - **Spec:** `docs/superpowers/specs/2026-06-24-outcome-focused-report-design.md`
> - **Plan:** `docs/superpowers/plans/2026-06-24-outcome-focused-report.md`
> - **Integration:** implemented directly on `master` across `2ceca40..35001a7`; no git remote is
>   configured.
> - **Verification:** 333 passing tests; Ruff and `git diff --check` clean (one pre-existing
>   Starlette/httpx deprecation warning).

> **Sub-project G: combined-engine failover — ALL 9 TASKS COMPLETE (2026-06-24).**
>
> **Shipped:** CLI/web `combined` mode over VirusTotal then MetaDefender; `EngineRotation`
> priority/failover with per-engine pacing, Retry-After cooldowns, daily/monthly/per-scan quota
> stops, short-wait/long-stop behavior, and pinned post-upload polling; cross-engine cache reuse;
> required keys for every online combined engine; CLI `--wait-threshold`; per-file `engine_id`, aggregate
> and per-engine request metrics, and `engine_breakdown` (`virustotal`, `metadefender`, `cache`,
> `not_checked`) across JSON/CSV/HTML and the web report. Combined-report on-demand uploads route
> back to the concrete engine that handled the file lookup.
> - **Spec:** `docs/superpowers/specs/2026-06-23-combined-engine-failover-design.md`
> - **Plan:** `docs/superpowers/plans/2026-06-23-combined-engine-failover.md`
> - **Integration:** fast-forwarded into `master` at `0dbfb34`; the merged feature branch was
>   deleted. No git remote is configured.
> - **Verification:** 315 passing tests; Ruff and `git diff --check` clean (one pre-existing
>   Starlette/httpx deprecation warning).

> **Sub-project F: multi-engine + HScanner product rename — ALL 16 TASKS COMPLETE (2026-06-23).**
>
> **Shipped:** `ScanEngine` protocol (`src/hscanner/engines/base.py`) with `EngineFileReport`
> as the normalized, engine-neutral output; `VirusTotalEngine` and `MetaDefenderEngine`
> (`src/hscanner/engines/`) as two concrete implementations; engine registry + factory
> (`build_engine(engine_id, api_key)`); engine-scoped cache keyed by `(engine_id, sha256)`;
> engine-scoped quota counters; report identity fields (`engine_id`, `engine_name`,
> `schema_version=2`); per-engine keys stored in keyring service `"HScanner"` / env
> `HS_API_KEY_<ENGINE>` (e.g. `HS_API_KEY_VIRUSTOTAL`, `HS_API_KEY_METADEFENDER`); CLI
> `--engine {virustotal|metadefender}`, `--require-engine`, `--max-requests`; web engine
> selector; full product rename to **HScanner** (package `hscanner`, console script `hscanner`,
> state dir `$XDG_STATE_HOME/hscanner/`). Security regressions for MetaDefender added in Task 16.
> - **Spec:** `docs/superpowers/specs/2026-06-22-multi-engine-hscanner-design.md`
> - **Plan:** `docs/superpowers/plans/2026-06-22-multi-engine-hscanner.md`
> - **Tests:** 276 passing, Ruff clean (one pre-existing deprecation warning, not ours).
> - **Final whole-branch review** (opus, `8ca4fc9..59fc6c6`): no Critical/Important —
>   "Ready to merge: Yes"; eight invariants verified engine-neutral. One follow-up fix wave
>   landed (`086a1ea`: keyless-report engine label, MetaDefender poll `or {}` null-guard,
>   settings unknown-engine → 400, generic quota message, leftover copy). Work is committed
>   directly on `master` (project working style); no git remote configured.

**MVP implemented** (Tasks 1–13 of `docs/superpowers/plans/2026-06-19-vtscanner-mvp.md`).
The Scanner Core, Typer CLI, and localhost FastAPI web UI are built and tested. All eight
non-negotiable invariants are enforced end-to-end (verified by a whole-branch review).

**Sub-project A implemented** — VirusTotal request lifecycle
(`docs/superpowers/plans/2026-06-19-vt-request-lifecycle.md`): per-minute pacing + per-kind
counters + optional per-scan ceiling (`src/hscanner/budget.py` `RequestBudget`), client-wide
retry/backoff (`_request_with_retry`) with the full VT error-code mapping, post-upload analysis
polling (`wait_for_analysis`), and per-scan SHA-256 dedup in `run_online_scan`. Verified
ready-to-merge by a whole-branch review.

**Sub-project B implemented** — local persistence: two SQLite stores in WAL mode —
`$XDG_STATE_HOME/hscanner/store.db` (global; VT result cache + quota counters) and
`<root>/.hscanner/scan.db` (per-root; resumable scan state). `VTCache` stores results with
a configurable TTL (default 7 days); stale entries are queryable with `include_stale=True`.
`ScanState` tracks per-file stage with change detection (size + mtime + SHA-256 key) so
interrupted scans can resume via `--resume`. `QuotaCounter` maintains persistent daily/monthly
VirusTotal API request counts; when either budget is exceeded `QuotaExhausted` is raised and
the CLI exits with code 5. Daily/monthly budgets remain `null` by default in the policy
(quota cap is inactive until configured). Hardlink reuse is implemented in `scanner.py` via
inode key deduplication — identical inodes skip re-hashing. The API key is never written to
either database (guarded by `tests/test_no_key_persisted.py`). The final whole-branch review is
clean: cache/database failures are non-fatal so local scan results survive persistence errors,
and automatic `.hscanner` exclusion is root-scoped so nested directories with that name remain
visible. Verified 2026-06-20 with 94 passing tests and a clean Ruff run.

**Sub-project C implemented** — report export completeness
(`docs/superpowers/specs/2026-06-20-report-export-completeness-design.md`):
- **Canonical `ScanReport` schema** (`src/hscanner/report.py`): versioned (`schema_version=1`),
  typed dataclass snapshot; `build_scan_report` constructs it from `FileResult` list; `report_payload`
  serializes to a JSON-safe dict (no API key, no secrets). Each `ReportFile` carries file path,
  SHA-256, classification bucket, risk label, report category, VT state, detection ratio, errors,
  and provenance fields (`action`, `analysis_status`, `vt_permalink`, `last_analysis_at`,
  `json_reference`).
- **Exporters** (`src/hscanner/exporters.py`): `render_json` (versioned JSON), `render_html`
  (self-contained standalone HTML via Jinja2 template), `render_csv` (one row per file, CSV-injection
  guard on every cell). All three write atomically via `export_report` (temp file + rename).
  Format is inferred from the file extension (`.json`, `.html`, `.csv`).
- **CLI flags** (`src/hscanner/cli.py`): `--report PATH` (save export to file), `--require-vt`
  (exit 4 if no key), `--max-vt-requests N` (per-scan ceiling on VT API calls, passed to
  `RequestBudget`). Full exit-code set: 0 no attention / 1 attention / 2 errors / 3 bad args,
  invalid config, or export failure / 4 no key (`--require-vt` with no key, or key rejected by
  VirusTotal/auth-failed) / 5 quota exhausted / 6 fatal internal error. Codes follow deterministic
  precedence (6 → 3 → 4 → 5 → 2 → 1 → 0); the `main()` boundary is credential-safe (only "Internal
  error" is printed — never a traceback — and the API key never enters the report or any export).
- **Web report registry** (`ReportRegistry` in `src/hscanner/web/report_store.py`, installed on
  `app.state` by `create_app`): bounded in-memory store backed by non-fatal persistent history
  (`PersistentReportStore` in `src/hscanner/web/persistent_reports.py`). The history database is
  `$XDG_STATE_HOME/hscanner/reports.db` (or the platform state-dir equivalent), with 7-day
  access-based retention and fall-through loading from `/history` and report URLs. Persistent-store
  startup, read, and write failures degrade to memory-only behavior; finished scans must not be
  lost or marked failed because `reports.db` is corrupt, locked, or unwritable. The memory tier
  keeps max 5 reports with a 1-hour TTL. Download endpoints at `/reports/{id}.json`,
  `/reports/{id}.html`, `/reports/{id}.csv`; 404 with "expired or unavailable" message if the id
  is unknown.
- **Policy per-scan ceiling**: `max_vt_requests` in the policy YAML is wired through `RequestBudget`
  in both CLI (`--max-vt-requests` overrides) and web scans.
- **Security invariants verified**: `tests/test_no_key_persisted.py` covers all four render paths
  (payload, JSON, HTML, CSV); `tests/test_web.py::test_api_key_is_absent_from_web_report_and_downloads`
  covers the web report page and all three download links.
- Verified 2026-06-21 with **149 passing tests** and a clean Ruff run.

**Sub-project D implemented** — live scan progress & control
(spec `docs/superpowers/specs/2026-06-21-live-scan-progress-design.md`, plan
`docs/superpowers/plans/2026-06-21-live-scan-progress.md`). Verified ready-to-merge by the final
whole-branch review (no Critical/Important findings); both whole-branch-review remediation waves are
landed.
- **Cooperative Core control:** `ScanStatus.CANCELLED`, `ScanController`, `ScanObserver`,
  `ScanProgressEvent`, and `ScanHooks` (`src/hscanner/progress.py`) carry pause/cancel checkpoints
  and wait/poll progress through the Scanner Core (`run_online_scan` observer/controller) and the
  VirusTotal client. The client checkpoints again after `RequestBudget.acquire` (no request fires
  after cancel during a pacing wait) and between analysis polls (cancel honored within one poll
  interval). All seams default to no-ops, so existing Core/CLI paths are unchanged.
- **Background web jobs:** `ScanJob` is the observer — it maintains the authoritative progress
  snapshot and a bounded per-subscriber fan-out; `JobManager` runs a single active scan as an
  asyncio task with bounded, TTL-based retention (TTL starts at terminal completion). Cache/scan-
  state setup runs only inside an accepted job, so a busy `POST /scan` cannot create a phantom
  persistent `running` scan.
- **Live transport and UI:** SSE `GET /scan/{id}/events` provides snapshot replay, live fan-out,
  and lifecycle-safe terminal delivery (`await asyncio.shield(job.task)` before the terminal payload
  so `report_id`/`scan_status` are populated; `Cache-Control: no-cache` headers). The progress page
  renders six count tiles, replays current file/stage from the snapshot on reconnect, syncs
  Pause/Resume/Cancel to `JobStatus`, handles failed control POSTs, shows credential-safe terminal
  errors, and has an `EventSource.onerror` handler for unknown/expired jobs. Completed/cancelled
  work navigates to `GET /reports/{id}` (cancel produces a partial report).
- **Snapshot summary/ETA mirror the canonical report:** `JobSnapshot` counts `uploaded` from the
  final `action` ({`uploaded`,`analysis_completed`} — catches upload-then-poll-failure) and
  `unknown` from `report_category` ∈ {`unknown_but_suspicious`,`full_inventory`} (`skipped`
  excluded; `unknown_but_suspicious` overlaps into attention, matching `ReportSummary`). ETA is a
  rolling mean of per-file durations floored by `remaining_live_requests / per_minute * 60` (live
  requests = observed lookup/uploading/polling stage events), labeled approximate. `FILE_FINISHED`
  carries a JSON-safe `action` field; non-terminal SSE payloads carry the coarse `JobStatus`.
- **Progress readability:** combined scans show the most recently selected concrete engine, and
  ETA automatically renders in seconds, minutes, or hours.
- **Boundary:** initial local traversal and hashing remain synchronous before `SCAN_STARTED` and
  controller checkpoints; streaming and controls begin with online VirusTotal processing.
- Verified 2026-06-21 with **208 passing tests**, clean Ruff, and clean `git diff --check` over the
  full D range `3776839..HEAD`.

**Sub-project E implemented** — risk-prioritized scan & on-demand per-file upload
(spec `docs/superpowers/specs/2026-06-22-risk-prioritized-scan-design.md`, plan
`docs/superpowers/plans/2026-06-22-risk-prioritized-scan.md`). Verified ready-to-merge by the
final whole-branch review.
- **Risk tiers:** `RiskTier` enum (PRIORITY / LOW_RISK / SKIPPED) derived from classification
  bucket in `src/hscanner/models.py`; `risk_tier_for(bucket)` resolves the mapping.
- **Default-on bypass:** low-risk VT lookups are skipped by default (`bypass_low_risk=True` in
  policy); only PRIORITY-tier files are queried in folder scans, cutting quota use. CLI flag
  `--no-bypass` re-enables low-risk lookups.
- **Hash-only folder scans:** the folder-level upload checkbox is removed; `run_online_scan` no
  longer uploads during folder scans (upload consent is now per-file). Files not found by hash
  remain Unknown/Not-uploaded until the user acts.
- **ELF/shebang promotion:** `file_signals` reads magic bytes + mode; `reclassify_with_signals`
  promotes files to PRIORITY when ELF or shebang is detected, even if the extension-based bucket
  was lower-risk.
- **On-demand per-file upload:** `scan_single_file(root, relative_path, engine, cache)` in
  `src/hscanner/scanner.py` — raises `SingleFileNotEligible(reason)` for sensitive/non-priority/
  too-large files before any engine call. `FileScanManager` (`src/hscanner/web/jobs.py`) runs
  serial per-file jobs, refuses new jobs while a folder scan is active, and surfaces progress via
  SSE. `ReportRegistry.update_file` merges the finished `FileResult` back into the stored report.
- **Endpoints:** `POST /reports/{id}/files/{index}/scan` (202 + job_id or 400/409/404),
  `GET /reports/{id}/files/{index}/scan/events` (SSE to done/error),
  `POST /reports/{id}/scan-unverified` (batch-enqueue all eligible unknowns).
- **Security regression tests:** `tests/test_single_file_security.py` proves a sensitive file
  raises `SingleFileNotEligible` and both a VirusTotal-shaped and a MetaDefender-shaped spy
  engine's `upload_file` are never called (parametrized over both engine shapes);
  `tests/test_no_key_persisted.py` has per-file key-absence tests for both engines, asserting the
  key is absent from all four surfaces (JSON/HTML/CSV exports and the report page).
- Verified 2026-06-22 with **246 passing tests** and a clean Ruff run.

**Web UI redesigned** — "triage console" theme (`src/hscanner/web/static/app.css`): dark
forensic palette, local system font stacks, and a severity ramp as the signature element.
Attention-first report (severity spectrum bar, summary tiles incl. an Uploaded count, expandable
file cards, collapsed secondary groups capped at 500 rows with `content-visibility` for large
inventories). Report display model is presentation-only in `src/hscanner/report_view.py`
(`build_report_view`, consuming the canonical `ScanReport`; the old `web/view.py` was removed in
Sub-project C); the Scanner Core is untouched. The engine client is injectable via
`create_app(engine_factory=lambda engine_id, key: ...)` for testing the online path without
network. The **web app requires a configured key to scan** (see "Keyless mode" below).

Engine selector on the scan form uses horizontal selection cards (`.e-card` in `app.css`) rather
than a `<select>` dropdown: each engine gets an SVG-badged card (shield+checkmark for VirusTotal,
shield+scan-lines for MetaDefender) with accent left-bar, border glow, and radio pip on selection,
driven by `:has(input:checked)` CSS. The "Connected" status pill was removed — only the actionable
"API key required" warning is shown when no key is present. Static asset cache-busting is done via
a `?v=N` query param on `app.css` in `base.html`; bump `N` whenever CSS changes to force a fresh
fetch.

**Stack:** Python 3.11+, FastAPI + Uvicorn + Jinja2 (web), Typer (CLI), httpx (engine HTTP),
keyring (API-key storage), PyYAML (policy), pytest + pytest-asyncio + pytest-httpx, Ruff.

**Build / test / run (canonical — use the project venv):**
- Run the web app: `./run.sh` — creates `.venv`, installs deps, fails fast if the port is taken,
  serves on `http://127.0.0.1:8765`, and auto-opens the browser after ~3s. First run needs network.
  Honors `HSCANNER_HOST`/`HSCANNER_PORT`; `HSCANNER_NO_BROWSER=1` skips the browser.
- Manual setup: `python3 -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"`.
  Dependencies are declared in `pyproject.toml` (runtime + `[dev]` extras) — that is the
  requirements source; there is no separate `requirements.txt`.
- Test: `pytest` (with the venv active — no `PYTHONPATH` needed). Lint: `ruff check .`
- CLI: `hscanner scan /path/to/folder` (add `--json` for the structured AI-integration surface).
  The CLI runs online scans automatically when the required key resolves (env
  `HS_API_KEY_VIRUSTOTAL` or `HS_API_KEY_METADEFENDER`, or the saved keyring entry); local-only
  inventory otherwise. Combined online scans require keys for every combined engine; if any are
  missing, the CLI falls back to local-only inventory unless `--require-engine` is set.
  Engine selection: `--engine virustotal` (default), `--engine metadefender`, or
  `--engine combined`.
  Online flags: `--resume` (continue an interrupted scan), `--refresh` (ignore cache and
  force re-query). Report-export flags: `--report PATH` (write a `.json`/`.html`/`.csv` report —
  format inferred from the extension, written atomically), `--require-engine` (exit 4 if required
  key(s) do not resolve), `--max-requests N` (per-scan engine request ceiling, overrides the policy). Stable
  exit codes with deterministic precedence (6→3→4→5→2→1→0): 0 none / 1 attention / 2 file errors /
  3 bad args, invalid config, or export failure / 4 no key (`--require-engine` with none, or key
  rejected by the engine) / 5 quota exhausted / 6 fatal internal error (the `main()` boundary is
  credential-safe — prints only "Internal error", never a traceback). The packaged entry point is
  `hscanner.cli:main`. Example:
  `HS_API_KEY_VIRUSTOTAL=key hscanner scan /path/to/folder --engine virustotal --resume --report report.html`.
- Web (manual, venv active): `uvicorn hscanner.web.app:create_app --factory --host 127.0.0.1 --port 8765`.

> Environment note for agents: do NOT use the system `uvicorn`/`python3` — the package is not
> installed there. Use the project `.venv` (the `apt` `uvicorn` runs under system Python and fails
> with `ModuleNotFoundError: hscanner`). On this Pop!_OS box `python3 -m venv` ships WITHOUT pip
> (the `python3-venv` package is stripped), so `run.sh` bootstraps pip via `ensurepip` then
> `get-pip.py`. An older dev workaround (`PYTHONPATH=src:/tmp/hscanner-testdeps python3 -m pytest`
> with deps under `/tmp/hscanner-testdeps`) still works as a fallback if the venv is unavailable.

**Still deferred** (present in the spec, intentionally NOT yet built — see the spec before
implementing):
- **Keyless mode — DECIDED (web gated):** without an API key HScanner does no VirusTotal work
  at all (VirusTotal has no anonymous access), so a keyless scan is only inventory + classification
  + local hashing — not threat triage. The **web app now requires a key to scan** (home prompts
  for one; `POST /scan` returns a clear message otherwise). The **CLI still allows local inventory**
  explicitly. The design and acceptance criterion document that this local-only behavior is a CLI
  capability; the web UI remains gated on a configured key.
- **Folder picker — WON'T DO (decided 2026-06-20).** A browser can't hand the server a folder's
  absolute path (sandbox); native folder dialogs are desktop/Electron only, and `webkitdirectory`
  uploads file *contents*, which contradicts the in-place, local-only scan model. The text path
  field stays. The only viable alternative (a server-side directory browser) was considered and
  declined as not worth it. Don't re-propose the OS-native picker.

## Source of truth

The design is authoritative: **`docs/superpowers/specs/2026-06-19-vtscanner-design.md`**.
Read it before doing any implementation work. If implementation needs to diverge from the spec,
update the spec first (and reflect durable decisions back here).

## Architecture (the one rule that matters)

Three layers — **Scanner Core**, **Local Web App**, **CLI**. The Scanner Core owns *all*
security-relevant behavior (traversal, classification, hashing, engine calls, upload eligibility,
rate limiting, scan state/cache, report model). The Web App and CLI both call the Core **directly**
— the CLI is not a subprocess the Web App shells out to, and neither layer reimplements Core logic.
Keep security decisions in the Core so they're testable in one place.

## Non-negotiable invariants

These are safety/privacy guarantees, not preferences. Don't weaken them without an explicit
spec change and the user's sign-off:

- **Secrets/sensitive files are never uploaded**, even when per-file upload consent is given.
  Sensitive-skip rules win over every later classification rule.
- **Uploads require explicit per-file consent** (web on-demand upload: clicking "Scan this file"
  is the consent for that individual file; sensitive-skip wins; size limits gate). Hashes may be
  sent for lookups when online scanning is on; raw file *contents* leave the machine only on consent.
- **Engine API keys are never persisted to** scan state, reports, exports, logs, browser
  storage, or the default config. Keyring/secret-service when available; session-only otherwise.
- **Classification is deterministic** — a fixed precedence pipeline, driven by structured policy
  data, never scattered hardcoded conditionals. Unmatched regular files fall back to Hash-only.
- **Size limits gate upload eligibility** (`large_upload_soft_block_mb`, `absolute_upload_block_mb`).
  Per-bucket rules may tighten global limits but never loosen them.
- **The web server binds to `127.0.0.1` by default.** No hosted backend in the MVP.
- **Never imply "safe."** Use "No detections." A missing engine result is "Unknown," not clean.
- **Engine results are cached with freshness metadata and expire** (default 7-day TTL); cached
  "No detections" is not permanent truth.

## Consistency anchors

The spec defines several interlocking taxonomies — keep them aligned when editing either side:

- Classification buckets → Risk labels → Report categories: see the **Bucket to report mapping**
  table in the spec. Changing one column means updating the table.
- Error statuses, CLI exit codes (with deterministic precedence), and the engine quota model
  are all enumerated in the spec — extend the tables there rather than inventing ad-hoc codes.

## Workflow notes

- Build with the Scanner Core as a directly-testable library first; the Web App and CLI are thin
  shells over it. This is the natural seam for TDD.
- The CLI must emit structured JSON and stable exit codes (it's also the future AI-integration
  surface).

## Maintaining this file

Update CLAUDE.md when durable decisions land — the chosen stack, build/test/run commands, cache
and report storage locations, or new conventions a future session would need. One-off fixes don't
warrant an update; architectural and workflow decisions do.
