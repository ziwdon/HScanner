# Priority tier split (HIGH / MEDIUM / LOW_RISK) — design

Status: design. Supersedes the single `PRIORITY` tier defined in
`2026-06-22-risk-prioritized-scan-and-on-demand-upload-design.md`. Backwards
compatible with persisted reports; online behavior is unchanged apart from
scheduling order inside the priority set.

## Motivation

Two related defects present in the post-scan triage report:

1. **Inflated Priority list.** Files such as `.json` / `.xml` / `.csv` / `.html`
   appear under "Priority" in the Needs-attention section. The classifier's
   final fallback (`classifier.py:101-107`) ignores the policy's
   `matching.default_bucket: hash_only` and instead returns
   `UPLOAD_CANDIDATE` with `suspicious=True`, so any unrecognized extension
   is promoted to `RiskTier.PRIORITY`. This contradicts the existing spec
   invariant ("Unmatched regular files still fall back to `hash_only` /
   `LOW_RISK`", `2026-06-22-risk-prioritized-scan-design.md`).

2. **Empty "Lower risk" pill.** In the default scan mode (`bypass_low_risk`
   ON), low-risk files are skipped before any engine lookup and land in the
   *Skipped* section, so the Needs-attention "Lower risk" pill is always 0.
   Consequently the entire tier split provides no actionable distinction in
   the common case — every actionable unknown sits under one undifferentiated
   "Priority" pill.

## Goals

- A meaningful, populated priority split visible in the default report.
- `.json`, `.xml`, `.csv`, and similar data/config/markup files no longer
  appear under Priority.
- No regression in security invariants (secrets skip, upload consented,
  size-gated, deterministic classification).
- No new per-scan quota cost; only the order in which priority files are
   sent to the engine changes.
- Backwards compatible with already-persisted reports and existing API
   cache entries.

## Non-goals

- Changing default `bypass_low_risk` behavior (low-risk files stay skipped
  in default mode and appear under the *Skipped* section).
- Mirroring tiers inside the *Skipped* section (deferred — Skipped keeps
  extension grouping).
- Quota-gating the MEDIUM tier. Both HIGH and MEDIUM are always scanned
  when the priority set is scanned.

## Design

### Risk tier model

`RiskTier` (`src/hscanner/models.py`) gains two explicit priority tiers in
place of the single `PRIORITY`:

```python
class RiskTier(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW_RISK = "low_risk"
    SKIPPED = "skipped"
```

`Classification` gains an explicit `risk_tier: RiskTier` field, set by the
classifier at classify-time. The bucket alone no longer carries tier
information because `UPLOAD_CANDIDATE` and `SUSPICIOUS_UPLOAD_BLOCKED` now
split into HIGH or MEDIUM depending on the matched extension (see below).

`risk_tier_for(bucket)` is removed. Two replacement helpers are added:

- `risk_tier_for_classification(cls: Classification) -> RiskTier` — reads
  `cls.risk_tier`. Used in the Core, view layer, and routes.
- `risk_tier_for_legacy_bucket(bucket: ClassificationBucket) -> RiskTier`
  — used only when loading a v1/v2 persisted report that did not store the
  tier. Maps `UPLOAD_CANDIDATE` / `SUSPICIOUS_UPLOAD_BLOCKED` → `HIGH`
  (worst-case deflection), `SKIPPED` → `SKIPPED`, otherwise `LOW_RISK`.
  Online cache records that predate the change do not require migration:
  they carry a hash result, not a classification, so no tier is needed.

### Classification rule (HIGH vs MEDIUM vs LOW_RISK)

Principle: **"Does this file run native code or a system shell when
launched, or does it require a separate runtime/interpreter/toolchain
to be installed to execute?"**

- **HIGH** — runs native code or a system shell when launched.
- **MEDIUM** — requires a runtime/interpreter/toolchain/engine.
- **LOW_RISK** — data, config, markup, docs, media, fonts.
- **SKIPPED** — sensitive or non-regular/unsupported.

### Policy (`default_policy.yaml`)

Split the existing `upload_candidate.extensions` list into two
sub-lists. Existing entries stay where they are today; the lists are
only extended, never reclassified:

```yaml
upload_candidate:
  high_extensions:
    # OS-shell-runnable / native code launchers
    [".exe", ".dll", ".so", ".bin", ".appimage", ".deb", ".rpm", ".msi", ".run",
     ".scr", ".com", ".lnk",
     ".sh", ".bash", ".zsh", ".bat", ".cmd", ".ps1", ".vbs", ".wsf"]
  medium_extensions:
    # Runtime / interpreter / toolchain required
    [".py", ".pyc", ".pyd", ".rpy", ".rpym", ".rpyc", ".rpymc", ".rpyb", ".rpa",
     ".pl", ".rb", ".js", ".jar"]
  executable_bit: true
  elf_magic: true
  shebang: true
  reason: "executable, package, or script"
```

Emphasis: the existing `upload_candidate.extensions` set (which today
contains all of the above under one list) is split *exactly* along its
existing membership — no currently-PRIORITY extension moves to a
different tier. The split is purely additive in semantics.

Curated `hash_only` extensions are extended (not reclassified) with
data/config/markup types so unrecognized data files are no longer
misbucketed:

```yaml
hash_only:
  extensions:
    # Existing entries (unchanged)
    [".pdf", ".docx", ".xlsx", ".mp4", ".mkv", ".png", ".jpg", ".jpeg",
     ".ogg", ".wav", ".svg", ".ttf", ".otf", ".ttc",
     ".pak", ".vpk", ".bundle", ".asset", ".ucas", ".utoc",
     # New data/config/markup entries
     ".json", ".xml", ".csv", ".tsv", ".yaml", ".yml", ".toml", ".ini",
     ".cfg", ".conf", ".lock", ".map", ".html", ".htm", ".css",
     ".sql", ".graphql", ".proto"]
  reason: "hash-only by default"
```

The `skipped.extensions` list (`.txt`, `.md`, `.log`) is unchanged.

### Classifier (`classifier.py`)

1. **Default-fallback bugfix.** The final fallback in `classify_file`
   (currently returns `UPLOAD_CANDIDATE` with `suspicious=True` regardless
   of `matching.default_bucket`) reads
   `policy["matching"]["default_bucket"]`:

   - If `default_bucket == "hash_only"` and the file is under the
     soft/absolute size limits, return `HASH_ONLY` with
     `risk_tier=LOW_RISK`, `upload_eligible=False`, `hash_eligible=True`.
   - The legacy `"upload_candidate"` value for `default_bucket` is still
     honored for back-compat (returns `UPLOAD_CANDIDATE`, tier per the
     matched extension rule below, or HIGH if no extension match).
   - The `suspicious=True` flag on the catch-all fallback is removed.

2. **Tier assignment.** `_is_upload_like` returns the matched sub-list
   (`"high"` / `"medium"` / `None`) in addition to the boolean. When the
   file matches an upload_candidate sub-list, tier is set accordingly:

   - matched `high_extensions` → `UPLOAD_CANDIDATE`, `risk_tier=HIGH`
   - matched `medium_extensions` → `UPLOAD_CANDIDATE`, `risk_tier=MEDIUM`
   - matched only by `executable_bit` set (no extension match) → `HIGH`
     (an executable bit on an unknown file is the worst-case signal)

3. **ELF / shebang promotion** (`reclassify_with_signals`). A HASH_ONLY
   file that shows ELF or shebang magic promotes to `UPLOAD_CANDIDATE`
   with `risk_tier=HIGH`, since ELF/shebang is direct execution
   capability. Existing size-block safeguards (soft/absolute limit) still
   produce `SUSPICIOUS_UPLOAD_BLOCKED`; the tier for a promoted
   size-blocked file follows rule 4 below.

4. **SUSPICIOUS_UPLOAD_BLOCKED tier.** Inherit the tier of the matched
   suspicious extension:
   - matched a `high_extensions` entry (e.g., oversized `.sh`) → HIGH
   - matched a `medium_extensions` entry (e.g., oversized `.rpy`) → MEDIUM
   - catch-all oversized-anonymous (unknown extension over limit) → HIGH
     (worst-case deflection for files we cannot otherwise classify)
   - `suspicious_upload_blocked.rules` (the `.pak` + executable_markers
     rule) → MEDIUM (`.pak` is in `hash_only`, but the rule fires only on
     executable markers; treat as MEDIUM attention since the inner
     content is unverified)

5. **`_matches_executable_marker_block`**: updated to return the tier of
   the rule (defaults MEDIUM for `.pak`).

### Report view (`report_view.py`)

`_RISK_GROUP_META` becomes:

```python
_RISK_GROUP_META = {
    RiskTier.HIGH.value:     {"key": "high",     "title": "High priority",   "sev": "sev-high"},
    RiskTier.MEDIUM.value:   {"key": "medium",   "title": "Medium priority", "sev": "sev-medium"},
    RiskTier.LOW_RISK.value: {"key": "low_risk", "title": "Lower risk",      "sev": "sev-low"},
}
```

- Needs-attention risk groups render in order: `high`, `medium`, `low_risk`.
- The Needs-attention `<details class="group">` for `high` is `open` by
  default. `medium` and `low_risk` are collapsed by default — High is the
  actionable focal point. (The existing template rule that auto-opens
  `data-group="priority"` is replaced with `data-group="high"`.)
- Filter pills: `All` / `High` / `Medium` / `Lower risk`. The "Lower risk"
  pill remains valid (it shows 0 in default mode and is populated only
  when `bypass_low_risk` is OFF).
- Risk chips above the pills mirror the same three keys + counts.
- `group_for_file_view` reads `file_view["risk_tier"]` (new) rather than
  calling `risk_tier_for(bucket)`. The single-file update payload
  (`/reports/{id}/files/{index}/scan/events` -> `applyFileUpdate` in
  `report.html`) carries the same `risk_tier` so a re-scanned file lands
  in the correct subgroup.
- `tier_key_for_bucket` (consumed by `routes.py` for the batch target)
  becomes `tier_key_for_classification`, reading `cls.risk_tier`. A
  legacy-bucket fallback (`risk_tier_for_legacy_bucket`) is used when the
  persisted report did not store `risk_tier`.

The Skipped section keeps the current grouping-by-extension behavior.
Mirroring tiers inside Skipped is explicitly deferred (see Non-goals).

### Scan order (`scanner.py`)

The existing priority-first ordering (`scanner.py:342`) sorts priority
files before low-risk files. Within the priority set, HIGH is now sorted
before MEDIUM, so the worst unknowns complete first. Concretely:

- the `key` function for the existing `sorted(...)` changes from
  `0 if priority else 1` to a tuple `(tier_rank, …)` where
  `tier_rank = {HIGH: 0, MEDIUM: 1, LOW_RISK: 2, SKIPPED: 3}`.
- Total scan count is unchanged. No quota impact.
- Low-risk bypass logic (`risk_tier_for(...) == LOW_RISK`) now reads
  `classification.risk_tier == LOW_RISK` via the new helper. The
  `/files/{index}/scan` eligibility gate (`scanner.py:597,672`) reads
  `risk_tier_for_classification(cls) in {HIGH, MEDIUM}` (i.e., any
  priority tier is upload-eligible; LOW_RISK and SKIPPED are not).

### Batch endpoint (`routes.py` + UI)

- `scan-unverified` accepts targets `{"all", "high", "medium",
  "low_risk", "priority"}`.
- `"priority"` is kept as a backwards-compatible alias for
  `"high" + "medium"` (the union of priority-tier files) so already-loaded
  UIs continue to work after the upgrade.
- The UI's filter pills and the batch-button label update to use the new
  targets (`Upload and scan all high priority` / `… medium priority`).
  The global "Upload and scan all unverified" still sends `target=all`.
- `_is_unresolved_scan_candidate` is unchanged. Only the target filter
  changes.

## Backwards compatibility

| Surface | Old value | Loading behavior post-upgrade |
|---|---|---|
| `RiskTier.PRIORITY` enum value | `"priority"` | Replaced by `HIGH`/`MEDIUM`. Loading code maps legacy `"priority"` to `HIGH` (worst-case) via `risk_tier_for_legacy_bucket`. |
| Persisted `scan.db` `FileResult.outcome_reason` | unchanged | N/A |
| Online cache (`cache.db`) | keyed by `(engine_id, sha256)`, no tier | N/A — a hash lookup result is engine output, not classification; the tier is recomputed from the file's classification on the next scan. |
| v1/v2 JSON/CSV exports in `reports.db` | `classification_bucket` only, no `risk_tier` | Read path uses `risk_tier_for_legacy_bucket(bucket)` when `risk_tier` is absent. New exports write `risk_tier`. |
| `/scan-unverified` `target="priority"` | scanned all priority files | Treated as `high ∪ medium`. Existing UIs stop sending `priority` once reloaded. |

No migration runs at startup. Stored classifications are not rewritten —
re-scan (or `--refresh`) refreshes previously affected files.

## Spec & doc updates

- `docs/superpowers/specs/2026-06-22-risk-prioritized-scan-and-on-demand-upload-design.md`:
  - Replace the `PRIORITY` / `LOW_RISK` tier table with `HIGH` / `MEDIUM` /
    `LOW_RISK` / `SKIPPED`.
  - Add the "OS-shell-runnable vs runtime-required" rule.
  - Add the `matching.default_bucket` invariant: "the classifier's
    unmatched-file fallback MUST honor `matching.default_bucket`".
  - Update the `upload_candidate.extensions` example to the split
    `high_extensions` / `medium_extensions`.
- `CLAUDE.md` "Consistency anchors":
  - "Classification buckets → Risk labels → Report categories" gains a
    fourth column "Risk tier".
- `2026-08-12-needs-attention-prioritization-design.md`: update to reflect
  three pills (All / High / Medium / Lower risk) instead of two.

## Tests

- `tests/test_classifier.py`:
  - Default-fallback: unrecognized extension (`.json`) with
    `default_bucket=hash_only` → `HASH_ONLY` / `LOW_RISK` (regression).
  - HIGH extension match → `UPLOAD_CANDIDATE` / `HIGH`.
  - MEDIUM extension match → `UPLOAD_CANDIDATE` / `MEDIUM`.
  - `executable_bit` set with unrecognized extension → `UPLOAD_CANDIDATE` /
    `HIGH` (worst-case).
  - ELF / shebang promotion → `UPLOAD_CANDIDATE` / `HIGH`.
  - `.pak` + executable markers suspicious-block → `SUSPICIOUS_UPLOAD_BLOCKED`
    / `MEDIUM`.
  - Oversized `.sh` (high ext) → `SUSPICIOUS_UPLOAD_BLOCKED` / `HIGH`.
  - Oversized `.rpy` (medium ext) → `SUSPICIOUS_UPLOAD_BLOCKED` / `MEDIUM`.
- `tests/test_report_view.py` (new or extended):
  - Three risk groups render in `high` / `medium` / `low_risk` order.
  - High group open by default; medium / low_risk collapsed.
  - Pills and chips arrays match.
- `tests/test_scanner.py`:
  - HIGH files are scheduled before MEDIUM files (assert ordering of a
    fixture file list).
  - LOW_RISK bypass unchanged.
  - `/files/{index}/scan` accepts HIGH + MEDIUM, rejects LOW_RISK +
    SKIPPED.
- `tests/test_web.py`:
  - `scan-unverified` `target=high` scans only high files.
  - `target=priority` scans high ∪ medium (back-compat).
- `tests/test_legacy_report_tier.py` (new):
  - A v2 report payload without `risk_tier` loads with `HIGH` for
    `upload_candidate`/`suspicious_upload_blocked` buckets and `LOW_RISK`
    for `hash_only`.

## Open questions

None — design is complete for task 1.