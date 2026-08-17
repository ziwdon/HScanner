# Priority tier split (HIGH / MEDIUM / LOW_RISK) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the single `PRIORITY` risk tier with `HIGH` / `MEDIUM` / `LOW_RISK` and fix the classifier's unrecognized-extension catch-all so it honors `matching.default_bucket` (stopping `.json` etc. from being misclassified as Priority). Curate the `upload_candidate` and `hash_only` extension lists. Adds three populated risk pills (High / Medium / Lower risk) in the Needs-attention report section, with HIGH files scheduled before MEDIUM in online scans.

**Architecture:** `Classification` gains an explicit `risk_tier` field set at classify-time. The `RiskTier` enum splits `PRIORITY` into `HIGH` + `MEDIUM`. The bucket-alone-derived `risk_tier_for(bucket)` helper is removed; `risk_tier_for_classification(cls)` reads the new field, and `risk_tier_for_legacy_bucket(bucket)` provides one-way back-compat for persisted v1/v2 reports (worst-case maps to `HIGH`). The classifier's final catch-all honors `matching.default_bucket` (default `hash_only`). Policy gains `high_extensions` and `medium_extensions` sub-lists under `upload_candidate` (chosen so no currently-listed extension changes tier). The report view renders three risk groups/pills in `high` → `medium` → `low_risk` order. Scanner sorts HIGH before MEDIUM within the priority set. The batch endpoint accepts `high` / `medium` / `priority` (legacy alias = high ∪ medium) targets.

**Tech Stack:** Python 3.11+, Typer, FastAPI, Jinja2, pytest + pytest-asyncio, Ruff.

## Global Constraints

- venv at `.venv` is canonical — install with `.venv/bin/python -m pip` only (per `CLAUDE.md` Pop!_OS note).
- Test command: `pytest` (with the venv active). Lint: `ruff check .`
- Security invariants from `CLAUDE.md` are non-negotiable: secrets skip, uploads are consented, engine keys never persisted to reports/exports/logs.
- No reclassification of currently-listed extensions: every extension in today's `upload_candidate.extensions` must keep its priority-tier membership (HIGH for OS-shell-runnable, MEDIUM for runtime-required); every extension in today's `hash_only.extensions` stays in `hash_only` (LOW_RISK).
- Persisted reports (JSON/CSV in `reports.db`, online cache) are NOT migrated on startup. Loading code uses `risk_tier_for_legacy_bucket` when `risk_tier` is absent. Re-scan refreshes affected files.

---

## File Structure

Files touched by this plan:

- **Modify** `src/hscanner/models.py` — `RiskTier` split, `Classification.risk_tier` field, remove `risk_tier_for`, add `risk_tier_for_classification` + `risk_tier_for_legacy_bucket`.
- **Modify** `src/hscanner/policy/default_policy.yaml` — split `upload_candidate.extensions` into `high_extensions` / `medium_extensions`; extend `hash_only.extensions` with data/config/markup.
- **Modify** `src/hscanner/classifier.py` — set `risk_tier` on every `Classification` returned; fix the catch-all fallback to honor `matching.default_bucket`; ELF/shebang promotion → `HIGH`; `_matches_executable_marker_block` returns tier of the rule.
- **Modify** `src/hscanner/scanner.py:340-356, 380-382, 597, 672` — read `classification.risk_tier` via the new helper; sort HIGH before MEDIUM; per-file scan eligibility uses `{HIGH, MEDIUM}`.
- **Modify** `src/hscanner/report.py:115-149, 217-249, 252-288, 501-551` — `ReportFile` gains `risk_tier: str`; serialize and deserialize (default to legacy mapping when absent).
- **Modify** `src/hscanner/exporters.py:55-130` — include `risk_tier` in JSON/CSV columns (after `classification_reason`).
- **Modify** `src/hscanner/report_view.py:4, 103-117, 120-138, 141-163, 220-242` — three-group meta; read `risk_tier` from file view; new pills/chips; `tier_key_for_classification` replacement.
- **Modify** `src/hscanner/web/routes.py:38-50, 577-620, 680-740, 855-861, 907-913` — import new helpers; `_clone_result_for_report_file` and `_error_result_for_report_file` carry `risk_tier`; batch `target` accepts `high`/`medium`/`priority`/`low_risk`.
- **Modify** `src/hscanner/web/templates/report.html:85, 127, 141-154, 228-232` — pills/chips render High/Medium/Lower risk; auto-open `data-group="high"`; SSE payload reads `risk_tier`.
- **Update tests:** `tests/test_models_risk_tier.py` (rewrite for new tiers), `tests/test_classifier.py` (add tier assertions), `tests/test_classifier_signals.py` (ELF → HIGH), `tests/test_report_view_grouping.py` (three groups), `tests/test_web.py` (batch `target=high` / `target=priority`). New tests: `tests/test_legacy_report_tier.py`, `tests/test_classifier_fallback_default_bucket.py`, `tests/test_classifier_tier_split.py`.
- **Modify** `docs/superpowers/specs/2026-06-22-risk-prioritized-scan-and-on-demand-upload-design.md`, `docs/superpowers/specs/2026-08-12-needs-attention-prioritization-design.md`, `CLAUDE.md` — reflect the new tier taxonomy.

---

## Task 1: Risk tier model

Extend `RiskTier` with HIGH and MEDIUM, remove the single-tier helper, and add the two replacement helpers. No callers change yet — that happens in later tasks. This task lands the data model on its own because every later task depends on the names and shapes defined here.

**Files:**
- Modify: `src/hscanner/models.py:9-33`
- Test: `tests/test_models_risk_tier.py`

**Interfaces:**
- Produces: `RiskTier.HIGH`, `RiskTier.MEDIUM`, `RiskTier.LOW_RISK`, `RiskTier.SKIPPED` (all `StrEnum`).
- Produces: `Classification.risk_tier: RiskTier` field (default `RiskTier.LOW_RISK` to keep the dataclass usable while callers migrate; classifiers always set it explicitly).
- Produces: `risk_tier_for_classification(cls: Classification) -> RiskTier` — returns `cls.risk_tier`.
- Produces: `risk_tier_for_legacy_bucket(bucket: ClassificationBucket) -> RiskTier` — `UPLOAD_CANDIDATE` / `SUSPICIOUS_UPLOAD_BLOCKED` → `HIGH`; `SKIPPED` → `SKIPPED`; otherwise `LOW_RISK`.
- Removes: `risk_tier_for`, `_PRIORITY_BUCKETS`.

- [ ] **Step 1: Write the failing tests**

Replace `tests/test_models_risk_tier.py` with:

```python
from hscanner.models import (
    Classification,
    ClassificationBucket as B,
    RiskTier,
    risk_tier_for_classification,
    risk_tier_for_legacy_bucket,
)


def test_risk_tier_enum_has_four_members():
    assert {t.value for t in RiskTier} == {"high", "medium", "low_risk", "skipped"}


def test_classification_carries_risk_tier_field():
    cls = Classification(
        bucket=B.HASH_ONLY, reason="x", upload_eligible=False, hash_eligible=True,
        risk_tier=RiskTier.LOW_RISK,
    )
    assert cls.risk_tier == RiskTier.LOW_RISK


def test_risk_tier_for_classification_reads_field():
    cls = Classification(
        bucket=B.UPLOAD_CANDIDATE, reason="x", upload_eligible=True, hash_eligible=True,
        risk_tier=RiskTier.HIGH,
    )
    assert risk_tier_for_classification(cls) == RiskTier.HIGH


def test_classification_default_risk_tier_is_low_risk():
    cls = Classification(
        bucket=B.HASH_ONLY, reason="x", upload_eligible=False, hash_eligible=True,
    )
    assert cls.risk_tier == RiskTier.LOW_RISK


def test_risk_tier_for_legacy_bucket_maps_priority_buckets_to_high():
    assert risk_tier_for_legacy_bucket(B.UPLOAD_CANDIDATE) == RiskTier.HIGH
    assert risk_tier_for_legacy_bucket(B.SUSPICIOUS_UPLOAD_BLOCKED) == RiskTier.HIGH


def test_risk_tier_for_legacy_bucket_maps_hash_only_to_low_risk():
    assert risk_tier_for_legacy_bucket(B.HASH_ONLY) == RiskTier.LOW_RISK


def test_risk_tier_for_legacy_bucket_maps_skipped_to_skipped():
    assert risk_tier_for_legacy_bucket(B.SKIPPED) == RiskTier.SKIPPED
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_models_risk_tier.py -v`
Expected: FAIL — `RiskTier.PRIORITY` missing, `risk_tier_for_classification`/`risk_tier_for_legacy_bucket` undefined, `Classification.risk_tier` absent.

- [ ] **Step 3: Implement the model**

Replace `src/hscanner/models.py:9-33` with:

```python
class ClassificationBucket(StrEnum):
    SKIPPED = "skipped"
    HASH_ONLY = "hash_only"
    UPLOAD_CANDIDATE = "upload_candidate"
    SUSPICIOUS_UPLOAD_BLOCKED = "suspicious_upload_blocked"


class RiskTier(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW_RISK = "low_risk"
    SKIPPED = "skipped"


def risk_tier_for_classification(cls: "Classification") -> RiskTier:
    return cls.risk_tier


def risk_tier_for_legacy_bucket(bucket: "ClassificationBucket") -> RiskTier:
    if bucket in {ClassificationBucket.UPLOAD_CANDIDATE, ClassificationBucket.SUSPICIOUS_UPLOAD_BLOCKED}:
        return RiskTier.HIGH
    if bucket == ClassificationBucket.SKIPPED:
        return RiskTier.SKIPPED
    return RiskTier.LOW_RISK
```

Replace the `Classification` dataclass (currently `models.py:142-149`) with:

```python
@dataclass
class Classification:
    bucket: ClassificationBucket
    reason: str
    upload_eligible: bool
    hash_eligible: bool
    suspicious: bool = False
    skip_reason: OutcomeReason | None = None
    risk_tier: RiskTier = RiskTier.LOW_RISK
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/test_models_risk_tier.py -v`
Expected: all PASS (the classifier-tier assertions are deferred to Task 3's own test file).

- [ ] **Step 5: Commit**

```bash
git add src/hscanner/models.py tests/test_models_risk_tier.py
git commit -m "Model: split RiskTier into HIGH/MEDIUM/LOW_RISK

Replaces the single PRIORITY tier with HIGH + MEDIUM, adds an explicit
Classification.risk_tier field (default LOW_RISK so the dataclass stays
back-compat-safe), and introduces risk_tier_for_classification plus
risk_tier_for_legacy_bucket (worst-case HIGH for legacy buckets).
No callers migrate yet — that happens in subsequent tasks."
```

---

## Task 2: Policy extension lists

Split the existing `upload_candidate.extensions` list into `high_extensions` and `medium_extensions`, choosing each existing extension's tier by the "OS-shell-runnable vs runtime-required" rule so no currently-listed extension changes tier. Extend `hash_only.extensions` with data/config/markup types.

**Files:**
- Modify: `src/hscanner/policy/default_policy.yaml:38-53`
- Test: `tests/test_policy_tier_lists.py`

**Interfaces:**
- Produces: `policy["buckets"]["upload_candidate"]` now contains `high_extensions: list[str]` and `medium_extensions: list[str]` (existing key `extensions` is removed).
- Produces: `policy["buckets"]["hash_only"]["extensions"]` extended with `.json`, `.xml`, `.csv`, `.tsv`, `.yaml`, `.yml`, `.toml`, `.ini`, `.cfg`, `.conf`, `.lock`, `.map`, `.html`, `.htm`, `.css`, `.sql`, `.graphql`, `.proto`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_policy_tier_lists.py`:

```python
from hscanner.policy.loader import load_default_policy

EXISTING_PRIORITY_EXT = {
    ".sh", ".bash", ".zsh", ".py", ".pyc", ".pyd", ".rpy", ".rpym", ".rpyc",
    ".rpymc", ".rpyb", ".rpa", ".pl", ".rb", ".js", ".jar",
    ".so", ".bin", ".appimage", ".deb", ".rpm", ".run", ".exe", ".dll", ".msi",
    ".scr", ".bat", ".cmd", ".ps1", ".com", ".vbs", ".wsf", ".lnk",
}
EXISTING_HASH_ONLY_EXT = {
    ".pdf", ".docx", ".xlsx", ".mp4", ".mkv", ".png", ".jpg", ".jpeg", ".ogg",
    ".wav", ".svg", ".ttf", ".otf", ".ttc",
    ".pak", ".vpk", ".bundle", ".asset", ".ucas", ".utoc",
}
HIGH_EXT = {
    ".exe", ".dll", ".so", ".bin", ".appimage", ".deb", ".rpm", ".msi", ".run",
    ".scr", ".com", ".lnk",
    ".sh", ".bash", ".zsh", ".bat", ".cmd", ".ps1", ".vbs", ".wsf",
}
MEDIUM_EXT = {
    ".py", ".pyc", ".pyd", ".rpy", ".rpym", ".rpyc", ".rpymc", ".rpyb", ".rpa",
    ".pl", ".rb", ".js", ".jar",
}
NEW_HASH_ONLY_EXT = {
    ".json", ".xml", ".csv", ".tsv", ".yaml", ".yml", ".toml", ".ini", ".cfg",
    ".conf", ".lock", ".map", ".html", ".htm", ".css",
    ".sql", ".graphql", ".proto",
}


def test_every_existing_priority_extension_stays_priority():
    policy = load_default_policy()
    high = {e.lower() for e in policy["buckets"]["upload_candidate"]["high_extensions"]}
    medium = {e.lower() for e in policy["buckets"]["upload_candidate"]["medium_extensions"]}
    actual_priority = high | medium
    assert EXISTING_PRIORITY_EXT <= actual_priority


def test_priority_extensions_are_split_into_high_and_medium_only():
    policy = load_default_policy()
    high = {e.lower() for e in policy["buckets"]["upload_candidate"]["high_extensions"]}
    medium = {e.lower() for e in policy["buckets"]["upload_candidate"]["medium_extensions"]}
    assert high | medium == EXISTING_PRIORITY_EXT
    assert high & medium == set()


def test_high_set_contains_only_os_shell_runnable():
    policy = load_default_policy()
    high = {e.lower() for e in policy["buckets"]["upload_candidate"]["high_extensions"]}
    assert high == HIGH_EXT


def test_medium_set_contains_only_runtime_required():
    policy = load_default_policy()
    medium = {e.lower() for e in policy["buckets"]["upload_candidate"]["medium_extensions"]}
    assert medium == MEDIUM_EXT


def test_legacy_extensions_key_is_absent():
    policy = load_default_policy()
    assert "extensions" not in policy["buckets"]["upload_candidate"]


def test_hash_only_keeps_existing_entries():
    policy = load_default_policy()
    actual = {e.lower() for e in policy["buckets"]["hash_only"]["extensions"]}
    assert EXISTING_HASH_ONLY_EXT <= actual


def test_hash_only_gains_new_data_config_markup_entries():
    policy = load_default_policy()
    actual = {e.lower() for e in policy["buckets"]["hash_only"]["extensions"]}
    assert NEW_HASH_ONLY_EXT <= actual


def test_hash_only_extension_lists_are_disjoint_from_priority():
    policy = load_default_policy()
    actual_hash = {e.lower() for e in policy["buckets"]["hash_only"]["extensions"]}
    high = {e.lower() for e in policy["buckets"]["upload_candidate"]["high_extensions"]}
    medium = {e.lower() for e in policy["buckets"]["upload_candidate"]["medium_extensions"]}
    assert (actual_hash & (high | medium)) == set()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_policy_tier_lists.py -v`
Expected: FAIL — `high_extensions`/`medium_extensions` keys missing; the `extensions` key still present under `upload_candidate`; new `hash_only` entries absent.

- [ ] **Step 3: Modify the policy**

Open `src/hscanner/policy/default_policy.yaml`. Replace lines 38-53 with:

```yaml
  hash_only:
    extensions:
      [".pdf", ".docx", ".xlsx", ".mp4", ".mkv", ".png", ".jpg", ".jpeg", ".ogg", ".wav",
       ".svg", ".ttf", ".otf", ".ttc",
       ".pak", ".vpk", ".bundle", ".asset", ".ucas", ".utoc",
       ".json", ".xml", ".csv", ".tsv", ".yaml", ".yml", ".toml", ".ini",
       ".cfg", ".conf", ".lock", ".map", ".html", ".htm", ".css",
       ".sql", ".graphql", ".proto"]
    reason: "hash-only by default"

  upload_candidate:
    high_extensions:
      [".exe", ".dll", ".so", ".bin", ".appimage", ".deb", ".rpm", ".msi", ".run",
       ".scr", ".com", ".lnk",
       ".sh", ".bash", ".zsh", ".bat", ".cmd", ".ps1", ".vbs", ".wsf"]
    medium_extensions:
      [".py", ".pyc", ".pyd", ".rpy", ".rpym", ".rpyc", ".rpymc", ".rpyb", ".rpa",
       ".pl", ".rb", ".js", ".jar"]
    executable_bit: true
    elf_magic: true
    shebang: true
    reason: "executable, package, or script"

  suspicious_upload_blocked:
    rules:
      - extension: ".pak"
        executable_markers: true
        reason: "large game bundle with executable markers"
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/test_policy_tier_lists.py -v`
Expected: all PASS.

Now also run the existing priority-ext test that depended on the old shape — it will fail (expected; we fix it in Task 3). For now, note this and continue.

Run: `pytest tests/test_classifier_priority_ext.py -v`
Expected: FAIL — `_record("a.exe")` etc still pass through `_is_upload_like` which only sees `extensions` (no longer present). This is the next task's job.

- [ ] **Step 5: Commit**

```bash
git add src/hscanner/policy/default_policy.yaml tests/test_policy_tier_lists.py
git commit -m "Policy: split upload_candidate.extensions into HIGH and MEDIUM

Splits the existing upload_candidate extension list along the
OS-shell-runnable (HIGH) vs runtime-required (MEDIUM) axis. Existing
extension membership is preserved (no currently-PRIORITY extension
moves tier). Extends hash_only.extensions with common data/config/
markup extensions (json/xml/csv/yaml/css/html/csv/...) so the
classifier's catch-all fallback (Task 3) routes them to LOW_RISK."
```

---

## Task 3: Classifier — tier assignment + default-bucket fallback

The classifier now sets `risk_tier` on every `Classification` it returns, chooses HIGH/MEDIUM based on which `upload_candidate` sub-list matched (with executable-bit/ELF/shebang → HIGH as the worst-case signal), promotes ELF/shebang HASH_ONLY files to HIGH, and honors `matching.default_bucket` in the final catch-all fallback.

**Files:**
- Modify: `src/hscanner/classifier.py:11-107, 142-156, 171-199`
- Test: `tests/test_classifier_tier_split.py` (new), `tests/test_classifier_fallback_default_bucket.py` (new), `tests/test_classifier_priority_ext.py` (modify), `tests/test_classifier_signals.py` (modify), `tests/test_models_risk_tier.py` (already written in Task 1; the classifier assertions should now pass).

**Interfaces:**
- Produces: `classify_file(record, policy)` returns a `Classification` whose `risk_tier` is one of `HIGH` / `MEDIUM` / `LOW_RISK` / `SKIPPED`.
- Produces: `_is_upload_like(record, ext, rule)` now returns `tuple[bool, str | None]` — `(matched, tier_key)` where `tier_key ∈ {"high", "medium", None}`. Callers use `tier_key` to set the `Classification.risk_tier`.
- Produces: `reclassify_with_signals(record, classification, prefix, policy)` returns a `Classification` with `risk_tier=HIGH` when promoting ELF/shebang into `UPLOAD_CANDIDATE`.
- Produces: `_matches_executable_marker_block(record, signals, policy)` returns `RiskTier | None` — the suspicious-block tier (`MEDIUM` for the existing `.pak` rule), or `None` when no block matches.
- Produces: the catch-all fallback at the end of `classify_file` honors `policy["matching"]["default_bucket"]`. When `default_bucket == "hash_only"` (the default), an unrecognized regular file under both size limits returns `Classification(bucket=HASH_ONLY, risk_tier=LOW_RISK)` and does NOT carry `suspicious=True`.

- [ ] **Step 1: Write the failing tier-split tests**

Create `tests/test_classifier_tier_split.py`:

```python
from pathlib import Path

from hscanner.classifier import classify_file
from hscanner.models import ClassificationBucket, FileRecord, RiskTier
from hscanner.policy.loader import load_default_policy


def _record(name: str, size: int = 10, mode: int = 0o100644) -> FileRecord:
    return FileRecord(
        root=Path("/scan"), path=Path("/scan") / name,
        size=size, mtime_ns=1, mode=mode,
        is_symlink=False, is_regular=True, is_hidden=name.startswith("."),
    )


def test_high_extension_match_is_high():
    policy = load_default_policy()
    for name in ("a.exe", "a.dll", "a.so", "a.bin", "a.appimage", "a.deb", "a.rpm",
                 "a.msi", "a.run", "a.scr", "a.com", "a.lnk",
                 "a.sh", "a.bash", "a.zsh", "a.bat", "a.cmd", "a.ps1",
                 "a.vbs", "a.wsf"):
        c = classify_file(_record(name), policy)
        assert c.bucket == ClassificationBucket.UPLOAD_CANDIDATE, name
        assert c.risk_tier == RiskTier.HIGH, name
        assert c.upload_eligible is True, name


def test_medium_extension_match_is_medium():
    policy = load_default_policy()
    for name in ("a.py", "a.pyc", "a.pyd", "a.rpy", "a.rpym", "a.rpyc",
                 "a.rpymc", "a.rpyb", "a.rpa",
                 "a.pl", "a.rb", "a.js", "a.jar"):
        c = classify_file(_record(name), policy)
        assert c.bucket == ClassificationBucket.UPLOAD_CANDIDATE, name
        assert c.risk_tier == RiskTier.MEDIUM, name
        assert c.upload_eligible is True, name


def test_executable_bit_on_unknown_extension_is_high():
    policy = load_default_policy()
    c = classify_file(_record("weird.xyz", mode=0o100755), policy)
    assert c.bucket == ClassificationBucket.UPLOAD_CANDIDATE
    assert c.risk_tier == RiskTier.HIGH
    assert c.upload_eligible is True


def test_sensitive_pattern_wins_and_is_skipped_tier():
    policy = load_default_policy()
    c = classify_file(_record(".env"), policy)
    assert c.bucket == ClassificationBucket.SKIPPED
    assert c.risk_tier == RiskTier.SKIPPED


def test_low_risk_skip_extension_is_skipped_tier():
    policy = load_default_policy()
    c = classify_file(_record("readme.txt"), policy)
    assert c.bucket == ClassificationBucket.SKIPPED
    assert c.risk_tier == RiskTier.SKIPPED


def test_hash_only_extension_is_low_risk_tier():
    policy = load_default_policy()
    for name in ("a.pdf", "a.mp4", "a.png", "a.json", "a.xml", "a.yaml",
                 "a.toml", "a.html", "a.css", "a.sql"):
        c = classify_file(_record(name), policy)
        assert c.bucket == ClassificationBucket.HASH_ONLY, name
        assert c.risk_tier == RiskTier.LOW_RISK, name


def test_oversized_high_extension_is_high_suspicious_blocked():
    policy = load_default_policy()
    size = policy["size_limits"]["large_upload_soft_block_mb"] * 1024 * 1024 + 1
    c = classify_file(_record("big.sh", size=size), policy)
    assert c.bucket == ClassificationBucket.SUSPICIOUS_UPLOAD_BLOCKED
    assert c.risk_tier == RiskTier.HIGH
    assert c.upload_eligible is False
    assert c.hash_eligible is True


def test_oversized_medium_extension_is_medium_suspicious_blocked():
    policy = load_default_policy()
    size = policy["size_limits"]["large_upload_soft_block_mb"] * 1024 * 1024 + 1
    c = classify_file(_record("big.py", size=size), policy)
    assert c.bucket == ClassificationBucket.SUSPICIOUS_UPLOAD_BLOCKED
    assert c.risk_tier == RiskTier.MEDIUM
    assert c.upload_eligible is False
    assert c.hash_eligible is True
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_classifier_tier_split.py -v`
Expected: all FAIL — the classifier doesn't set `risk_tier` and `_is_upload_like` no longer works against the split lists.

- [ ] **Step 3: Write the failing fallback tests**

Create `tests/test_classifier_fallback_default_bucket.py`:

```python
from pathlib import Path

from hscanner.classifier import classify_file
from hscanner.models import ClassificationBucket, FileRecord, RiskTier
from hscanner.policy.loader import load_default_policy


def _record(name: str) -> FileRecord:
    return FileRecord(
        root=Path("/scan"), path=Path("/scan") / name,
        size=10, mtime_ns=1, mode=0o100644,
        is_symlink=False, is_regular=True, is_hidden=False,
    )


def test_unrecognized_extension_falls_back_to_hash_only_low_risk():
    """The catch-all MUST honor matching.default_bucket (default hash_only)."""
    policy = load_default_policy()
    c = classify_file(_record("data.unknownext"), policy)
    assert c.bucket == ClassificationBucket.HASH_ONLY
    assert c.risk_tier == RiskTier.LOW_RISK
    assert c.upload_eligible is False
    assert c.hash_eligible is True
    assert c.suspicious is False


def test_explicit_default_bucket_upload_candidate_changes_fallback():
    policy = load_default_policy()
    policy = {**policy, "matching": {**policy["matching"], "default_bucket": "upload_candidate"}}
    c = classify_file(_record("data.unknownext"), policy)
    assert c.bucket == ClassificationBucket.UPLOAD_CANDIDATE
    # An unrecognized extension with no executable bit falls back to HIGH
    # (worst-case for unknown upload-candidate default).
    assert c.risk_tier == RiskTier.HIGH
    assert c.upload_eligible is True


def test_unrecognized_oversized_file_is_high_suspicious_blocked():
    policy = load_default_policy()
    size = policy["size_limits"]["large_upload_soft_block_mb"] * 1024 * 1024 + 1
    record = FileRecord(
        root=Path("/scan"), path=Path("/scan") / "blob.unknownext",
        size=size, mtime_ns=1, mode=0o100644,
        is_symlink=False, is_regular=True, is_hidden=False,
    )
    c = classify_file(record, policy)
    assert c.bucket == ClassificationBucket.SUSPICIOUS_UPLOAD_BLOCKED
    assert c.risk_tier == RiskTier.HIGH
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `pytest tests/test_classifier_fallback_default_bucket.py -v`
Expected: all FAIL — current catch-all returns `UPLOAD_CANDIDATE` regardless of `default_bucket`.

- [ ] **Step 5: Update the classifier**

Open `src/hscanner/classifier.py`. Replace the whole `classify_file` body through line 107 with:

```python
def classify_file(record: FileRecord, policy: dict[str, Any]) -> Classification:
    if record.is_symlink or not record.is_regular:
        return Classification(
            bucket=ClassificationBucket.SKIPPED,
            reason="non-regular file or symlink",
            upload_eligible=False,
            hash_eligible=False,
            skip_reason=OutcomeReason.UNSUPPORTED_FILE,
            risk_tier=RiskTier.SKIPPED,
        )

    basename = record.path.name
    match_basename = basename.lower()
    ext = _extension(record.path).lower()
    buckets = policy["buckets"]

    if _matches_rule(match_basename, ext, buckets["sensitive"]):
        return Classification(
            bucket=ClassificationBucket.SKIPPED,
            reason=f"sensitive pattern matched: {basename}",
            upload_eligible=False,
            hash_eligible=False,
            skip_reason=OutcomeReason.SENSITIVE,
            risk_tier=RiskTier.SKIPPED,
        )

    if _matches_rule(match_basename, ext, buckets["skipped"]):
        return Classification(
            bucket=ClassificationBucket.SKIPPED,
            reason=f"low-risk skipped pattern matched: {basename}",
            upload_eligible=False,
            hash_eligible=False,
            skip_reason=OutcomeReason.LOW_RISK,
            risk_tier=RiskTier.SKIPPED,
        )

    soft_limit = policy["size_limits"]["large_upload_soft_block_mb"] * 1024 * 1024
    absolute_limit = policy["size_limits"]["absolute_upload_block_mb"] * 1024 * 1024
    matched, tier_key = _is_upload_like(record, ext, buckets["upload_candidate"])
    upload_like_tier = _tier_from_key(tier_key) if matched else None

    if record.size > absolute_limit and matched:
        return _suspicious_blocked(
            "file exceeds absolute upload block",
            tier=upload_like_tier or RiskTier.HIGH,
        )
    if record.size > soft_limit and matched:
        return _suspicious_blocked(
            "file exceeds soft upload block",
            tier=upload_like_tier or RiskTier.HIGH,
        )

    suspicious_tier = _matches_executable_marker_block(record, ext, buckets["suspicious_upload_blocked"])
    if suspicious_tier is not None:
        return _suspicious_blocked(
            "suspicious upload-blocked rule matched",
            tier=suspicious_tier,
        )

    if matched:
        return Classification(
            bucket=ClassificationBucket.UPLOAD_CANDIDATE,
            reason=buckets["upload_candidate"]["reason"],
            upload_eligible=True,
            hash_eligible=True,
            suspicious=True,
            risk_tier=upload_like_tier or RiskTier.HIGH,
        )

    if ext in _normalized_extensions(buckets["hash_only"].get("extensions", [])):
        return Classification(
            bucket=ClassificationBucket.HASH_ONLY,
            reason=buckets["hash_only"]["reason"],
            upload_eligible=False,
            hash_eligible=True,
            risk_tier=RiskTier.LOW_RISK,
        )

    if record.size > soft_limit or record.size > absolute_limit:
        return _suspicious_blocked(
            "unknown file type exceeds upload size limit",
            tier=RiskTier.HIGH,
        )

    default_bucket = str(policy.get("matching", {}).get("default_bucket", "hash_only")).lower()
    if default_bucket == "upload_candidate":
        return Classification(
            bucket=ClassificationBucket.UPLOAD_CANDIDATE,
            reason="default fallback upload candidate",
            upload_eligible=True,
            hash_eligible=True,
            suspicious=True,
            risk_tier=RiskTier.HIGH,
        )
    return Classification(
        bucket=ClassificationBucket.HASH_ONLY,
        reason="default fallback hash-only",
        upload_eligible=False,
        hash_eligible=True,
        risk_tier=RiskTier.LOW_RISK,
    )


def _suspicious_blocked(reason: str, *, tier: RiskTier) -> Classification:
    return Classification(
        bucket=ClassificationBucket.SUSPICIOUS_UPLOAD_BLOCKED,
        reason=reason,
        upload_eligible=False,
        hash_eligible=True,
        suspicious=True,
        risk_tier=tier,
    )


def _tier_from_key(key: str | None) -> RiskTier:
    return RiskTier.HIGH if key == "high" else RiskTier.MEDIUM
```

Replace `_is_upload_like` (currently `classifier.py:126-130`):

```python
def _is_upload_like(
    record: FileRecord, ext: str, rule: dict[str, Any]
) -> tuple[bool, str | None]:
    high = _normalized_extensions(rule.get("high_extensions", []))
    medium = _normalized_extensions(rule.get("medium_extensions", []))
    if ext in high:
        return True, "high"
    if ext in medium:
        return True, "medium"
    executable_bits = 0o111
    if rule.get("executable_bit") and (record.mode & executable_bits):
        return True, "high"
    return False, None
```

Replace `_matches_suspicious_block` (currently returns `bool`) with a tier-returning variant. This function inspects oversize rules only (`min_size_mb`); the `executable_markers` branch lives separately in `_matches_executable_marker_block` because that fire requires reading actual ELF/shebang magic bytes via `reclassify_with_signals`:

```python
def _matches_suspicious_block(
    record: FileRecord, ext: str, rules: dict[str, Any]
) -> RiskTier | None:
    size_mb = record.size / (1024 * 1024)
    for rule in rules.get("rules", []):
        rule_ext = str(rule.get("extension", "")).lower()
        if rule_ext == ext and size_mb >= rule.get("min_size_mb", float("inf")):
            return _rule_tier(rule)
    return None


def _rule_tier(rule: dict[str, Any]) -> RiskTier:
    # Default: HIGH for oversized rules (worst-case attention for unknown
    # large files). The current default policy has no `min_size_mb` rules,
    # so this is purely future-proof; the `.pak` executable_markers rule
    # is handled by _matches_executable_marker_block, which defaults to
    # MEDIUM.
    tier = str(rule.get("tier", "high")).lower()
    return RiskTier.HIGH if tier == "high" else RiskTier.MEDIUM
```

Replace `_matches_executable_marker_block` (currently returns `bool`). Update its callers — there is only one direct call site, inside `reclassify_with_signals`:

```python
def _matches_executable_marker_block(
    record: FileRecord,
    signals: dict[str, bool],
    policy: dict[str, Any],
) -> RiskTier | None:
    ext = _extension(record.path).lower()
    for rule in policy["buckets"]["suspicious_upload_blocked"].get("rules", []):
        rule_ext = str(rule.get("extension", "")).lower()
        if (
            rule_ext == ext
            and rule.get("executable_markers") is True
            and (signals["elf"] or signals["shebang"])
        ):
            return _rule_tier(rule)
    return None
```

Replace `reclassify_with_signals` (currently `classifier.py:171-199`):

```python
def reclassify_with_signals(
    record: FileRecord, classification: Classification, prefix: bytes, policy: dict[str, Any]
) -> Classification:
    if classification.bucket != ClassificationBucket.HASH_ONLY:
        return classification
    signals = file_signals(prefix, record.mode)
    if not (signals["elf"] or signals["shebang"]):
        return classification
    suspicious_tier = _matches_executable_marker_block(record, signals, policy)
    if suspicious_tier is not None:
        return _suspicious_blocked(
            "executable marker in upload-blocked file type",
            tier=suspicious_tier,
        )
    soft = policy["size_limits"]["large_upload_soft_block_mb"] * 1024 * 1024
    absolute = policy["size_limits"]["absolute_upload_block_mb"] * 1024 * 1024
    if record.size > soft or record.size > absolute:
        return _suspicious_blocked(
            "executable content over upload size limit",
            tier=RiskTier.HIGH,
        )
    return Classification(
        bucket=ClassificationBucket.UPLOAD_CANDIDATE,
        reason="executable content (ELF/shebang) detected",
        upload_eligible=True, hash_eligible=True, suspicious=True,
        risk_tier=RiskTier.HIGH,
    )
```

Add the `RiskTier` import at the top of the file (next to the existing `Classification` import):

```python
from hscanner.models import Classification, ClassificationBucket, FileRecord, OutcomeReason, RiskTier
```

- [ ] **Step 6: Run all classifier-tier tests**

Run: `pytest tests/test_classifier_tier_split.py tests/test_classifier_fallback_default_bucket.py tests/test_models_risk_tier.py -v`
Expected: all PASS (including the two classifier assertions left pending in Task 1).

- [ ] **Step 7: Update and re-run the existing priority-ext and signals tests**

Open `tests/test_classifier_priority_ext.py`. The existing tests assert the bucket only — they should still pass. Add risk-tier assertions to `test_new_windows_and_linux_extensions_are_priority`:

```python
def test_new_windows_and_linux_extensions_are_priority():
    policy = load_default_policy()
    for name in ("a.exe", "a.dll", "a.msi", "a.ps1", "a.bat", "a.pyc", "a.run"):
        c = classify_file(_record(name), policy)
        assert c.bucket == ClassificationBucket.UPLOAD_CANDIDATE, name
        # Those in the HIGH list stay HIGH; .pyc stays MEDIUM.
        from hscanner.models import RiskTier
        high_ext = {".exe", ".dll", ".msi", ".ps1", ".bat", ".run"}
        expected = RiskTier.HIGH if Path(name).suffix.lower() in high_ext else RiskTier.MEDIUM
        assert c.risk_tier == expected, name
```

(Add `from pathlib import Path` at the top if not already present — it is.)

Open `tests/test_classifier_signals.py`. Find the ELF/shebang promotion tests; ensure they assert `risk_tier == RiskTier.HIGH` on the promoted `Classification`. If a test only asserts the bucket today, add the tier assertion alongside it. Specifically, after every `assert c.bucket == ClassificationBucket.UPLOAD_CANDIDATE` line that follows an ELF or shebang promotion, add:

```python
assert c.risk_tier == RiskTier.HIGH
```

Also add (or confirm) a test asserting that when the `.pak` executable-markers rule fires via `reclassify_with_signals` (ELF/shebang magic on a `.pak` file), the result is `SUSPICIOUS_UPLOAD_BLOCKED` with `risk_tier == RiskTier.MEDIUM`. The existing signals test that exercises the `.pak` promotion should gain this tier assertion. If no such test exists, add:

```python
def test_pak_with_shebang_promotes_to_medium_suspicious_blocked():
    from hscanner.classifier import reclassify_with_signals
    from hscanner.policy.loader import load_default_policy
    from pathlib import Path
    from hscanner.models import FileRecord, Classification, ClassificationBucket, RiskTier

    record = FileRecord(
        root=Path("/scan"), path=Path("/scan") / "game.pak",
        size=10, mtime_ns=1, mode=0o100644,
        is_symlink=False, is_regular=True, is_hidden=False,
    )
    base = Classification(
        bucket=ClassificationBucket.HASH_ONLY, reason="hash-only by default",
        upload_eligible=False, hash_eligible=True,
        risk_tier=RiskTier.LOW_RISK,
    )
    shebang_prefix = b"#!/bin/sh\n"
    result = reclassify_with_signals(record, base, shebang_prefix, load_default_policy())
    assert result.bucket == ClassificationBucket.SUSPICIOUS_UPLOAD_BLOCKED
    assert result.risk_tier == RiskTier.MEDIUM
```

Run: `pytest tests/test_classifier_priority_ext.py tests/test_classifier_signals.py -v`
Expected: all PASS.

- [ ] **Step 8: Run the full test suite and fix fallout**

Run: `pytest`
Expected: many failures in scanner/report_view/web tests because they still call `risk_tier_for(bucket)` or compare against `RiskTier.PRIORITY`. These get migrated in Tasks 4–8. Record the count and proceed — the next tasks address each failure.

- [ ] **Step 9: Commit**

```bash
git add src/hscanner/classifier.py tests/test_classifier_tier_split.py \
        tests/test_classifier_fallback_default_bucket.py \
        tests/test_classifier_priority_ext.py tests/test_classifier_signals.py
git commit -m "Classifier: tier-aware classification + default-bucket fallback

classify_file now sets risk_tier on every Classification (HIGH/MEDIUM
for upload_candidate based on the matched sub-list, HIGH for executable
bit / ELF / shebang, MEDIUM for the existing .pak executable-marker rule,
LOW_RISK for hash_only, SKIPPED for sensitive/unsupported). The catch-all
fallback now honors matching.default_bucket (default hash_only) instead
of unconditionally returning UPLOAD_CANDIDATE, fixing the bug where
.json/.xml/etc. were misclassified as Priority. reclassify_with_signals
promotes ELF/shebang to HIGH."
```

---

## Task 4: Report model — `ReportFile.risk_tier`

Persist the new tier on `ReportFile` so the report view and exports carry it. Loading tolerates absence (use the legacy mapping) so old persisted reports still render.

**Files:**
- Modify: `src/hscanner/report.py:115-149` (dataclass), `203-249` (`_report_file`), `252-288` (`_report_file_payload`), `501-551` (`_report_file_from_payload`)
- Test: `tests/test_legacy_report_tier.py` (new), `tests/test_report_payload_roundtrip.py` if it exists (add tier assertions).

**Interfaces:**
- Produces: `ReportFile.risk_tier: str` field. Defaults to `""` (empty string sentinel for "not set") on the dataclass to keep the frozen dataclass back-compat-safe; `risk_tier_for_legacy_bucket` is used when loading encounters the empty string.
- Produces: `_report_file_payload` serializes `risk_tier`.
- Produces: `_report_file_from_payload` reads `risk_tier`; if absent or empty, calls `risk_tier_for_legacy_bucket(ClassificationBucket(classification_bucket))` and uses its `.value`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_legacy_report_tier.py`:

```python
from pathlib import Path

from hscanner.classifier import classify_file
from hscanner.models import FileRecord, FileResult, ReportAction
from hscanner.policy.loader import load_default_policy
from hscanner.report import (
    _report_file,
    _report_file_payload,
    _report_file_from_payload,
)
from hscanner.models import RiskTier


def _record(name: str, size: int = 10, mode: int = 0o100755) -> FileRecord:
    return FileRecord(
        root=Path("/scan"), path=Path("/scan") / name,
        size=size, mtime_ns=1, mode=mode,
        is_symlink=False, is_regular=True, is_hidden=False,
    )


def _file_result(name: str, mode: int = 0o100755) -> FileResult:
    cls = classify_file(_record(name, mode=mode), load_default_policy())
    result = FileResult(record=_record(name, mode=mode), classification=cls)
    result.action = ReportAction.HASHED
    return result


_LEGACY_PAYLOAD_SKELETON = {
    "index": 0, "relative_path": "a", "size": 10, "sha256": None,
    "classification_bucket": "upload_candidate", "classification_reason": "x",
    "hash_eligible": True, "upload_eligible": True, "suspicious": True,
    "outcome": "needs_attention", "outcome_reason": "scan_incomplete",
    "lookup_status": "not_checked", "upload_status": "not_uploaded",
    "risk_label": "unknown", "report_category": "full_inventory",
    "action": "hashed", "engine_state": "not_queried",
    "permalink": None, "engine_counts": {},
    "detection_ratio": {"flagged": 0, "total": 0},
    "detections": [], "last_analysis_at": None,
    "analysis_status": "not_applicable",
    "errors": [], "json_reference": "/files/0/raw_result", "raw_result": None,
    "assessment_complete": False, "executable_bit": False,
    "shebang": False, "elf": False, "engine_id": None,
}


def test_report_payload_serializes_risk_tier_for_high():
    result = _file_result("a.sh")
    rf = _report_file(0, result)
    payload = _report_file_payload(rf)
    assert payload["risk_tier"] == "high"


def test_report_payload_serializes_risk_tier_for_medium():
    result = _file_result("a.py", mode=0o100644)
    rf = _report_file(0, result)
    payload = _report_file_payload(rf)
    assert payload["risk_tier"] == "medium"


def test_report_payload_roundtrips_risk_tier():
    result = _file_result("a.py", mode=0o100644)
    rf = _report_file(0, result)
    payload = _report_file_payload(rf)
    restored = _report_file_from_payload(payload)
    assert restored.risk_tier == "medium"


def test_legacy_payload_without_risk_tier_maps_to_high_for_upload_candidate():
    payload = dict(_LEGACY_PAYLOAD_SKELETON)
    rf = _report_file_from_payload(payload)
    assert rf.risk_tier == "high"


def test_legacy_payload_without_risk_tier_maps_to_low_risk_for_hash_only():
    payload = dict(_LEGACY_PAYLOAD_SKELETON)
    payload["classification_bucket"] = "hash_only"
    rf = _report_file_from_payload(payload)
    assert rf.risk_tier == "low_risk"


def test_legacy_payload_without_risk_tier_maps_to_skipped_for_skipped():
    payload = dict(_LEGACY_PAYLOAD_SKELETON)
    payload["classification_bucket"] = "skipped"
    rf = _report_file_from_payload(payload)
    assert rf.risk_tier == "skipped"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_legacy_report_tier.py -v`
Expected: all FAIL — `ReportFile` lacks `risk_tier`; `_report_file_payload` doesn't serialize it; `_report_file_from_payload` doesn't restore it.

- [ ] **Step 3: Modify `ReportFile` and helpers**

In `src/hscanner/report.py`:

Add to imports (line 11-23 area):

```python
from hscanner.models import (
    ...,
    RiskTier,
    risk_tier_for_legacy_bucket,
)
```

Add a new field to `ReportFile` (after `engine_id: str | None = None`):

```python
    risk_tier: str = ""
```

In `_report_file` (around line 217-249), set the new field from the `Classification`:

```python
    return ReportFile(
        index=index,
        relative_path=result.record.relative_path,
        size=result.record.size,
        sha256=result.sha256,
        classification_bucket=result.classification.bucket.value,
        classification_reason=result.classification.reason,
        risk_tier=result.classification.risk_tier.value,
        hash_eligible=result.classification.hash_eligible,
        upload_eligible=result.classification.upload_eligible,
        suspicious=result.classification.suspicious,
        # ...rest unchanged...
    )
```

In `_report_file_payload`, add `risk_tier` next to `classification_reason`:

```python
        "classification_bucket": file.classification_bucket,
        "classification_reason": file.classification_reason,
        "risk_tier": file.risk_tier,
        "hash_eligible": file.hash_eligible,
```

In `_report_file_from_payload`, restore the tier with legacy fallback:

```python
    risk_tier_raw = str(file.get("risk_tier") or "")
    if not risk_tier_raw:
        risk_tier_raw = risk_tier_for_legacy_bucket(
            ClassificationBucket(str(file["classification_bucket"]))
        ).value
    return ReportFile(
        ...
        classification_bucket=str(file["classification_bucket"]),
        classification_reason=str(file["classification_reason"]),
        risk_tier=risk_tier_raw,
        ...
    )
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/test_legacy_report_tier.py -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/hscanner/report.py tests/test_legacy_report_tier.py
git commit -m "Report: serialize ReportFile.risk_tier with legacy fallback

Adds risk_tier to ReportFile, serializes it in the JSON payload, and
restores it on load with a worst-case HIGH fallback (via
risk_tier_for_legacy_bucket) when the source payload predates the
tier split. Old reports render as HIGH/MEDIUM/LOW_RISK based on
their legacy bucket; re-scan refreshes."
```

---

## Task 5: Exporters — include risk_tier in JSON/CSV

**Files:**
- Modify: `src/hscanner/exporters.py:55-130`
- Test: `tests/test_no_key_persisted.py` (the JSON/CSV key-absence tests already operate on column lists — extend to assert `risk_tier` is present).

**Interfaces:**
- Produces: JSON payload includes `risk_tier` (via the report-payload change from Task 4; no extra exporter work needed beyond the column ordering).
- Produces: CSV gains a `risk_tier` column after `classification_reason`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_exporters_risk_tier.py` (new file):

```python
import io
import csv
import json
from pathlib import Path

from hscanner.classifier import classify_file
from hscanner.exporters import render_csv, render_json
from hscanner.models import FileRecord, FileResult, ReportAction
from hscanner.policy.loader import load_default_policy
from hscanner.report import build_scan_report


def _record(name: str, size: int = 10, mode: int = 0o100755) -> FileRecord:
    return FileRecord(
        root=Path("/scan"), path=Path("/scan") / name,
        size=size, mtime_ns=1, mode=mode,
        is_symlink=False, is_regular=True, is_hidden=False,
    )


def test_csv_has_risk_tier_column_after_classification_reason():
    cls = classify_file(_record("a.sh"), load_default_policy())
    result = FileResult(record=_record("a.sh"), classification=cls)
    result.action = ReportAction.HASHED
    report = build_scan_report(
        root=Path("/scan"), results=[result],
        online=True, upload_consent=False,
        engine_id="virustotal", engine_name="Test",
    )
    text = render_csv(report)
    reader = csv.reader(io.StringIO(text))
    header = next(reader)
    assert "risk_tier" in header
    assert header.index("risk_tier") == header.index("classification_reason") + 1


def test_json_payload_includes_risk_tier_per_file():
    cls = classify_file(_record("a.sh"), load_default_policy())
    result = FileResult(record=_record("a.sh"), classification=cls)
    result.action = ReportAction.HASHED
    report = build_scan_report(
        root=Path("/scan"), results=[result],
        online=True, upload_consent=False,
        engine_id="virustotal", engine_name="Test",
    )
    payload = json.loads(render_json(report))
    assert payload["files"][0]["risk_tier"] == "high"
```

Note: `build_scan_report`'s exact signature — see `report.py`. If it differs, adjust to match its actual call shape (the test should compile against current `report.build_scan_report`).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_exporters_risk_tier.py -v`
Expected: FAIL — CSV column missing, JSON doesn't contain the field yet (until Task 4 is applied; Task 4 already landed, so JSON should pass already).

- [ ] **Step 3: Modify the exporters**

Open `src/hscanner/exporters.py`. Find the CSV column list (around line 60-70). Add `"risk_tier"` immediately after `"classification_reason"`. If the row writer builds the row by key name lookup, no row-side change needed; if it builds by position, add `file.risk_tier` in the matching position.

Confirm `render_json` already serializes via `_report_file_payload` (it does — Task 4 already added `risk_tier` there).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/test_exporters_risk_tier.py tests/test_no_key_persisted.py -v`
Expected: PASS. The key-absence assertions still pass because `risk_tier` carries no secret.

- [ ] **Step 5: Commit**

```bash
git add src/hscanner/exporters.py tests/test_exporters_risk_tier.py
git commit -m "Exporters: add risk_tier to CSV column and JSON files

CSV gains a risk_tier column immediately after classification_reason.
JSON payload carried risk_tier from Task 4; this adds coverage."
```

---

## Task 6: Scanner Core — tier reads + HIGH-before-MEDIUM scheduling

Migrate the scanner's `risk_tier_for(...)` call sites to `risk_tier_for_classification(...)`. Sort HIGH before MEDIUM within the priority set. Per-file scan eligibility uses `{HIGH, MEDIUM}` instead of `!= PRIORITY`.

**Files:**
- Modify: `src/hscanner/scanner.py:32-36` (imports), `340-356` (sort + bypass counts), `380-382` (low-risk bypass branch), `597`, `672` (per-file eligibility).
- Test: `tests/test_scanner_priority_order.py` (new), existing scanner tests should still pass.

**Interfaces:**
- Consumes: `risk_tier_for_classification(cls)` (Task 1).
- Produces: `run_online_scan`'s priority sort key `(tier_rank, relative_path)` where `tier_rank = {HIGH:0, MEDIUM:1, LOW_RISK:2, SKIPPED:3}`.
- Produces: `scan_single_file*` eligibility raises `SingleFileNotEligible("not_priority")` when `risk_tier_for_classification(cls) not in {HIGH, MEDIUM}`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_scanner_priority_order.py`:

```python
from hscanner.models import RiskTier, risk_tier_for_classification


def test_high_ranks_before_medium_before_low_risk_before_skipped():
    order = {
        RiskTier.HIGH: 0,
        RiskTier.MEDIUM: 1,
        RiskTier.LOW_RISK: 2,
        RiskTier.SKIPPED: 3,
    }
    assert order[RiskTier.HIGH] < order[RiskTier.MEDIUM]
    assert order[RiskTier.MEDIUM] < order[RiskTier.LOW_RISK]
    assert order[RiskTier.LOW_RISK] < order[RiskTier.SKIPPED]
```

Drives a real ordering test using the scanner's exposed sort key:

```python
from hscanner.classifier import classify_file
from hscanner.models import FileRecord
from hscanner.policy.loader import load_default_policy
from pathlib import Path


def _record(name: str, mode: int = 0o100644) -> FileRecord:
    return FileRecord(
        root=Path("/scan"), path=Path("/scan") / name,
        size=10, mtime_ns=1, mode=mode,
        is_symlink=False, is_regular=True, is_hidden=False,
    )


def test_priority_sort_key_places_high_before_medium():
    policy = load_default_policy()
    py_cls = classify_file(_record("z.py"), policy)
    sh_cls = classify_file(_record("a.sh"), policy)
    # Mirror the sort key actually used inside run_online_scan.
    order = {RiskTier.HIGH: 0, RiskTier.MEDIUM: 1, RiskTier.LOW_RISK: 2, RiskTier.SKIPPED: 3}
    key_py = (order[risk_tier_for_classification(py_cls)], "z.py")
    key_sh = (order[risk_tier_for_classification(sh_cls)], "a.sh")
    assert key_sh < key_py  # HIGH ahead of MEDIUM even though "a.sh" < "z.py" alphabetically


def test_low_risk_below_high_and_medium():
    policy = load_default_policy()
    pdf_cls = classify_file(_record("a.pdf"), policy)
    order = {RiskTier.HIGH: 0, RiskTier.MEDIUM: 1, RiskTier.LOW_RISK: 2, RiskTier.SKIPPED: 3}
    assert order[risk_tier_for_classification(pdf_cls)] > order[RiskTier.MEDIUM]
    assert order[risk_tier_for_classification(pdf_cls)] > order[RiskTier.HIGH]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_scanner_priority_order.py -v`
Expected: the first test (rank table) should PASS immediately (the table is just constants). The classifier/fixtures all classify correctly post-Task-3, so the second/third tests should already pass too. If they fail, the ordering constant in scanner needs the migration in Step 3.

- [ ] **Step 3: Migrate the scanner**

Open `src/hscanner/scanner.py`. Replace lines 24-37 area (the model imports) — change `risk_tier_for` to `risk_tier_for_classification`:

```python
from hscanner.models import (
    AnalysisStatus,
    ClassificationBucket,
    EngineState,
    FileRecord,
    FileResult,
    LookupStatus,
    OutcomeReason,
    ReportAction,
    RiskLabel,
    RiskTier,
    ScanOutcome,
    ScanStatus,
    UploadStatus,
    risk_tier_for_classification,
)
```

Remove the existing `risk_tier_for` import (no longer defined in models).

Add `_TIER_ORDER` as a module-level constant just below the imports (around line 52, before the first `@dataclass`):

```python
_TIER_ORDER = {
    RiskTier.HIGH: 0,
    RiskTier.MEDIUM: 1,
    RiskTier.LOW_RISK: 2,
    RiskTier.SKIPPED: 3,
}
```

Replace the sort key at lines 340-345 with:

```python
    results.sort(
        key=lambda r: (
            _TIER_ORDER[risk_tier_for_classification(r.classification)],
            r.record.relative_path,
        )
    )
```

Replace the two bypass-count references at lines 350, 356 with:

```python
        if r.sha256 and (
            not bypass_low_risk
            or risk_tier_for_classification(r.classification) != RiskTier.LOW_RISK
        )
```

```python
        if r.sha256 and bypass_low_risk
        and risk_tier_for_classification(r.classification) == RiskTier.LOW_RISK
```

Replace the bypass branch at line 380-382 with:

```python
                if (
                    bypass_low_risk
                    and risk_tier_for_classification(result.classification) == RiskTier.LOW_RISK
                ):
```

Replace the per-file eligibility at lines 597 and 672 with:

```python
    if risk_tier_for_classification(classification) not in {RiskTier.HIGH, RiskTier.MEDIUM}:
        raise SingleFileNotEligible("not_priority")
```

- [ ] **Step 4: Run the new tests + scanner tests**

Run: `pytest tests/test_scanner_priority_order.py tests/test_scanner.py -v`
Expected: PASS.

- [ ] **Step 5: Run the full test suite**

Run: `pytest`
Expected: Remaining failures are in `report_view` and `routes`/`web` tests (Tasks 7-8 address them). Note the count.

- [ ] **Step 6: Commit**

```bash
git add src/hscanner/scanner.py tests/test_scanner_priority_order.py
git commit -m "Scanner: read risk_tier from Classification, HIGH before MEDIUM

Migrates risk_tier_for(bucket) call sites to
risk_tier_for_classification(classification). Within the priority set,
HIGH files are now scheduled before MEDIUM ones so the worst unknowns
complete first. Per-file scan eligibility accepts HIGH + MEDIUM and
rejects LOW_RISK + SKIPPED (behavior unchanged)."
```

---

## Task 7: Report view — three risk groups, new pills

Render three risk groups (`high`, `medium`, `low_risk`) in the Needs-attention section, with `high` auto-open by default. Mirror pills and chips for the same three keys.

**Files:**
- Modify: `src/hscanner/report_view.py:4, 58-100, 103-138, 141-163, 220-242`
- Test: `tests/test_report_view_grouping.py` (modify — fail and fix), `tests/test_report_view_tier_split.py` (new).

**Interfaces:**
- Produces: `_RISK_GROUP_META` now defines `HIGH` / `MEDIUM` / `LOW_RISK` with keys `"high"` / `"medium"` / `"low_risk"`.
- Produces: `build_file_view(file: ReportFile)` adds `"risk_tier": file.risk_tier` to the returned dict.
- Produces: `group_for_file_view(file_view)` reads `file_view["risk_tier"]` for needs-attention; falls back to `risk_tier_for_legacy_bucket` when `file_view["risk_tier"]` is empty.
- Produces: `tier_key_for_classification(cls) -> str | None` (replaces `tier_key_for_bucket`).
- Produces: `tier_key_for_bucket(bucket)` is removed. Callers use `tier_key_for_classification` or fall back via `risk_tier_for_legacy_bucket`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_report_view_tier_split.py`:

```python
from hscanner.report_view import build_report_view, _RISK_GROUP_META
from hscanner.models import RiskTier


def test_risk_group_meta_has_three_groups():
    keys = {m["key"] for m in _RISK_GROUP_META.values()}
    assert keys == {"high", "medium", "low_risk"}


def test_risk_group_order_is_high_medium_low_risk():
    keys = [m["key"] for m in _RISK_GROUP_META.values()]
    assert keys == ["high", "medium", "low_risk"]
```

Now a behavioral test that builds a real `ScanReport`:

```python
from hscanner.classifier import classify_file
from hscanner.models import FileRecord, FileResult, ReportAction, ScanOutcome
from hscanner.policy.loader import load_default_policy
from hscanner.report import build_scan_report
from pathlib import Path


def _record(name: str, mode: int = 0o100644) -> FileRecord:
    return FileRecord(
        root=Path("/scan"), path=Path("/scan") / name,
        size=10, mtime_ns=1, mode=mode,
        is_symlink=False, is_regular=True, is_hidden=False,
    )


def test_needs_attention_renders_high_medium_low_risk_groups():
    policy = load_default_policy()
    files = []
    for name, mode in [("z.py", 0o644), ("a.sh", 0o755), ("data.json", 0o644)]:
        cls = classify_file(_record(name, mode=mode), policy)
        result = FileResult(record=_record(name, mode=mode), classification=cls)
        result.action = ReportAction.HASHED
        result.outcome = ScanOutcome.NEEDS_ATTENTION
        files.append(result)
    report = build_scan_report(
        root=Path("/scan"), results=files,
        online=True, upload_consent=False,
        engine_id="virustotal", engine_name="Test",
    )
    view = build_report_view(report)
    section = next(s for s in view["sections"] if s["outcome"] == "needs_attention")
    group_keys = [g["key"] for g in section["groups"]]
    assert group_keys == ["high", "medium", "low_risk"]
    high_group = next(g for g in section["groups"] if g["key"] == "high")
    medium_group = next(g for g in section["groups"] if g["key"] == "medium")
    low_group = next(g for g in section["groups"] if g["key"] == "low_risk")
    assert high_group["total"] == 1   # a.sh
    assert medium_group["total"] == 1  # z.py
    assert low_group["total"] == 1     # data.json in LOW_RISK — only appears if bypass was off (treat as attention here since we forced outcome)
    chip_keys = [c["key"] for c in section["risk_chips"]]
    assert chip_keys == ["high", "medium", "low_risk"]
    pill_keys = [p["key"] for p in section["filters"]]
    assert pill_keys == ["all", "high", "medium", "low_risk"]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_report_view_tier_split.py -v`
Expected: all FAIL.

- [ ] **Step 3: Modify `report_view.py`**

Replace `_RISK_GROUP_META` (currently lines 103-106):

```python
_RISK_GROUP_META = {
    RiskTier.HIGH.value:     {"key": "high",     "title": "High priority",   "sev": "sev-high"},
    RiskTier.MEDIUM.value:   {"key": "medium",   "title": "Medium priority", "sev": "sev-medium"},
    RiskTier.LOW_RISK.value: {"key": "low_risk", "title": "Lower risk",      "sev": "sev-low"},
}
```

Add the import of `risk_tier_for_legacy_bucket` (and `RiskTier` already imported):

```python
from hscanner.models import ClassificationBucket, RiskTier, risk_tier_for_legacy_bucket
```

Replace `tier_key_for_bucket` with:

```python
def tier_key_for_classification(cls: Classification) -> str | None:
    tier = cls.risk_tier
    meta = _RISK_GROUP_META.get(tier.value)
    return meta["key"] if meta is not None else None


def tier_key_for_bucket(bucket: ClassificationBucket) -> str | None:
    """Legacy-compatible tier key for persisted reports that predate the
    HIGH/MEDIUM split. Reads from the bucket only — use
    tier_key_for_classification for fresh classifications."""
    tier = risk_tier_for_legacy_bucket(bucket)
    meta = _RISK_GROUP_META.get(tier.value)
    return meta["key"] if meta is not None else None
```

(Keep `tier_key_for_bucket` because `routes.py` uses it on `ReportFile.classification_bucket` for legacy reports; it now resolves through `risk_tier_for_legacy_bucket`. Update `routes.py` to prefer `tier_key_for_classification` when a fresh `Classification` is available — Task 8.)

In `build_file_view`, add `risk_tier` to the returned dict. Insert after `"classification_reason"`:

```python
        "classification_reason": file.classification_reason,
        "risk_tier": file.risk_tier,
```

Replace `group_for_file_view`:

```python
def group_for_file_view(file_view: dict[str, Any]) -> dict[str, str] | None:
    outcome = file_view["outcome_key"]
    if outcome == "needs_attention":
        tier_str = file_view.get("risk_tier") or ""
        if not tier_str:
            tier = risk_tier_for_legacy_bucket(ClassificationBucket(file_view["classification_bucket"]))
            tier_str = tier.value
        meta = _RISK_GROUP_META.get(tier_str)
        return {"key": meta["key"], "title": meta["title"]} if meta is not None else None
    if outcome in {"no_detections", "skipped"}:
        ext = file_view["extension"]
        return {"key": ext, "title": "(no extension)" if ext == "" else f".{ext}"}
    return None
```

Replace `_group_needs_attention_by_risk`'s fixed-buckets logic — it should iterate `_RISK_GROUP_META.values()` in source-dict order so the output matches HIGH → MEDIUM → LOW_RISK:

```python
def _group_needs_attention_by_risk(
    files: list[dict[str, Any]], cap: int
) -> list[dict[str, Any]]:
    buckets: dict[str, list[dict[str, Any]]] = {
        meta["key"]: [] for meta in _RISK_GROUP_META.values()
    }
    for file in files:
        group = group_for_file_view(file)
        key = group["key"] if group and group["key"] in buckets else "high"
        buckets[key].append(file)
    groups = []
    for meta in _RISK_GROUP_META.values():
        key = meta["key"]
        group_files = buckets.get(key, [])
        groups.append({
            "key": key,
            "title": meta["title"],
            "files": group_files,
            "total": len(group_files),
            "hidden": 0,
            "subgroups": _group_by_extension(group_files, cap),
        })
    return groups
```

Update the risk chips block in `build_report_view` (around lines 220-242). Change the `"sev"` lookup to read the meta's own `sev`, not the old priority/low_risk switch:

```python
            section["risk_chips"] = [
                {
                    "key": g["key"],
                    "label": g["title"],
                    "count": g["total"],
                    "sev": next(m["sev"] for m in _RISK_GROUP_META.values() if m["key"] == g["key"]),
                }
                for g in risk_groups
            ]
            section["filters"] = [
                {"key": "all", "label": "All", "pressed": True},
                {"key": "high", "label": "High", "pressed": False},
                {"key": "medium", "label": "Medium", "pressed": False},
                {"key": "low_risk", "label": "Lower risk", "pressed": False},
            ]
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/test_report_view_tier_split.py tests/test_report_view_grouping.py -v`
Expected: PASS for tier-split tests; the older `test_report_view_grouping.py` may need updates if it asserts the old two-group shape. Update it: replace `priority`/`low_risk` group expectations with `high`/`medium`/`low_risk` according to the fixtures used.

- [ ] **Step 5: Commit**

```bash
git add src/hscanner/report_view.py tests/test_report_view_tier_split.py tests/test_report_view_grouping.py
git commit -m "Report view: three risk groups (high/medium/low_risk)

build_file_view exposes risk_tier, group_for_file_view reads it (with
legacy-bucket fallback for persisted reports), and the Needs-attention
section renders three groups in HIGH → MEDIUM → LOW_RISK order with
matching chips and pills (All/High/Medium/Lower risk). The open-by-
default group becomes \"high\" (template change follows in the next task)."
```

---

## Task 8: Web routes — propagate risk_tier, batch target accepts high/medium

Migrate `routes.py` to use the new helpers, carry `risk_tier` through `_clone_result_for_report_file` / `_error_result_for_report_file`, and accept `high` / `medium` / `priority` (legacy alias = high ∪ medium) targets in the batch endpoint.

**Files:**
- Modify: `src/hscanner/web/routes.py:38-50, 577-620, 680-740, 855-861, 907-913`
- Test: `tests/test_web_file_scan.py` (modify if needed), `tests/test_web.py` (modify if needed), new `tests/test_web_batch_targets.py`.

**Interfaces:**
- Produces: `scan_unverified` body targets ∈ `{"all", "high", "medium", "low_risk", "priority"}`. `"priority"` is a legacy alias returned by `target_indices = high_indices + medium_indices`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_web_batch_targets.py`:

```python
import pytest
from httpx import AsyncClient
from hscanner.web.app import create_app


@pytest.mark.asyncio
async def test_scan_unverified_rejects_unknown_target(tmp_path):
    app = create_app()
    # Pre-create a report with a keyless store to keep this unit isolated.
    # The endpoint returns 400 for unknown targets before any work runs.
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.post(
            "/reports/any/scan-unverified",
            json={"target": "bogus"},
        )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_scan_unverified_accepts_high_and_medium_and_priority_targets():
    app = create_app()
    async with AsyncClient(app=app, base_url="http://test") as client:
        for target in ("all", "high", "medium", "low_risk", "priority"):
            response = await client.post(
                "/reports/any/scan-unverified",
                json={"target": target},
            )
            # 404/400 is fine; we are asserting the target is not rejected
            # for being unknown.
            assert response.status_code != 400 or (
                response.json().get("error", "").startswith("unknown target") is False
            ), target
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_web_batch_targets.py -v`
Expected: FAIL — `target="high"` / `"medium"` / `"priority"` rejected with 400 "unknown target".

- [ ] **Step 3: Modify `routes.py`**

Open `src/hscanner/web/routes.py`. Replace the import at lines 31-40:

```python
from hscanner.models import (
    Classification,
    ClassificationBucket,
    EngineState,
    FileRecord,
    FileResult,
    ReportAction,
    RiskTier,
    risk_tier_for_classification,
    risk_tier_for_legacy_bucket,
)
```

Replace the import from `report_view` at lines 44-50:

```python
from hscanner.report_view import (
    build_file_view,
    build_report_view,
    group_for_file_view,
    outcome_section_meta,
    tier_key_for_bucket,
    tier_key_for_classification,
)
```

(Keep `tier_key_for_bucket` for now — used for legacy `ReportFile.classification_bucket`.)

Update the per-file scan eligibility gate (lines 615-625 area). Replace the `risk_tier_for(cls.bucket) != RiskTier.PRIORITY` check with:

```python
        if risk_tier_for_classification(cls) not in {RiskTier.HIGH, RiskTier.MEDIUM}:
            return JSONResponse({"reason": "not_priority"}, status_code=400)
```

Update the batch endpoint at lines 692-707:

```python
    target = (body or {}).get("target", "all")
    if target not in {"all", "high", "medium", "low_risk", "priority"}:
        return JSONResponse(
            {"error": f"unknown target: {target}"}, status_code=400,
        )

    indices = [f.index for f in report.files if _is_unresolved_scan_candidate(f)]
    if target != "all":
        def _tier_key_for_report_file(f):
            bucket = ClassificationBucket(f.classification_bucket)
            if f.risk_tier:
                return _RISK_GROUP_META_KEY_BY_TIER.get(
                    RiskTier(f.risk_tier), "high"
                )
            return tier_key_for_bucket(bucket)
        if target == "priority":
            indices = [
                i for i in indices
                if _tier_key_for_report_file(report.files[i]) in {"high", "medium"}
            ]
        else:
            indices = [
                i for i in indices
                if _tier_key_for_report_file(report.files[i]) == target
            ]
```

Add a module-level constant near the top of `routes.py` for the inverse mapping:

```python
_RISK_GROUP_META_KEY_BY_TIER = {
    RiskTier.HIGH.value: "high",
    RiskTier.MEDIUM.value: "medium",
    RiskTier.LOW_RISK.value: "low_risk",
}
```

Update `_clone_result_for_report_file` (lines 854-863) to carry `risk_tier`:

```python
        classification=Classification(
            ClassificationBucket(file.classification_bucket),
            file.classification_reason,
            upload_eligible=file.upload_eligible,
            hash_eligible=file.hash_eligible,
            suspicious=file.suspicious,
            risk_tier=(
                RiskTier(file.risk_tier) if file.risk_tier
                else risk_tier_for_legacy_bucket(ClassificationBucket(file.classification_bucket))
            ),
        ),
```

Apply the same `risk_tier=` argument to `_error_result_for_report_file` (lines 907-913).

Update `build_file_view` payload — the route that renders a per-file update card uses `build_file_view` directly, and Task 7 already adds `risk_tier` to that dict. No additional route change needed for the SSE file update — the payload's `file.risk_tier` flows through `build_file_view`. The single-file SSE payload at the call site that builds `{"file": file_view, ...}` should include `file_view["risk_tier"]` automatically. Search the route for `build_file_view` and confirm the returned dict is what's serialized — no changes required.

- [ ] **Step 4: Run the tests**

Run: `pytest tests/test_web_batch_targets.py tests/test_web_file_scan.py tests/test_web.py -v`
Expected: PASS. If `test_web_file_scan.py` asserts `not_priority` rejection, the new gate still rejects LOW_RISK/SKIPPED files with the same `not_priority` reason, so it should pass unchanged.

- [ ] **Step 5: Commit**

```bash
git add src/hscanner/web/routes.py tests/test_web_batch_targets.py
git commit -m "Routes: accept high/medium/priority/low_risk batch targets

scan-unverified now accepts high, medium, and priority (legacy alias =
high ∪ medium) targets in addition to all and low_risk. _clone_result
and _error_result carry risk_tier from the stored ReportFile, falling
back to risk_tier_for_legacy_bucket when the persisted report predates
the split. The per-file eligibility gate uses HIGH/MEDIUM membership."
```

---

## Task 9: Report template — three pills, auto-open "high"

Update the report template so the Needs-attention "high" group is open by default and the filter pill / batch-button labels know about the new keys.

**Files:**
- Modify: `src/hscanner/web/templates/report.html:85, 127, 141-154, 228-232`

**Interfaces:**
- Produces: template renders pills in the order `all` / `high` / `medium` / `low_risk` driven by `section.filters` (no hardcoding needed). The `details.group[data-group="high"]` is `open` by default; medium / low_risk collapse.
- Produces: the JS filter-pill click handler sets `btn-scan-all` data-target to one of `all` / `high` / `medium` / `low_risk`, with label `"Upload and scan all high priority"` / `"… medium priority"` / `"… lower risk"`.

- [ ] **Step 1: Inspect the current template**

Open `src/hscanner/web/templates/report.html`. The auto-open rule lives at line 85:

```jinja
{% if section.outcome == 'needs_attention' and group.key == 'priority' %} open{% endif %}
```

The JS filter handler that targets the scan-all button lives around lines 144-154. Both need updating.

- [ ] **Step 2: Modify the template**

Change line 85 to:

```jinja
{% if section.outcome == 'needs_attention' and group.key == 'high' %} open{% endif %}
```

Change the JS filter handler (lines 145-154):

```javascript
    const scanAllBtn = section.querySelector('.btn-scan-all');
    if (scanAllBtn) {
      scanAllBtn.dataset.target = key;
      scanAllBtn.textContent = key === 'all'
        ? 'Upload and scan all unverified'
        : key === 'high'
        ? 'Upload and scan all high priority'
        : key === 'medium'
        ? 'Upload and scan all medium priority'
        : 'Upload and scan all lower risk';
    }
```

- [ ] **Step 3: Verify by running the existing tests**

Run: `pytest tests/test_web.py -v -k report`
Expected: PASS. The template is exercised indirectly by web tests that fetch `/reports/{id}`. No template-content assertion needs to change shape — the pills are data-driven; their labels come from `section.filters` and the JS uses the new labels above.

- [ ] **Step 4: Commit**

```bash
git add src/hscanner/web/templates/report.html
git commit -m "Report template: auto-open High group, new pill/batch labels

The Needs-attention 'high' group opens by default (replacing the old
'priority' group). The scan-all button label updates per-pill to
'Upload and scan all high priority' / '… medium priority' /
'… lower risk' to match the new tier targets."
```

---

## Task 10: Update legacy specs and CLAUDE.md

Update the two source-of-truth specs and the project CLAUDE.md to reflect the new tier taxonomy.

**Files:**
- Modify: `docs/superpowers/specs/2026-06-22-risk-prioritized-scan-and-on-demand-upload-design.md`
- Modify: `docs/superpowers/specs/2026-08-12-needs-attention-prioritization-design.md`
- Modify: `docs/superpowers/specs/2026-08-13-needs-attention-tier-extension-subgroups-design.md` (if it references `priority` as a single tier)
- Modify: `CLAUDE.md` Consistency Anchors section

- [ ] **Step 1: Edit the risk-prioritized spec**

Open `docs/superpowers/specs/2026-06-22-risk-prioritized-scan-and-on-demand-upload-design.md`. In the tier table (around lines 64-65), replace:

```
- `PRIORITY` = bucket ∈ {`upload_candidate`, `suspicious_upload_blocked`}
- `LOW_RISK` = bucket == `hash_only`
```

with:

```
- `HIGH`      = upload-candidate extension in `high_extensions` (OS-shell-runnable
                 / native code launchers) OR executable-bit set on an unknown
                 extension OR ELF/shebang promotion.
- `MEDIUM`    = upload-candidate extension in `medium_extensions` (runtime/
                 interpreter required) OR suspicious-block rule with `tier: medium`
                 (e.g., `.pak` + executable markers).
- `LOW_RISK`  = bucket == `hash_only` (data, config, markup, docs, media, fonts).
- `SKIPPED`   = bucket == `skipped` (sensitive or unsupported).
```

Replace the "Unmatched regular files still fall back to `hash_only` / `LOW_RISK`" line (around line 118) with:

```
Unmatched regular files still fall back to `matching.default_bucket` (default
`hash_only` / `LOW_RISK`) — the classifier's catch-all MUST honor this setting.
```

Update the Priority detection section (around line 83) to describe the split rule:

```
Priority detection — split: a file is `HIGH` when it matches an extension
in `upload_candidate.high_extensions`, has the executable bit set, OR is
promoted by ELF/shebang magic. A file is `MEDIUM` when it matches
`upload_candidate.medium_extensions` only. LOW_RISK is unchanged.
```

Replace the `upload_candidate.extensions` example (around line 112) with the split `high_extensions` / `medium_extensions` shape used by `default_policy.yaml` (copy the lists verbatim from the modified policy file).

- [ ] **Step 2: Edit the needs-attention prioritization spec**

Open `docs/superpowers/specs/2026-08-12-needs-attention-prioritization-design.md`. Replace `priority` / `low_risk` two-group references with `high` / `medium` / `low_risk` three-group references. Specifically:

- The group dicts (around lines 76-78) become three entries with keys `"high"`, `"medium"`, `"low_risk"` (titles "High priority", "Medium priority", "Lower risk").
- The order note: "Priority first" becomes "High first, then Medium, then Lower risk".
- The pills section (around line 102) becomes `[{"key": "all", "label": "All", "pressed": true}, {"key": "high", "label": "High", "pressed": false}, {"key": "medium", "label": "Medium", "pressed": false}, {"key": "low_risk", "label": "Lower risk", "pressed": false}]`.
- The CSS filter rule (around line 104) targets `[data-group="high"]` / `[data-group="medium"]` / `[data-group="low_risk"]` accordingly.
- The risk chips (around line 109) become three: high (`sev-high`), medium (`sev-medium`), low_risk (`sev-low`).
- The acceptance criterion that "Priority opens" (around line 185) becomes "the `high` group opens".
- The "toggling the Lower risk pill hides the Priority group" note becomes "toggling any pill hides the other two groups".

- [ ] **Step 3: Edit the 2026-08-13 subgroups spec (if needed)**

Open `docs/superpowers/specs/2026-08-13-needs-attention-tier-extension-subgroups-design.md`. Replace references to a single "Priority" group with "High" and "Medium" groups. The subgroups within each are still grouped by extension — no shape change, just rename "Priority" → "High"/"Medium" where it appears as the outer grouping.

- [ ] **Step 4: Edit CLAUDE.md**

Open `CLAUDE.md`. In the "Consistency anchors" section, update the "Classification buckets → Risk labels → Report categories" line to add a fourth column:

```
- Classification buckets → Risk tiers → Risk labels → Report categories:
  see the **Bucket to report mapping** table in the spec. Changing one column
  means updating the table. Risk tiers are HIGH / MEDIUM / LOW_RISK / SKIPPED.
```

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/specs/2026-06-22-risk-prioritized-scan-and-on-demand-upload-design.md \
        docs/superpowers/specs/2026-08-12-needs-attention-prioritization-design.md \
        docs/superpowers/specs/2026-08-13-needs-attention-tier-extension-subgroups-design.md \
        CLAUDE.md
git commit -m "Docs: reflect HIGH/MEDIUM/LOW_RISK taxonomy across specs

Updates the risk-prioritized spec, the needs-attention prioritization
spec, the tier extension-subgroups spec, and CLAUDE.md consistency
anchors to reflect the new tier split. Documents the
matching.default_bucket invariant and the OS-shell-runnable vs
runtime-required rule."
```

---

## Task 11: Full suite + Ruff + manual smoke

- [ ] **Step 1: Run the full test suite**

Run: `pytest`
Expected: all tests PASS (483 or more; the new tests were added). Investigate any failure.

- [ ] **Step 2: Run Ruff**

Run: `ruff check .`
Expected: clean.

- [ ] **Step 3: Manual smoke (optional, requires network + API key)**

If you have a configured key:

```
HS_API_KEY_VIRUSTOTAL=<key> .venv/bin/python -m hscanner scan /tmp/sample --engine virustotal
```

Expected: the printed report's Needs-attention section groups files into High / Medium / Lower risk. Files with `.json`/`.xml`/`.csv` extensions are no longer under Priority — they appear under Skipped (default bypass). A `.sh` file appears under High; a `.py` file under Medium.

- [ ] **Step 4: Commit any final fixes**

If the smoke / suite surfaced anything, commit the fixes.

---

## Verification (whole-plan)

After Task 11:

- `pytest` passes (full suite, expected ~490+ tests).
- `ruff check .` clean.
- A scan report's Needs-attention section shows three pills (All / High / Medium / Lower risk) and three chips with matching counts.
- The High group is open by default; Medium and Lower risk are collapsed.
- `.json` files in the default report appear in the Skipped section (under their extension group), NOT under any Needs-attention pill.
- Clicking "Upload and scan all high priority" scans only HIGH files; clicking "… medium priority" scans only MEDIUM files.
- An existing persisted report (pre-upgrade) still renders — its priority files land in High (worst-case) via the legacy mapping.