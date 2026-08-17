# Scanned count should include uploaded files — design

Status: design. Small logic fix to `compute_summary`.

## Motivation

The `scanned` summary tile counts files where `engine_checked` is
True (`lookup_status != NOT_CHECKED`). This counts files whose hash
was looked up but not found (outcome: `needs_attention`) as "scanned."

After an online folder scan, HIGH/MEDIUM files are hash-checked. Files
whose hash is not found are `needs_attention` but are already counted
as `scanned`. When the user later uploads one via per-file scan, the
`scanned` count doesn't change because the file was already counted.

The user expects "scanned" to mean "the engine has a definitive
verdict" (INFECTED or NO_DETECTIONS) or "the file was uploaded and
analyzed" — NOT "the hash was checked but the engine has no record."

## Fix

Change `compute_summary` in `src/hscanner/report.py`:

```python
scanned=sum(
    file.outcome in {ScanOutcome.INFECTED.value, ScanOutcome.NO_DETECTIONS.value}
    or file.upload_status == UploadStatus.ANALYSIS_COMPLETE.value
    for file in files
),
```

This counts:
- Files found by hash with a clean/infected verdict → scanned ✓
- Files uploaded and analysis completed (any outcome) → scanned ✓
- Files hash-checked but not found (needs_attention) → NOT scanned ✓
- Skipped files → NOT scanned ✓
- Error files → NOT scanned (errors count separately) ✓

## Acceptance

1. After an online folder scan, `scanned` counts only files with
   INFECTED/NO_DETECTIONS outcomes or ANALYSIS_COMPLETE upload status.
   Files that are `needs_attention` (hash not found, not uploaded) are
   NOT counted as scanned.
2. After a per-file upload scan that completes analysis, `scanned`
   increments by 1 (the file's upload_status becomes ANALYSIS_COMPLETE).
3. Existing tests updated to match the new definition.
4. `pytest` passes, `ruff check .` clean.