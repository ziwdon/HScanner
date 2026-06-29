from typing import Any

from hscanner.engines.registry import ENGINES
from hscanner.policy.loader import load_default_policy
from hscanner.report import ReportFile, ScanReport

_ABSOLUTE_UPLOAD_MB = load_default_policy()["size_limits"]["absolute_upload_block_mb"]
_MAX_SECONDARY_ROWS = 500

_OUTCOME_META = {
    "infected": ("Infected", "sev-high", "infected"),
    "needs_attention": ("Needs attention", "sev-unknown", "needs-attention"),
    "no_detections": ("No detections", "sev-clear", "no-detections"),
    "skipped": ("Skipped", "sev-skipped", "skipped"),
    "error": ("Errors", "sev-error", "errors"),
}
_OUTCOME_ORDER = tuple(_OUTCOME_META)
_REASON_LABELS = {
    "engine_detection": "The scan engine reported a malicious or suspicious detection",
    "engine_clean": "The scan engine completed its assessment with no detections",
    "engine_not_found": "The hash was checked, but the scan engine has no existing report",
    "incomplete_engine_result": "The scan engine returned insufficient data for a verdict",
    "scan_incomplete": "The file did not reach a scan engine before the scan stopped",
    "upload_blocked": "The hash is unknown and policy prevents uploading this file",
    "low_risk": "Intentionally skipped by the low-risk policy",
    "sensitive": "Sensitive-file policy prevents reading or sending this file",
    "unsupported_file": "Symlinks and non-regular files are outside scanner scope",
}
_STATUS_LABELS = {
    "not_checked": "Not checked",
    "found": "Found",
    "not_found": "Not found",
    "not_uploaded": "Not uploaded",
    "upload_failed": "Upload failed",
    "uploaded": "Uploaded",
    "analysis_complete": "Analysis complete",
    "analysis_failed": "Analysis failed",
}


def _label_reason(reason: str) -> str:
    return _REASON_LABELS.get(reason, reason.replace("_", " ").capitalize())


def _engine_name(engine_id: str | None) -> str:
    if engine_id is None:
        return "—"
    info = ENGINES.get(engine_id)
    return info.display_name if info is not None else engine_id


def outcome_section_meta(outcome: str) -> dict[str, str]:
    title, severity, anchor = _OUTCOME_META[outcome]
    return {"outcome": outcome, "id": anchor, "title": title, "sev": severity}


def build_file_view(file: ReportFile) -> dict[str, Any]:
    directory, _, name = file.relative_path.rpartition("/")
    title, severity, _ = _OUTCOME_META[file.outcome]
    badges = []
    if file.executable_bit:
        badges.append("executable")
    if file.elf:
        badges.append("ELF")
    if file.shebang:
        badges.append("shebang")
    can_scan = file.outcome in {"needs_attention", "error"} and file.upload_eligible
    return {
        "index": file.index,
        "name": name,
        "dir": directory,
        "size": file.size,
        "sha256": file.sha256,
        "outcome": title,
        "outcome_key": file.outcome,
        "outcome_reason": _label_reason(file.outcome_reason),
        "sev": severity,
        "classification_bucket": file.classification_bucket,
        "classification_reason": file.classification_reason,
        "scan_engine": _engine_name(file.engine_id),
        "lookup_status": _STATUS_LABELS[file.lookup_status],
        "upload_status": _STATUS_LABELS[file.upload_status],
        "permalink": file.permalink,
        "flagged": file.detection_ratio.flagged,
        "total_engines": file.detection_ratio.total,
        "ratio": file.detection_ratio.total > 0,
        "counts": dict(file.engine_counts),
        "detections": file.detections,
        "last_analysis_at": file.last_analysis_at,
        "analysis_status": file.analysis_status.replace("_", " "),
        "errors": file.errors,
        "json_reference": file.json_reference,
        "badges": badges,
        "can_scan": can_scan,
        "too_large": file.outcome_reason == "upload_blocked",
        "size_limit_mb": _ABSOLUTE_UPLOAD_MB,
    }


def build_report_view(
    report: ScanReport,
    *,
    secondary_cap: int | None = _MAX_SECONDARY_ROWS,
) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for file in report.files:
        grouped.setdefault(file.outcome, []).append(build_file_view(file))

    sections = []
    batch_action_assigned = False
    for outcome in _OUTCOME_ORDER:
        files = grouped.get(outcome)
        if not files:
            continue
        title, severity, anchor = _OUTCOME_META[outcome]
        cap = secondary_cap if outcome in {"no_detections", "skipped"} else None
        shown = files if cap is None else files[:cap]
        has_batch_action = (
            not batch_action_assigned
            and outcome in {"needs_attention", "error"}
            and any(file["can_scan"] for file in files)
        )
        batch_action_assigned = batch_action_assigned or has_batch_action
        sections.append({
            "outcome": outcome,
            "id": anchor,
            "title": title,
            "sev": severity,
            "files": shown,
            "total": len(files),
            "hidden": len(files) - len(shown),
            "has_batch_action": has_batch_action,
        })

    summary = report.summary
    tiles = [
        {"k": "Inventoried", "v": summary.inventoried},
        {"k": "Scanned", "v": summary.scanned},
        {"k": "Infected", "v": summary.infected, "alert": summary.infected > 0},
        {
            "k": "Needs attention",
            "v": summary.needs_attention,
            "alert": summary.needs_attention > 0,
        },
        {"k": "Uploaded", "v": summary.uploaded},
        {"k": "Skipped", "v": summary.skipped},
        {"k": "Errors", "v": summary.errors, "alert": summary.errors > 0},
    ]
    return {
        "report_id": report.report_id,
        "engine_name": report.engine_name,
        "folder": report.root,
        "generated_at": report.generated_at,
        "status": report.status.replace("_", " "),
        "online": report.online,
        "total": summary.inventoried,
        "scanned": summary.scanned,
        "uploaded": summary.uploaded,
        "tiles": tiles,
        "sections": sections,
        "navigation": [
            {"id": section["id"], "title": section["title"], "total": section["total"]}
            for section in sections
        ],
        "section_meta": {
            outcome: outcome_section_meta(outcome) for outcome in _OUTCOME_ORDER
        },
        "request_metrics": report.request_metrics,
        "engine_breakdown": dict(report.engine_breakdown),
        "quota_stop_reasons": report.quota_stop_reasons,
    }
