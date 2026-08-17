from typing import Any

from hscanner.engines.registry import ENGINES
from hscanner.models import (
    Classification,
    ClassificationBucket,
    RiskTier,
    risk_tier_for_classification,
    risk_tier_for_legacy_bucket,
)
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
    ext = name.rpartition(".")[2].lower() if "." in name else ""
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
        "risk_tier": file.risk_tier,
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
        "extension": ext,
    }


_RISK_GROUP_META = {
    RiskTier.HIGH.value:     {"key": "high",     "title": "High priority",   "sev": "sev-high"},
    RiskTier.MEDIUM.value:   {"key": "medium",   "title": "Medium priority", "sev": "sev-medium"},
    RiskTier.LOW_RISK.value: {"key": "low_risk", "title": "Lower risk",      "sev": "sev-low"},
}


def tier_key_for_classification(cls: Classification) -> str | None:
    """Resolve the Needs-attention tier key for a fresh Classification.
    Single source of truth consumed by both the view layer and the batch
    endpoint when a Classification is in hand."""
    tier = risk_tier_for_classification(cls)
    meta = _RISK_GROUP_META.get(tier.value)
    return meta["key"] if meta is not None else None


def tier_key_for_bucket(bucket: ClassificationBucket) -> str | None:
    """Legacy-compatible tier key for persisted reports that predate the
    HIGH/MEDIUM split. Reads from the bucket only — use
    tier_key_for_classification for fresh classifications."""
    tier = risk_tier_for_legacy_bucket(bucket)
    meta = _RISK_GROUP_META.get(tier.value)
    return meta["key"] if meta is not None else None


def group_for_file_view(file_view: dict[str, Any]) -> dict[str, str] | None:
    """Resolve the grouping ``{"key", "title"}`` for a built file view, or
    ``None`` when the file's outcome section is flat (no grouping).

    Shared by the static report render grouping (``_group_needs_attention_by_risk``,
    ``_group_by_extension``) and the live single-file update payload so both
    paths place a file in the same group with the same label.
    """
    outcome = file_view["outcome_key"]
    if outcome == "needs_attention":
        tier_str = file_view.get("risk_tier") or ""
        if not tier_str:
            tier = risk_tier_for_legacy_bucket(ClassificationBucket(file_view["classification_bucket"]))
            tier_str = tier.value
        meta = _RISK_GROUP_META.get(tier_str)
        if meta is None:
            return None
        return {"key": meta["key"], "title": meta["title"]}
    if outcome in {"no_detections", "skipped"}:
        ext = file_view["extension"]
        return {"key": ext, "title": "(no extension)" if ext == "" else f".{ext}"}
    return None


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


def _group_by_extension(files: list[dict[str, Any]], cap: int) -> list[dict[str, Any]]:
    by_ext: dict[str, list[dict[str, Any]]] = {}
    for file in files:
        ext = file["extension"]
        by_ext.setdefault(ext, []).append(file)
    groups = []
    for ext in sorted(by_ext):
        group_files = by_ext[ext]
        shown = group_files[:cap]
        title = "(no extension)" if ext == "" else f".{ext}"
        groups.append({
            "key": ext,
            "title": title,
            "files": shown,
            "total": len(group_files),
            "hidden": len(group_files) - len(shown),
        })
    return groups


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
        section = {
            "outcome": outcome,
            "id": anchor,
            "title": title,
            "sev": severity,
            "files": shown,
            "total": len(files),
            "hidden": len(files) - len(shown),
            "has_batch_action": has_batch_action,
        }
        if outcome == "needs_attention":
            risk_groups = _group_needs_attention_by_risk(files, secondary_cap)
            section["groups"] = risk_groups
            section["risk_chips"] = [
                {
                    "key": g["key"],
                    "label": g["title"],
                    "count": g["total"],
                    "sev": next(
                        m["sev"] for m in _RISK_GROUP_META.values() if m["key"] == g["key"]
                    ),
                }
                for g in risk_groups
            ]
            section["filters"] = [
                {"key": "all", "label": "All", "pressed": True},
                {"key": "high", "label": "High", "pressed": False},
                {"key": "medium", "label": "Medium", "pressed": False},
                {"key": "low_risk", "label": "Lower risk", "pressed": False},
            ]
        elif outcome in {"no_detections", "skipped"}:
            section["groups"] = _group_by_extension(files, secondary_cap)
        sections.append(section)

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
        "file_paths": {file.index: file.relative_path for file in report.files},
        "batch_candidate_paths": [
            file.relative_path
            for file in report.files
            if file.outcome in {"needs_attention", "error"} and file.upload_eligible
        ],
        "request_metrics": report.request_metrics,
        "engine_breakdown": dict(report.engine_breakdown),
        "quota_stop_reasons": report.quota_stop_reasons,
    }
