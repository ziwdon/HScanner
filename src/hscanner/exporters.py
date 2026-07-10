import csv
import io
import json
import tempfile
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from hscanner.report import ReportFile, ScanReport, report_payload
from hscanner.report_view import build_report_view


class ExportError(Exception):
    pass


def render_json(report: ScanReport) -> str:
    return json.dumps(report_payload(report), indent=2, sort_keys=True) + "\n"


def _utf8_replacement_text(value: Any) -> str:
    return str(value).encode("utf-8", errors="replace").decode("utf-8")


def _utf8_bytes(value: str) -> bytes:
    return value.encode("utf-8", errors="replace")


def _spreadsheet_safe(value: Any) -> str:
    text = "" if value is None else _utf8_replacement_text(value)
    if text.startswith(("\t", "\r")) or text.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


CSV_FIELDNAMES = [
    "schema_version",
    "report_id",
    "root",
    "generated_at",
    "online",
    "upload_consent",
    "status",
    "quota_stop_reasons",
    "request_total",
    "request_by_kind",
    "pacing_wait_count",
    "pacing_wait_seconds",
    "rate_limit_wait_count",
    "rate_limit_wait_seconds",
    "summary_inventoried",
    "summary_scanned",
    "summary_infected",
    "summary_needs_attention",
    "summary_uploaded",
    "summary_skipped",
    "summary_errors",
    "summary_delay_count",
    "index",
    "relative_path",
    "size",
    "sha256",
    "classification_bucket",
    "classification_reason",
    "hash_eligible",
    "upload_eligible",
    "suspicious",
    "outcome",
    "outcome_reason",
    "lookup_status",
    "upload_status",
    "engine_checked",
    "engine_id",
    "permalink",
    "engine_counts",
    "detection_flagged",
    "detection_total",
    "detections",
    "last_analysis_at",
    "analysis_status",
    "errors",
    "json_reference",
]


def _csv_row(report: ScanReport, file: ReportFile) -> dict[str, Any]:
    summary = report.summary
    metrics = report.request_metrics
    detections = [
        {"engine": engine, "category": category, "name": name}
        for engine, category, name in file.detections
    ]
    return {
        "schema_version": report.schema_version,
        "report_id": report.report_id,
        "root": report.root,
        "generated_at": report.generated_at,
        "online": report.online,
        "upload_consent": report.upload_consent,
        "status": report.status,
        "quota_stop_reasons": json.dumps(report.quota_stop_reasons),
        "request_total": metrics.total,
        "request_by_kind": json.dumps(dict(metrics.by_kind), sort_keys=True),
        "pacing_wait_count": metrics.pacing_wait_count,
        "pacing_wait_seconds": metrics.pacing_wait_seconds,
        "rate_limit_wait_count": metrics.rate_limit_wait_count,
        "rate_limit_wait_seconds": metrics.rate_limit_wait_seconds,
        "summary_inventoried": summary.inventoried,
        "summary_scanned": summary.scanned,
        "summary_infected": summary.infected,
        "summary_needs_attention": summary.needs_attention,
        "summary_uploaded": summary.uploaded,
        "summary_skipped": summary.skipped,
        "summary_errors": summary.errors,
        "summary_delay_count": summary.delay_count,
        "index": file.index,
        "relative_path": file.relative_path,
        "size": file.size,
        "sha256": file.sha256,
        "classification_bucket": file.classification_bucket,
        "classification_reason": file.classification_reason,
        "hash_eligible": file.hash_eligible,
        "upload_eligible": file.upload_eligible,
        "suspicious": file.suspicious,
        "outcome": file.outcome,
        "outcome_reason": file.outcome_reason,
        "lookup_status": file.lookup_status,
        "upload_status": file.upload_status,
        "engine_checked": file.engine_checked,
        "engine_id": file.engine_id or "",
        "permalink": file.permalink,
        "engine_counts": json.dumps(dict(file.engine_counts), sort_keys=True),
        "detection_flagged": file.detection_ratio.flagged,
        "detection_total": file.detection_ratio.total,
        "detections": json.dumps(detections, sort_keys=True),
        "last_analysis_at": file.last_analysis_at,
        "analysis_status": file.analysis_status,
        "errors": json.dumps(file.errors),
        "json_reference": file.json_reference,
    }


def render_csv(report: ScanReport) -> str:
    output = io.StringIO(newline="")
    fieldnames = CSV_FIELDNAMES
    writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for file in report.files:
        row = _csv_row(report, file)
        writer.writerow({name: _spreadsheet_safe(row[name]) for name in fieldnames})
    return output.getvalue()


def render_html(report: ScanReport) -> str:
    environment = Environment(
        loader=FileSystemLoader(Path(__file__).parent / "web" / "templates"),
        autoescape=select_autoescape(("html",)),
    )
    template = environment.get_template("standalone_report.html")
    return _utf8_replacement_text(
        template.render(view=build_report_view(report, secondary_cap=None))
    )


def render_export(report: ScanReport, suffix: str) -> tuple[bytes, str]:
    normalized = suffix.lower()
    if normalized == ".json":
        return _utf8_bytes(render_json(report)), "application/json; charset=utf-8"
    if normalized == ".html":
        return _utf8_bytes(render_html(report)), "text/html; charset=utf-8"
    if normalized == ".csv":
        return _utf8_bytes(render_csv(report)), "text/csv; charset=utf-8"
    raise ExportError(f"Unsupported report extension: {suffix or '<none>'}")


def export_report(report: ScanReport, output: Path) -> None:
    if not output.parent.is_dir():
        raise ExportError(f"Report directory does not exist: {output.parent}")
    temporary: Path | None = None
    try:
        data, _ = render_export(report, output.suffix)
        with tempfile.NamedTemporaryFile(dir=output.parent, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(data)
        temporary.replace(output)
    except (OSError, UnicodeEncodeError, ValueError) as exc:
        raise ExportError(f"Could not write report: {exc}") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
