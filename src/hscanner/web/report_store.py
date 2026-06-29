import dataclasses
import time
from collections import OrderedDict
from collections.abc import Callable
from threading import Lock
from typing import Any

from hscanner.models import FileResult
from hscanner.report import ScanReport, _report_file, classify_report_result, compute_summary


class ReportRegistry:
    def __init__(
        self,
        *,
        max_reports: int = 5,
        ttl_seconds: float = 3600,
        monotonic: Callable[[], float] = time.monotonic,
        persistent_store: Any | None = None,
    ) -> None:
        self.max_reports = max_reports
        self.ttl_seconds = ttl_seconds
        self._monotonic = monotonic
        self._persistent_store = persistent_store
        self._lock = Lock()
        self._reports: OrderedDict[str, tuple[float, ScanReport]] = OrderedDict()

    def put(self, report: ScanReport) -> None:
        with self._lock:
            now = self._monotonic()
            self._prune(now)
            self._remember(now, report)
            if self._persistent_store is not None:
                self._persistent_store.put(report)

    def get(self, report_id: str) -> ScanReport | None:
        with self._lock:
            now = self._monotonic()
            self._prune(now)
            item = self._reports.get(report_id)
            if item is not None:
                self._reports[report_id] = (now, item[1])
                self._reports.move_to_end(report_id)
                return item[1]
            if self._persistent_store is None:
                return None
            report = self._persistent_store.get(report_id)
            if report is not None:
                self._remember(now, report)
            return report

    def list_reports(self) -> list[ScanReport]:
        with self._lock:
            now = self._monotonic()
            self._prune(now)
            reports: dict[str, ScanReport] = {}
            if self._persistent_store is not None and hasattr(
                self._persistent_store, "list_reports"
            ):
                for report in self._persistent_store.list_reports():
                    reports[report.report_id] = report
            for _, report in self._reports.values():
                reports[report.report_id] = report
            return sorted(
                reports.values(),
                key=lambda report: (report.generated_at, report.report_id),
                reverse=True,
            )

    def update_file(self, report_id: str, index: int, result: FileResult) -> ScanReport | None:
        with self._lock:
            now = self._monotonic()
            item = self._reports.get(report_id)
            if item is None:
                self._prune(now)
                report = (
                    self._persistent_store.get(report_id)
                    if self._persistent_store is not None
                    else None
                )
                if report is None:
                    return None
            else:
                report = item[1]
            if not (0 <= index < len(report.files)):
                return None
            classify_report_result(result)
            new_file = _report_file(index, result)
            files = report.files[:index] + (new_file,) + report.files[index + 1:]
            summary = compute_summary(files, report.request_metrics)
            new_report = dataclasses.replace(report, files=files, summary=summary)
            self._remember(now, new_report)
            self._prune(now)
            if self._persistent_store is not None:
                self._persistent_store.put(new_report)
            return new_report

    def _remember(self, now: float, report: ScanReport) -> None:
        self._reports[report.report_id] = (now, report)
        self._reports.move_to_end(report.report_id)
        while len(self._reports) > self.max_reports:
            self._reports.popitem(last=False)

    def _prune(self, now: float) -> None:
        expired = [
            report_id
            for report_id, (created_at, _) in self._reports.items()
            if now - created_at >= self.ttl_seconds
        ]
        for report_id in expired:
            del self._reports[report_id]
