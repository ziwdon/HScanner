import dataclasses
import logging
import time
from collections import OrderedDict
from collections.abc import Callable
from threading import Lock
from typing import Any

from hscanner.models import FileResult
from hscanner.report import ScanReport, _report_file, classify_report_result, compute_summary

logger = logging.getLogger(__name__)


class ReportRegistry:
    def __init__(
        self,
        *,
        max_reports: int = 5,
        ttl_seconds: float = 3600,
        monotonic: Callable[[], float] = time.monotonic,
        persistent_store: Any | None = None,
        persistent_update_interval: float = 2.0,
    ) -> None:
        self.max_reports = max_reports
        self.ttl_seconds = ttl_seconds
        self._monotonic = monotonic
        self._persistent_store = persistent_store
        self._persistent_warning_emitted = False
        self._persistent_update_interval = persistent_update_interval
        self._persistent_last_write: dict[str, float] = {}
        self._persistent_dirty: set[str] = set()
        self._lock = Lock()
        self._reports: OrderedDict[str, tuple[float, ScanReport]] = OrderedDict()

    def put(self, report: ScanReport) -> None:
        with self._lock:
            now = self._monotonic()
            self._prune(now)
            self._remember(now, report)
            self._persistent_put(report, now=now)

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
            report = self._persistent_get(report_id)
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
                for report in self._persistent_list():
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
                report = self._persistent_get(report_id)
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
            self._persistent_put_throttled(new_report, now)
            return new_report

    def flush(self, report_id: str) -> None:
        with self._lock:
            item = self._reports.get(report_id)
            if item is None:
                return
            report = item[1]
            now = self._monotonic()
            self._persistent_put(report, now=now)

    def _persistent_put(self, report: ScanReport, *, now: float | None = None) -> None:
        if self._persistent_store is None:
            return
        try:
            self._persistent_store.put(report)
            self._persistent_last_write[report.report_id] = (
                self._monotonic() if now is None else now
            )
            self._persistent_dirty.discard(report.report_id)
        except Exception as exc:
            self._warn_persistent_failure("write", exc)

    def _persistent_put_throttled(self, report: ScanReport, now: float) -> None:
        if self._persistent_store is None:
            return
        last = self._persistent_last_write.get(report.report_id)
        if last is None or now - last >= self._persistent_update_interval:
            self._persistent_put(report, now=now)
            return
        self._persistent_dirty.add(report.report_id)

    def _persistent_get(self, report_id: str) -> ScanReport | None:
        if self._persistent_store is None:
            return None
        try:
            return self._persistent_store.get(report_id)
        except Exception as exc:
            self._warn_persistent_failure("read", exc)
            return None

    def _persistent_list(self) -> list[ScanReport]:
        if self._persistent_store is None or not hasattr(self._persistent_store, "list_reports"):
            return []
        try:
            return list(self._persistent_store.list_reports())
        except Exception as exc:
            self._warn_persistent_failure("list", exc)
            return []

    def _warn_persistent_failure(self, operation: str, exc: Exception) -> None:
        if self._persistent_warning_emitted:
            return
        self._persistent_warning_emitted = True
        logger.warning(
            "Persistent report store %s failed; continuing with in-memory reports only",
            operation,
            exc_info=(type(exc), exc, exc.__traceback__),
        )

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
