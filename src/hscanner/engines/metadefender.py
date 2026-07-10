from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import httpx

from hscanner.budget import RequestBudget, RequestKind
from hscanner.engines._http import EngineHttpMixin
from hscanner.engines.base import EngineFileReport, EngineInfo
from hscanner.errors import ErrorCode, HScannerError
from hscanner.progress import ScanHooks, ScanStage

_MD_BASE = "https://api.metadefender.com/v4"
_TERMINAL_SCAN_LABELS = {
    "allowed",
    "infected",
    "no threat detected",
}


class MetaDefenderEngine(EngineHttpMixin):
    def __init__(
        self,
        api_key: str,
        http_client: httpx.AsyncClient | None = None,
        budget: RequestBudget | None = None,
        *,
        hooks: ScanHooks | None = None,
        max_retries: int = 3,
        backoff_base: float = 1.0,
        poll_interval: float = 15.0,
        poll_timeout: float = 600.0,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.info = EngineInfo("metadefender", "MetaDefender", 10)
        self.api_key = api_key
        self.http = http_client or httpx.AsyncClient()
        self.budget = budget or RequestBudget(per_minute=self.info.default_per_minute)
        self.hooks = hooks
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.poll_interval = poll_interval
        self.poll_timeout = poll_timeout
        self._sleep = sleep
        self._monotonic = monotonic
        self.rate_limit_wait_count = 0
        self.rate_limit_wait_seconds = 0.0

    def _headers(self) -> dict[str, str]:
        return {"apikey": self.api_key}

    async def get_file_report(self, sha256: str) -> EngineFileReport | None:
        response = await self._request_with_retry(
            RequestKind.LOOKUP, "GET", f"{_MD_BASE}/hash/{sha256}"
        )
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            raise HScannerError(
                ErrorCode.ENGINE_CLIENT_ERROR, f"MetaDefender client error {response.status_code}"
            )
        body = self._json_body(response, "hash lookup")
        if isinstance(body.get("error"), dict):  # 200-with-error guard (e.g. 404008 body)
            return None
        return self._to_report(body, sha256)

    async def upload_file(self, path: Path) -> str:
        response = await self._request_with_retry(
            RequestKind.UPLOAD, "POST", f"{_MD_BASE}/file",
            files_path=path, extra_headers={"filename": path.name},
        )
        if response.status_code >= 400:
            raise HScannerError(
                ErrorCode.UPLOAD_FAILED, f"MetaDefender upload error {response.status_code}"
            )
        body = self._json_body(response, "upload")
        data_id = body.get("data_id")
        if not isinstance(data_id, str) or not data_id:
            raise HScannerError(
                ErrorCode.UPLOAD_FAILED, "MetaDefender malformed upload response"
            )
        return data_id

    async def wait_for_analysis(self, analysis_id: str, sha256: str) -> EngineFileReport:
        deadline = self._monotonic() + self.poll_timeout
        while True:
            response = await self._request_with_retry(
                RequestKind.POLL, "GET", f"{_MD_BASE}/file/{analysis_id}"
            )
            if response.status_code >= 400:
                raise HScannerError(
                    ErrorCode.ENGINE_CLIENT_ERROR,
                    f"MetaDefender analysis error {response.status_code}",
                )
            body = self._json_body(response, "analysis")
            progress = (body.get("scan_results") or {}).get("progress_percentage")
            scan_results = body.get("scan_results") or {}
            process_info = body.get("process_info") or {}
            if not isinstance(scan_results, dict):
                scan_results = {}
            if not isinstance(process_info, dict):
                process_info = {}
            if progress == 100 or self._assessment_complete(scan_results, process_info):
                return self._to_report(body, sha256)
            if self._monotonic() >= deadline:
                raise HScannerError(
                    ErrorCode.ANALYSIS_TIMEOUT, "MetaDefender analysis polling timed out"
                )
            self._notify_wait(self.poll_interval, ScanStage.POLLING)
            await self._sleep(self.poll_interval)

    async def close(self) -> None:
        await self.http.aclose()

    def _json_body(self, response: httpx.Response, context: str) -> dict[str, Any]:
        try:
            body = response.json()
        except ValueError as exc:
            raise HScannerError(
                ErrorCode.ENGINE_CLIENT_ERROR,
                f"MetaDefender malformed {context} response",
            ) from exc
        if not isinstance(body, dict):
            raise HScannerError(
                ErrorCode.ENGINE_CLIENT_ERROR,
                f"MetaDefender malformed {context} response",
            )
        return body

    def _parse_int(
        self,
        value: Any,
        field: str,
        *,
        default: int = 0,
        allow_none: bool = True,
    ) -> int:
        if value is None and allow_none:
            return default
        try:
            return int(value)
        except (TypeError, ValueError) as exc:
            raise HScannerError(
                ErrorCode.ENGINE_CLIENT_ERROR,
                f"MetaDefender malformed {field} response",
            ) from exc

    def _assessment_complete(self, sr: dict[str, Any], process_info: dict[str, Any]) -> bool:
        progress = sr.get("progress_percentage")
        if progress is None:
            progress = process_info.get("progress_percentage")
        if progress == 100:
            return True
        result_code = sr.get("scan_all_result_i")
        if result_code is not None:
            try:
                if int(result_code) in {0, 1}:
                    return True
            except (TypeError, ValueError):
                pass
        result_label = sr.get("scan_all_result_a")
        if isinstance(result_label, str) and result_label.strip().lower() in _TERMINAL_SCAN_LABELS:
            return True
        return False

    def _to_report(self, body: dict[str, Any], sha256: str) -> EngineFileReport:
        sr = body.get("scan_results", {}) or {}
        process_info = body.get("process_info", {}) or {}
        if not isinstance(sr, dict):
            raise HScannerError(
                ErrorCode.ENGINE_CLIENT_ERROR, "MetaDefender malformed scan_results response"
            )
        if not isinstance(process_info, dict):
            process_info = {}
        total = self._parse_int(sr.get("total_avs"), "total_avs")
        detected = self._parse_int(sr.get("total_detected_avs"), "total_detected_avs")
        stats: dict[str, int] = {}
        if total or detected:
            stats = {"malicious": detected, "undetected": max(total - detected, 0)}
        details = sr.get("scan_details", {}) or {}
        if not isinstance(details, dict):
            details = {}
        detections = [
            {"engine": str(name), "category": "malicious", "name": str(info.get("threat_found"))}
            for name, info in sorted(details.items())
            if isinstance(info, dict) and info.get("threat_found")
            and self._parse_int(
                info.get("scan_result_i"), "scan_result_i", allow_none=False
            ) != 0
        ]
        return EngineFileReport(
            engine_stats=stats,
            detections=detections,
            permalink=f"https://metadefender.com/results/hash/{sha256}",
            last_analysis_at=None,
            assessment_complete=self._assessment_complete(sr, process_info),
            raw=body,
        )
