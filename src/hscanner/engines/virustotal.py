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

_VT_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalEngine(EngineHttpMixin):
    info = EngineInfo("virustotal", "VirusTotal", 4)

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
        self.api_key = api_key
        self.http = http_client or httpx.AsyncClient()
        self.budget = budget or RequestBudget()
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
        return {"x-apikey": self.api_key}

    async def get_file_report(self, sha256: str) -> EngineFileReport | None:
        response = await self._request_with_retry(
            RequestKind.LOOKUP, "GET", f"{_VT_BASE}/files/{sha256}"
        )
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            raise HScannerError(
                ErrorCode.ENGINE_CLIENT_ERROR, f"VirusTotal client error {response.status_code}"
            )
        return self._to_report(self._json_body(response, "file report"), sha256)

    async def get_large_upload_url(self) -> str:
        response = await self._request_with_retry(
            RequestKind.UPLOAD_URL, "GET", f"{_VT_BASE}/files/upload_url"
        )
        if response.status_code >= 400:
            raise HScannerError(
                ErrorCode.ENGINE_CLIENT_ERROR, f"VirusTotal upload URL error {response.status_code}"
            )
        body = self._json_body(response, "large upload URL")
        upload_url = body.get("data")
        if not isinstance(upload_url, str) or not upload_url:
            raise HScannerError(
                ErrorCode.UPLOAD_FAILED, "VirusTotal malformed large upload URL response"
            )
        return upload_url

    async def upload_file(self, path: Path) -> str:
        size = path.stat().st_size
        if size > 32 * 1024 * 1024:
            upload_url = await self.get_large_upload_url()
            response = await self._post_file(upload_url, path)
        else:
            response = await self._post_file(f"{_VT_BASE}/files", path)
        data = response.get("data")
        analysis_id = data.get("id") if isinstance(data, dict) else None
        if not isinstance(analysis_id, str) or not analysis_id:
            raise HScannerError(
                ErrorCode.UPLOAD_FAILED, "VirusTotal malformed upload response"
            )
        return analysis_id

    async def _post_file(self, url: str, path: Path) -> dict[str, Any]:
        response = await self._request_with_retry(
            RequestKind.UPLOAD, "POST", url, files_path=path
        )
        if response.status_code >= 400:
            raise HScannerError(
                ErrorCode.UPLOAD_FAILED, f"VirusTotal upload error {response.status_code}"
            )
        return self._json_body(response, "upload")

    async def wait_for_analysis(self, analysis_id: str, sha256: str) -> EngineFileReport:
        deadline = self._monotonic() + self.poll_timeout
        while True:
            response = await self._request_with_retry(
                RequestKind.POLL, "GET", f"{_VT_BASE}/analyses/{analysis_id}"
            )
            if response.status_code >= 400:
                raise HScannerError(
                    ErrorCode.ENGINE_CLIENT_ERROR,
                    f"VirusTotal analysis error {response.status_code}",
                )
            body = self._json_body(response, "analysis")
            status = body.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                report = await self.get_file_report(sha256)
                return report if report is not None else self._to_report(body, sha256)
            if self._monotonic() >= deadline:
                raise HScannerError(
                    ErrorCode.ANALYSIS_TIMEOUT, "VirusTotal analysis polling timed out"
                )
            self._notify_wait(self.poll_interval, ScanStage.POLLING)
            await self._sleep(self.poll_interval)

    def _json_body(self, response: httpx.Response, context: str) -> dict[str, Any]:
        try:
            body = response.json()
        except ValueError as exc:
            raise HScannerError(
                ErrorCode.ENGINE_CLIENT_ERROR,
                f"VirusTotal malformed {context} response",
            ) from exc
        if not isinstance(body, dict):
            raise HScannerError(
                ErrorCode.ENGINE_CLIENT_ERROR,
                f"VirusTotal malformed {context} response",
            )
        return body

    def _to_report(self, payload: dict[str, Any], sha256: str) -> EngineFileReport:
        attributes = payload.get("data", {}).get("attributes", {})
        if not isinstance(attributes, dict):
            attributes = {}
        last_stats = attributes.get("last_analysis_stats")
        analysis_stats = attributes.get("stats")
        assessment_complete = isinstance(last_stats, dict) or (
            attributes.get("status") == "completed" and isinstance(analysis_stats, dict)
        )
        stats = last_stats or analysis_stats or {}
        if not isinstance(stats, dict):
            stats = {}
        engine_stats = {
            key: value
            for key, value in stats.items()
            if isinstance(key, str) and type(value) is int
        }
        results = attributes.get("last_analysis_results")
        if not isinstance(results, dict):
            results = {}
        detections = [
            {
                "engine": engine,
                "category": str(info["category"]),
                "name": str(info.get("result") or info["category"]),
            }
            for engine, info in sorted(results.items())
            if isinstance(engine, str)
            and isinstance(info, dict)
            and info.get("category") in {"malicious", "suspicious"}
        ]
        last_analysis_at = attributes.get("last_analysis_date")
        return EngineFileReport(
            engine_stats=engine_stats,
            detections=detections,
            permalink=f"https://www.virustotal.com/gui/file/{sha256}",
            last_analysis_at=(last_analysis_at if type(last_analysis_at) is int else None),
            assessment_complete=assessment_complete,
            raw=payload,
        )

    async def close(self) -> None:
        await self.http.aclose()
