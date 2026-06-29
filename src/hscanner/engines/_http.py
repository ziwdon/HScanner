"""Shared HTTP retry / pacing mixin for scan engines.

Engines inherit ``EngineHttpMixin`` and implement ``_headers()`` to supply
their auth header.  The mixin expects the following attributes on ``self``,
which each engine's ``__init__`` must set:

    api_key, http, budget, hooks, max_retries, backoff_base, _sleep,
    rate_limit_wait_count, rate_limit_wait_seconds
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx

from hscanner.budget import RequestKind
from hscanner.errors import ErrorCode, HScannerError
from hscanner.progress import ScanStage


class EngineHttpMixin:
    """Engine-neutral HTTP retry, pacing, and checkpoint helpers."""

    # --- to be provided by each engine's __init__ ---
    # api_key: str
    # http: httpx.AsyncClient
    # budget: RequestBudget
    # hooks: ScanHooks | None
    # max_retries: int
    # backoff_base: float
    # _sleep: Callable[[float], Awaitable[None]]
    # rate_limit_wait_count: int
    # rate_limit_wait_seconds: float

    def _headers(self) -> dict[str, str]:
        """Return auth headers for this engine.  Override in each subclass."""
        raise NotImplementedError

    async def _checkpoint(self) -> None:
        if self.hooks is not None:
            await self.hooks.checkpoint()

    def _notify_wait(self, seconds: float, stage: ScanStage) -> None:
        if self.hooks is not None:
            self.hooks.on_wait(seconds, stage)

    async def _request_with_retry(
        self,
        kind: RequestKind,
        method: str,
        url: str,
        *,
        files_path: Path | None = None,
        extra_headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        attempt = 0
        while True:
            await self._checkpoint()
            await self.budget.acquire(
                kind,
                on_wait=lambda secs: self._notify_wait(secs, ScanStage.WAITING_RATE_LIMIT),
            )
            await self._checkpoint()
            headers = {**self._headers(), **(extra_headers or {})}
            try:
                if files_path is not None:
                    with files_path.open("rb") as handle:
                        response = await self.http.request(
                            method,
                            url,
                            headers=headers,
                            files={"file": (files_path.name, handle)},
                            **kwargs,
                        )
                else:
                    response = await self.http.request(
                        method, url, headers=headers, **kwargs
                    )
            except httpx.TransportError as exc:
                if attempt >= self.max_retries:
                    raise HScannerError(
                        ErrorCode.ENGINE_NETWORK_ERROR, f"engine network error: {exc}"
                    ) from exc
                await self._sleep(self._backoff(attempt))
                attempt += 1
                continue
            if response.status_code in {401, 403}:
                raise HScannerError(ErrorCode.ENGINE_AUTH_FAILED, "engine API key rejected")
            if response.status_code == 429:
                retry_after = self._retry_after_header(response)
                if attempt >= self.max_retries:
                    raise HScannerError(
                        ErrorCode.ENGINE_RATE_LIMITED,
                        "engine rate limit reached",
                        retry_after=retry_after,
                    )
                delay = retry_after if retry_after is not None else self._backoff(attempt)
                self._notify_wait(delay, ScanStage.WAITING_RATE_LIMIT)
                await self._sleep(delay)
                self.rate_limit_wait_count += 1
                self.rate_limit_wait_seconds += delay
                attempt += 1
                continue
            if 500 <= response.status_code:
                if attempt >= self.max_retries:
                    raise HScannerError(ErrorCode.ENGINE_SERVER_ERROR, "engine server error")
                await self._sleep(self._backoff(attempt))
                attempt += 1
                continue
            return response

    def _backoff(self, attempt: int) -> float:
        return self.backoff_base * (2**attempt)

    def _retry_after_header(self, response: httpx.Response) -> float | None:
        header = response.headers.get("Retry-After")
        if header:
            try:
                return float(header)
            except ValueError:
                return None
        return None

    def metrics_snapshot(self):
        return self.budget.snapshot(
            rate_limit_wait_count=self.rate_limit_wait_count,
            rate_limit_wait_seconds=self.rate_limit_wait_seconds,
        )
