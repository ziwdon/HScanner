import asyncio
import json
from contextlib import suppress
from pathlib import Path

import keyring as system_keyring
from fastapi import APIRouter, Form, Request
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from fastapi.templating import Jinja2Templates

from hscanner.budget import QuotaCounter, RequestBudget
from hscanner.cache import EngineCache
from hscanner.classifier import classify_file, reclassify_with_signals
from hscanner.engines.registry import (
    COMBINED_ENGINE_IDS,
    ENGINES,
    build_engine,
    build_rotation,
)
from hscanner.errors import ErrorCode
from hscanner.exporters import render_export
from hscanner.hash import read_magic
from hscanner.inventory import InventoryPathError, record_from_path
from hscanner.keys import clear_saved_api_key, load_saved_api_key, resolve_api_key, save_api_key
from hscanner.models import (
    Classification,
    ClassificationBucket,
    EngineState,
    FileRecord,
    FileResult,
    ReportAction,
    RiskTier,
    risk_tier_for,
)
from hscanner.policy.loader import load_default_policy, parse_quota_policy
from hscanner.progress import EventType
from hscanner.report import build_scan_report
from hscanner.report_view import build_file_view, build_report_view, outcome_section_meta
from hscanner.scanner import run_online_scan, scan_single_file, scan_single_file_with_rotation
from hscanner.state import ScanState
from hscanner.store import open_global_store, open_scan_store
from hscanner.web.jobs import JobBusy

router = APIRouter()
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")


def _keyring_module(request: Request):
    return getattr(request.app.state, "keyring_module", None) or system_keyring


def _has_key(request: Request, engine_id: str) -> bool:
    return load_saved_api_key(engine_id, keyring_module=_keyring_module(request)) is not None


@router.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "index.html",
        {"active": "scan", "has_key": any(_has_key(request, eid) for eid in ENGINES)},
    )


@router.get("/settings", response_class=HTMLResponse)
def settings(request: Request) -> HTMLResponse:
    engine_list = [
        {"id": eid, "name": ENGINES[eid].display_name, "has_key": _has_key(request, eid)}
        for eid in ENGINES
    ]
    return templates.TemplateResponse(
        request, "settings.html", {"active": "settings", "engine_list": engine_list}
    )


@router.get("/history", response_class=HTMLResponse)
def history(request: Request) -> HTMLResponse:
    reports = [
        _history_report_item(report)
        for report in request.app.state.report_registry.list_reports()
    ]
    return templates.TemplateResponse(
        request,
        "history.html",
        {"active": "history", "reports": reports},
    )


def _history_report_item(report) -> dict:
    no_detections = sum(file.outcome == "no_detections" for file in report.files)
    return {
        "report_id": report.report_id,
        "root": report.root,
        "generated_at": report.generated_at,
        "engine_name": report.engine_name,
        "status": report.status.replace("_", " "),
        "summary": {
            "inventoried": report.summary.inventoried,
            "infected": report.summary.infected,
            "needs_attention": report.summary.needs_attention,
            "no_detections": no_detections,
            "errors": report.summary.errors,
        },
    }


@router.post("/settings/api-key")
def save_settings_key(
    request: Request,
    api_key: str = Form(...),
    engine: str = Form("virustotal"),
) -> Response:
    if engine not in ENGINES:
        return JSONResponse({"error": f"Unknown engine '{engine}'."}, status_code=400)
    save_api_key(engine, api_key, keyring_module=_keyring_module(request))
    return RedirectResponse("/settings", status_code=303)


@router.post("/settings/api-key/clear")
def clear_settings_key(
    request: Request,
    engine: str = Form("virustotal"),
) -> Response:
    if engine not in ENGINES:
        return JSONResponse({"error": f"Unknown engine '{engine}'."}, status_code=400)
    clear_saved_api_key(engine, keyring_module=_keyring_module(request))
    return RedirectResponse("/settings", status_code=303)


@router.post("/scan", response_class=HTMLResponse)
async def scan_folder(
    request: Request,
    folder: str = Form(...),
    bypass_low_risk: bool = Form(True),
    engine: str = Form("virustotal"),
) -> HTMLResponse:
    has_required_keys = any(_has_key(request, eid) for eid in ENGINES)

    def _index_error(message: str, status: int):
        return templates.TemplateResponse(
            request,
            "index.html",
            {
                "active": "scan",
                "has_key": has_required_keys,
                "folder": folder,
                "bypass_low_risk": bypass_low_risk,
                "engine": engine,
                "error": message,
            },
            status_code=status,
        )

    valid_engines = set(ENGINES) | {"combined"}
    if engine not in valid_engines:
        return _index_error(f"Unknown engine '{engine}'.", 400)

    engine_ids_in_order = COMBINED_ENGINE_IDS if engine == "combined" else [engine]
    keys = {
        engine_id: resolve_api_key(
            engine_id,
            lambda engine_id=engine_id: load_saved_api_key(
                engine_id, keyring_module=_keyring_module(request)
            ),
        )
        for engine_id in engine_ids_in_order
    }
    missing = [engine_id for engine_id, key in keys.items() if key is None]
    has_required_keys = not missing

    scan_root = Path(folder).expanduser().resolve()
    if scan_root.exists() and not scan_root.is_dir():
        return _index_error(f"{scan_root} is a file, not a folder.", 400)
    if not scan_root.is_dir():
        return _index_error("That folder doesn't exist on this machine.", 400)

    # A key is required: without it HScanner can do no engine work at all.
    if missing:
        names = ", ".join(ENGINES[engine_id].display_name for engine_id in missing)
        return _index_error(
            f"An API key is required for: {names}. Add it in Settings.",
            400,
        )

    policy = load_default_policy()
    quota = parse_quota_policy(policy)
    factory_override = getattr(request.app.state, "engine_factory", None)

    def _build_rotation(global_store):
        engines = []
        for engine_id in engine_ids_in_order:
            api_key = keys[engine_id]
            if factory_override is not None:
                engines.append(factory_override(engine_id, api_key))
                continue
            budget = RequestBudget(
                per_minute=quota.requests_per_minute,
                max_requests=quota.per_scan_request_budget,
                quota=QuotaCounter(
                    global_store,
                    engine_id=engine_id,
                    daily=quota.daily_request_budget,
                    monthly=quota.monthly_request_budget,
                ),
            )
            engines.append(
                build_engine(
                    engine_id,
                    api_key,
                    budget=budget,
                    poll_timeout=quota.polling_timeout_seconds,
                )
            )
        return build_rotation(engine_ids_in_order, engines)

    registry = request.app.state.report_registry

    async def _scan_coro(observer, controller):
        global_store = open_global_store()
        try:
            cache = EngineCache(global_store, ttl_days=quota.cache_ttl_days)
            scan_state = ScanState(open_scan_store(scan_root), scan_root)
            scan_state.start_or_resume(resume=False)
            rotation = _build_rotation(global_store)
            try:
                return await run_online_scan(
                    scan_root,
                    rotation,
                    upload_consent=False,
                    bypass_low_risk=bypass_low_risk,
                    cache=cache,
                    scan_state=scan_state,
                    observer=observer,
                    controller=controller,
                )
            finally:
                for slot in rotation._slots:
                    await slot.engine.close()
        finally:
            global_store.close()

    def _finalize(outcome) -> str:
        is_combined = engine == "combined"
        report = build_scan_report(
            scan_root,
            outcome.results,
            online=True,
            upload_consent=False,
            engine_id="combined" if is_combined else engine,
            engine_name="Combined" if is_combined else ENGINES[engine].display_name,
            status=outcome.status,
            quota_stop_reasons=outcome.quota_stop_reasons,
            request_metrics=outcome.request_metrics,
            engine_breakdown=outcome.engine_breakdown,
            request_metrics_by_engine=outcome.request_metrics_by_engine,
        )
        registry.put(report)
        return report.report_id

    if (
        request.app.state.file_scan_manager.has_active()
        or request.app.state.batch_file_scan_manager.has_active()
    ):
        return _index_error("A scan is already in progress. Wait for it to finish.", 409)

    try:
        job = request.app.state.job_manager.start(
            _scan_coro, _finalize, per_minute=quota.requests_per_minute
        )
    except JobBusy:
        return _index_error("A scan is already in progress. Wait for it to finish.", 409)

    return templates.TemplateResponse(
        request,
        "progress.html",
        {
            "active": "scan",
            "job_id": job.id,
            "engine_display_names": {
                engine_id: info.display_name for engine_id, info in ENGINES.items()
            },
        },
    )


def _job_or_404(request: Request, job_id: str):
    return request.app.state.job_manager.get(job_id)


def _sse(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"


def _terminal_payload(job, event_data: dict[str, object] | None = None) -> dict[str, object]:
    data = {**job.snapshot.to_dict(), **(event_data or {})}
    data["type"] = EventType.SCAN_FINISHED.value
    if job.error is not None:
        data["status"] = job.status.value
        data["error"] = job.error
    elif "status" not in data:
        data["status"] = (
            job.scan_status.value if job.scan_status is not None else job.status.value
        )
    data["report_id"] = job.report_id
    return data


@router.get("/scan/{job_id}/events")
def scan_events(request: Request, job_id: str) -> Response:
    job = _job_or_404(request, job_id)
    if job is None:
        return JSONResponse({"error": "unknown job"}, status_code=404)

    async def _stream():
        queue = job.subscribe()
        queue_get_task = None
        try:
            yield _sse({"type": "snapshot", "status": job.status.value, **job.snapshot.to_dict()})
            if job.is_terminal:
                yield _sse(_terminal_payload(job))
                return

            while True:
                if not queue.empty():
                    event = queue.get_nowait()
                elif job.task is None:
                    event = await queue.get()
                elif job.task.done():
                    yield _sse(_terminal_payload(job))
                    return
                else:
                    queue_get_task = asyncio.create_task(queue.get())
                    done, _ = await asyncio.wait(
                        (queue_get_task, job.task), return_when=asyncio.FIRST_COMPLETED
                    )
                    if queue_get_task in done:
                        event = queue_get_task.result()
                        queue_get_task = None
                    else:
                        queue_get_task.cancel()
                        with suppress(asyncio.CancelledError):
                            await queue_get_task
                        queue_get_task = None
                        yield _sse(_terminal_payload(job))
                        return

                data = {**job.snapshot.to_dict(), "status": job.status.value, **event.as_dict()}
                if event.type == EventType.SCAN_FINISHED:
                    if job.task is not None:
                        await asyncio.shield(job.task)
                    yield _sse(_terminal_payload(job, data))
                    return
                yield _sse(data)
        finally:
            if queue_get_task is not None and not queue_get_task.done():
                queue_get_task.cancel()
                with suppress(asyncio.CancelledError):
                    await queue_get_task
            job.unsubscribe(queue)

    return StreamingResponse(
        _stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/scan/{job_id}/pause")
async def pause_scan(request: Request, job_id: str) -> Response:
    job = _job_or_404(request, job_id)
    if job is None:
        return JSONResponse({"error": "unknown job"}, status_code=404)
    job.pause()
    return JSONResponse({"status": job.status.value})


@router.post("/scan/{job_id}/resume")
async def resume_scan(request: Request, job_id: str) -> Response:
    job = _job_or_404(request, job_id)
    if job is None:
        return JSONResponse({"error": "unknown job"}, status_code=404)
    job.resume()
    return JSONResponse({"status": job.status.value})


@router.post("/scan/{job_id}/cancel")
async def cancel_scan(request: Request, job_id: str) -> Response:
    job = _job_or_404(request, job_id)
    if job is None:
        return JSONResponse({"error": "unknown job"}, status_code=404)
    job.cancel()
    return JSONResponse({"status": job.status.value})


@router.get("/reports/{report_id}.{format_name}")
def download_report(request: Request, report_id: str, format_name: str) -> Response:
    suffix = f".{format_name.lower()}"
    if suffix not in {".json", ".html", ".csv"}:
        return HTMLResponse("<h1>Report expired or unavailable</h1>", status_code=404)
    report = request.app.state.report_registry.get(report_id)
    if report is None:
        return HTMLResponse("<h1>Report expired or unavailable</h1>", status_code=404)
    data, media_type = render_export(report, suffix)
    filename = f"hscanner-report-{report.report_id[:12]}{suffix}"
    return Response(
        data,
        media_type=media_type.split(";", 1)[0],
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/reports/{report_id}", response_class=HTMLResponse)
def report_page(request: Request, report_id: str) -> HTMLResponse:
    report = request.app.state.report_registry.get(report_id)
    if report is None:
        return HTMLResponse("<h1>Report expired or unavailable</h1>", status_code=404)
    view = build_report_view(report)
    return templates.TemplateResponse(request, "report.html", {"active": "scan", "view": view})


# ---------------------------------------------------------------------------
# Per-file scan helpers and endpoints
# ---------------------------------------------------------------------------


def _build_engine_client(
    request: Request,
    api_key: str,
    quota,
    global_store,
    engine_id: str = "virustotal",
):
    """Build a scan engine client, using the injected factory if present (for testing)."""
    factory = getattr(request.app.state, "engine_factory", None)
    if factory is not None:
        return factory(engine_id, api_key)
    budget = RequestBudget(
        per_minute=quota.requests_per_minute,
        max_requests=quota.per_scan_request_budget,
        quota=QuotaCounter(
            global_store,
            engine_id=engine_id,
            daily=quota.daily_request_budget,
            monthly=quota.monthly_request_budget,
        ),
    )
    return build_engine(
        engine_id,
        api_key,
        budget=budget,
        poll_timeout=quota.polling_timeout_seconds,
    )


def _file_terminal_payload(request: Request, report_id: str, index: int, job) -> dict:
    """Build the terminal SSE payload for a file scan job."""
    if job.state == "error":
        return {"state": "error", "error": job.error or "Internal error"}
    report = request.app.state.report_registry.get(report_id)
    f = report.files[index] if report and 0 <= index < len(report.files) else None
    if f is None:
        return {"state": "done"}
    return {
        "state": "done",
        "outcome": f.outcome,
        "outcome_reason": f.outcome_reason,
        "lookup_status": f.lookup_status,
        "upload_status": f.upload_status,
        "flagged": f.detection_ratio.flagged,
        "total_engines": f.detection_ratio.total,
        "permalink": f.permalink,
        **_live_file_payload(f),
    }


def _render_file_card(file_view: dict) -> str:
    return templates.env.get_template("_file_card.html").render(f=file_view)


def _live_file_payload(file) -> dict:
    file_view = build_file_view(file)
    section = outcome_section_meta(file.outcome)
    return {
        "file": {
            "index": file_view["index"],
            "outcome": file_view["outcome_key"],
            "title": file_view["outcome"],
            "can_scan": file_view["can_scan"],
        },
        "section": section,
        "file_card_html": _render_file_card(file_view),
    }


def _is_unresolved_scan_candidate(file) -> bool:
    return file.outcome in {"needs_attention", "error"} and file.upload_eligible


@router.post("/reports/{report_id}/files/{index}/scan")
async def scan_report_file(request: Request, report_id: str, index: int) -> Response:
    """Enqueue a per-file scan for a single report file."""
    registry = request.app.state.report_registry
    report = registry.get(report_id)
    if report is None or not (0 <= index < len(report.files)):
        return JSONResponse({"error": "report expired or unavailable"}, status_code=404)

    file = report.files[index]
    report_engine_id = getattr(report, "engine_id", None) or "virustotal"
    # Combined reports route an explicit upload back to the engine that handled
    # this file's lookup. Fall back to the first-priority engine for legacy rows.
    engine_id = (
        file.engine_id or COMBINED_ENGINE_IDS[0]
        if report_engine_id == "combined"
        else report_engine_id
    )
    api_key = resolve_api_key(
        engine_id,
        lambda: load_saved_api_key(engine_id, keyring_module=_keyring_module(request)),
    )
    if not api_key:
        return JSONResponse({"reason": "no_key"}, status_code=400)

    root = Path(report.root)
    policy = load_default_policy()
    quota = parse_quota_policy(policy)

    # Eagerly validate eligibility so the caller gets a synchronous 4xx.
    # The Core enforces these same guards again inside scan_single_file.
    # SKIPPED is checked before read_magic to avoid reading bytes of sensitive files.
    try:
        record = record_from_path(root, file.relative_path)
        base = classify_file(record, policy)
        if base.bucket == ClassificationBucket.SKIPPED:
            reason = base.skip_reason.value if base.skip_reason is not None else "not_eligible"
            return JSONResponse({"reason": reason}, status_code=400)
        prefix = read_magic(record.path)
        cls = reclassify_with_signals(record, base, prefix, policy)
        if risk_tier_for(cls.bucket) != RiskTier.PRIORITY:
            return JSONResponse({"reason": "not_priority"}, status_code=400)
        if not cls.upload_eligible:
            return JSONResponse({"reason": "too_large"}, status_code=400)
    except FileNotFoundError:
        return JSONResponse({"reason": "vanished"}, status_code=400)
    except InventoryPathError:
        return JSONResponse({"reason": "invalid_path"}, status_code=400)

    manager = request.app.state.file_scan_manager

    async def _coro():
        global_store = open_global_store()
        try:
            cache = EngineCache(global_store, ttl_days=quota.cache_ttl_days)
            client = _build_engine_client(request, api_key, quota, global_store, engine_id)
            try:
                result = await scan_single_file(
                    root, file.relative_path, client, cache, policy=policy
                )
            finally:
                await client.close()
            registry.update_file(report_id, index, result)
            return result
        finally:
            global_store.close()

    try:
        job = manager.enqueue(report_id, index, _coro)
    except JobBusy:
        return JSONResponse({"error": "a scan is already in progress"}, status_code=409)
    return JSONResponse({"job_id": job.id}, status_code=202)


@router.get("/reports/{report_id}/files/{index}/scan/events")
def scan_report_file_events(request: Request, report_id: str, index: int) -> Response:
    """SSE stream of state transitions for a per-file scan job."""
    manager = request.app.state.file_scan_manager
    job = manager.latest(report_id, index)
    if job is None:
        return JSONResponse({"error": "unknown job"}, status_code=404)

    async def _stream():
        queue = job.subscribe()
        try:
            yield _sse({"state": job.state})
            while not job.is_terminal:
                state = await queue.get()
                if state != "done" and state != "error":
                    yield _sse({"state": state})
            yield _sse(_file_terminal_payload(request, report_id, index, job))
        finally:
            job.unsubscribe(queue)

    return StreamingResponse(
        _stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/reports/{report_id}/scan-unverified")
async def scan_unverified(request: Request, report_id: str) -> Response:
    """Start or return the active server-side batch for upload-eligible attention files."""
    registry = request.app.state.report_registry
    report = registry.get(report_id)
    if report is None:
        return JSONResponse({"error": "report expired or unavailable"}, status_code=404)
    indices = [
        f.index
        for f in report.files
        if _is_unresolved_scan_candidate(f)
    ]
    if not indices:
        return JSONResponse({"indices": [], "active": False}, status_code=202)
    manager = request.app.state.batch_file_scan_manager
    existing = manager.active_for_report(report_id)
    if existing is not None:
        return JSONResponse(
            {"job_id": existing.id, "indices": existing.indices, "active": True},
            status_code=202,
        )

    engine_ids = _report_engine_ids(report)
    keys = {
        engine_id: resolve_api_key(
            engine_id,
            lambda engine_id=engine_id: load_saved_api_key(
                engine_id, keyring_module=_keyring_module(request)
            ),
        )
        for engine_id in engine_ids
    }
    missing = [engine_id for engine_id, key in keys.items() if key is None]
    if missing:
        names = ", ".join(ENGINES[engine_id].display_name for engine_id in missing)
        return JSONResponse(
            {"reason": "no_key", "error": f"API key required for: {names}"},
            status_code=400,
        )

    async def _runner(job):
        await _run_scan_unverified_batch(request, report_id, list(indices), keys, job)

    try:
        job = manager.enqueue(report_id, indices, _runner)
    except JobBusy:
        return JSONResponse({"error": "a scan is already in progress"}, status_code=409)
    return JSONResponse({"job_id": job.id, "indices": indices, "active": False}, status_code=202)


@router.get("/reports/{report_id}/scan-unverified/active")
def active_scan_unverified(request: Request, report_id: str) -> Response:
    report = request.app.state.report_registry.get(report_id)
    if report is None:
        return JSONResponse({"error": "report expired or unavailable"}, status_code=404)
    job = request.app.state.batch_file_scan_manager.active_for_report(report_id)
    if job is None:
        job = request.app.state.batch_file_scan_manager.recent_for_report(report_id)
    if job is None:
        return JSONResponse({"active": False})
    return JSONResponse({
        "active": not job.is_terminal,
        "job_id": job.id,
        "last": job.last_event,
    })


@router.get("/reports/{report_id}/scan-unverified/{job_id}/events")
def scan_unverified_events(request: Request, report_id: str, job_id: str) -> Response:
    job = request.app.state.batch_file_scan_manager.get(job_id)
    if job is None or job.report_id != report_id:
        return JSONResponse({"error": "unknown job"}, status_code=404)

    async def _stream():
        queue = job.subscribe()
        try:
            terminal_sent = False
            for event in job.replay_events():
                yield _sse(event)
                terminal_sent = terminal_sent or event.get("state") in {
                    "done", "cancelled", "error"
                }
            while not terminal_sent:
                event = await queue.get()
                yield _sse(event)
                terminal_sent = event.get("state") in {"done", "cancelled", "error"}
        finally:
            job.unsubscribe(queue)

    return StreamingResponse(
        _stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/reports/{report_id}/scan-unverified/{job_id}/cancel")
async def cancel_scan_unverified(request: Request, report_id: str, job_id: str) -> Response:
    job = request.app.state.batch_file_scan_manager.get(job_id)
    if job is None or job.report_id != report_id:
        return JSONResponse({"error": "unknown job"}, status_code=404)
    if job.is_terminal:
        return JSONResponse({
            "status": job.state,
            "terminal": True,
            "last": job.last_event,
        })
    job.cancel()
    job.emit({"state": "cancelling", **_batch_progress_payload(request, report_id, job)})
    return JSONResponse({"status": "cancelling"})


def _report_engine_ids(report) -> list[str]:
    return COMBINED_ENGINE_IDS if report.engine_id == "combined" else [report.engine_id]


def _summary_payload(report) -> dict[str, int]:
    if report is None:
        return {}
    summary = report.summary
    return {
        "inventoried": summary.inventoried,
        "scanned": summary.scanned,
        "infected": summary.infected,
        "needs_attention": summary.needs_attention,
        "uploaded": summary.uploaded,
        "skipped": summary.skipped,
        "errors": summary.errors,
    }


def _batch_progress_payload(request: Request, report_id: str, job) -> dict:
    report = request.app.state.report_registry.get(report_id)
    payload = {
        "total": len(job.indices),
        "processed": int(job.last_event.get("processed", 0)),
    }
    if report is not None:
        payload["summary"] = _summary_payload(report)
    return payload


def _clone_result_for_report_file(root: Path, file, source: FileResult) -> FileResult | None:
    try:
        record = record_from_path(root, file.relative_path)
    except (FileNotFoundError, InventoryPathError):
        return None
    result = FileResult(
        record=record,
        classification=Classification(
            ClassificationBucket(file.classification_bucket),
            file.classification_reason,
            upload_eligible=file.upload_eligible,
            hash_eligible=file.hash_eligible,
            suspicious=file.suspicious,
        ),
        sha256=file.sha256 or source.sha256,
        engine_id=source.engine_id,
        outcome=source.outcome,
        outcome_reason=source.outcome_reason,
        lookup_status=source.lookup_status,
        upload_status=source.upload_status,
        engine_state=source.engine_state,
        risk_label=source.risk_label,
        report_category=source.report_category,
        permalink=source.permalink,
        engine_stats=dict(source.engine_stats),
        detections=[dict(detection) for detection in source.detections],
        raw_result=source.raw_result,
        action=source.action,
        analysis_status=source.analysis_status,
        assessment_complete=source.assessment_complete,
        last_analysis_at=source.last_analysis_at,
        executable_bit=file.executable_bit,
        shebang=file.shebang,
        elf=file.elf,
    )
    return result


def _record_for_report_file(root: Path, file) -> FileRecord:
    try:
        return record_from_path(root, file.relative_path)
    except (FileNotFoundError, InventoryPathError):
        path = root / Path(file.relative_path).name
        return FileRecord(
            root=root,
            path=path,
            size=file.size,
            mtime_ns=0,
            mode=0,
            is_symlink=False,
            is_regular=True,
            is_hidden=any(part.startswith(".") for part in Path(file.relative_path).parts),
        )


def _error_result_for_report_file(root: Path, file, error: ErrorCode) -> FileResult:
    result = FileResult(
        record=_record_for_report_file(root, file),
        classification=Classification(
            ClassificationBucket(file.classification_bucket),
            file.classification_reason,
            upload_eligible=file.upload_eligible,
            hash_eligible=file.hash_eligible,
            suspicious=file.suspicious,
        ),
        sha256=file.sha256,
        engine_id=file.engine_id,
        engine_state=EngineState.ERROR,
        action=ReportAction.FAILED,
        executable_bit=file.executable_bit,
        shebang=file.shebang,
        elf=file.elf,
    )
    result.errors.append(error)
    return result


async def _run_scan_unverified_batch(
    request: Request,
    report_id: str,
    indices: list[int],
    keys: dict[str, str],
    job,
) -> None:
    registry = request.app.state.report_registry
    initial_report = registry.get(report_id)
    if initial_report is None:
        registry.flush(report_id)
        job.emit({"state": "error", "error": "report expired or unavailable"})
        return
    root = Path(initial_report.root)
    policy = load_default_policy()
    quota = parse_quota_policy(policy)
    global_store = open_global_store()
    clients = []
    try:
        cache = EngineCache(global_store, ttl_days=quota.cache_ttl_days)
        for engine_id in _report_engine_ids(initial_report):
            clients.append(
                _build_engine_client(request, keys[engine_id], quota, global_store, engine_id)
            )
        rotation = build_rotation(_report_engine_ids(initial_report), clients)
        groups: dict[str, list[int]] = {}
        for index in indices:
            report = registry.get(report_id)
            if report is None or not (0 <= index < len(report.files)):
                continue
            file = report.files[index]
            key = file.sha256 or f"idx:{index}"
            groups.setdefault(key, []).append(index)

        processed = 0
        job.emit({
            "state": "running",
            "total": len(indices),
            "processed": processed,
            "groups": len(groups),
            "summary": _summary_payload(registry.get(report_id)),
        })
        for group_indices in groups.values():
            if job.cancel_requested:
                registry.flush(report_id)
                job.emit({
                    "state": "cancelled",
                    "processed": processed,
                    "total": len(indices),
                    "summary": _summary_payload(registry.get(report_id)),
                })
                return
            report = registry.get(report_id)
            if report is None:
                registry.flush(report_id)
                job.emit({"state": "error", "error": "report expired or unavailable"})
                return
            representative = report.files[group_indices[0]]

            def state_callback(
                state: str,
                engine_id: str | None,
                *,
                current_index: int = representative.index,
                current_path: str = representative.relative_path,
                current_processed: int = processed,
            ) -> None:
                if job.cancel_requested:
                    return
                job.emit({
                    "state": state,
                    "current_index": current_index,
                    "current_path": current_path,
                    "current_engine_id": engine_id,
                    "processed": current_processed,
                    "total": len(indices),
                    "summary": _summary_payload(registry.get(report_id)),
                })

            try:
                result = await scan_single_file_with_rotation(
                    root,
                    representative.relative_path,
                    rotation,
                    cache,
                    policy=policy,
                    state_callback=state_callback,
                )
            except Exception:
                for index in group_indices:
                    current = registry.get(report_id)
                    if current is None or not (0 <= index < len(current.files)):
                        continue
                    failed_file = current.files[index]
                    update_result = _error_result_for_report_file(
                        root,
                        failed_file,
                        ErrorCode.ENGINE_CLIENT_ERROR,
                    )
                    updated = registry.update_file(report_id, index, update_result)
                    processed += 1
                    job.emit({
                        "state": "file_error",
                        "current_index": index,
                        "current_path": failed_file.relative_path,
                        "processed": processed,
                        "total": len(indices),
                        "summary": _summary_payload(updated),
                        **(
                            _live_file_payload(updated.files[index])
                            if updated is not None and 0 <= index < len(updated.files)
                            else {}
                        ),
                    })
                if job.cancel_requested:
                    registry.flush(report_id)
                    job.emit({
                        "state": "cancelled",
                        "processed": processed,
                        "total": len(indices),
                        "summary": _summary_payload(registry.get(report_id)),
                    })
                    return
                continue

            for index in group_indices:
                current = registry.get(report_id)
                if current is None or not (0 <= index < len(current.files)):
                    continue
                update_result = (
                    result
                    if index == representative.index
                    else _clone_result_for_report_file(root, current.files[index], result)
                )
                if update_result is None:
                    update_result = _error_result_for_report_file(
                        root,
                        current.files[index],
                        ErrorCode.FILE_VANISHED,
                    )
                    updated = registry.update_file(report_id, index, update_result)
                    processed += 1
                    job.emit({
                        "state": "file_error",
                        "current_index": index,
                        "current_path": current.files[index].relative_path,
                        "processed": processed,
                        "total": len(indices),
                        "summary": _summary_payload(updated),
                        **(
                            _live_file_payload(updated.files[index])
                            if updated is not None and 0 <= index < len(updated.files)
                            else {}
                        ),
                    })
                    continue
                registry.update_file(report_id, index, update_result)
                processed += 1
                updated = registry.get(report_id)
                job.emit({
                    "state": "file_done",
                    "current_index": index,
                    "current_path": current.files[index].relative_path,
                    "outcome": update_result.outcome.value,
                    "processed": processed,
                    "total": len(indices),
                    "summary": _summary_payload(updated),
                    **(
                        _live_file_payload(updated.files[index])
                        if updated is not None and 0 <= index < len(updated.files)
                        else {}
                    ),
                })
            if job.cancel_requested:
                registry.flush(report_id)
                job.emit({
                    "state": "cancelled",
                    "processed": processed,
                    "total": len(indices),
                    "summary": _summary_payload(registry.get(report_id)),
                })
                return

        registry.flush(report_id)
        job.emit({
            "state": "done",
            "processed": processed,
            "total": len(indices),
            "summary": _summary_payload(registry.get(report_id)),
        })
    finally:
        for client in clients:
            await client.close()
        global_store.close()
