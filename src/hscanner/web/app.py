from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from hscanner.web.jobs import BatchFileScanManager, FileScanManager, JobManager
from hscanner.web.persistent_reports import PersistentReportStore
from hscanner.web.report_store import ReportRegistry
from hscanner.web.routes import router

_STATIC_DIR = Path(__file__).parent / "static"


def create_app(
    keyring_module: Any | None = None,
    engine_factory: Any | None = None,
    report_registry: ReportRegistry | None = None,
) -> FastAPI:
    app = FastAPI(title="HScanner")
    app.state.keyring_module = keyring_module
    app.state.engine_factory = engine_factory
    app.state.report_registry = (
        report_registry
        if report_registry is not None
        else ReportRegistry(persistent_store=PersistentReportStore())
    )
    app.state.job_manager = JobManager()
    app.state.file_scan_manager = FileScanManager(
        job_scan_guard=lambda: app.state.job_manager._active() is not None
        or app.state.batch_file_scan_manager.has_active()
    )
    app.state.batch_file_scan_manager = BatchFileScanManager(
        job_scan_guard=lambda: app.state.job_manager._active() is not None
        or app.state.file_scan_manager.has_active()
    )
    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")
    app.include_router(router)
    return app
