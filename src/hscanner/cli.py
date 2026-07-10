import asyncio
import json
from pathlib import Path

import typer
from typer.main import get_command

# Typer bundles its own fork of Click (typer._click); import that rather
# than the standalone `click` package so exception isinstance checks work.
try:
    import typer._click as _click  # type: ignore[import]
except ImportError:
    import click as _click  # type: ignore[no-redef]

from hscanner.budget import QuotaCounter, RequestBudget
from hscanner.cache import EngineCache
from hscanner.engines.base import ScanEngine
from hscanner.engines.registry import (
    COMBINED_ENGINE_IDS,
    ENGINES,
    build_engine,
    build_rotation,
    engine_ids,
)
from hscanner.exporters import ExportError, export_report
from hscanner.keys import load_saved_api_key, resolve_api_key
from hscanner.models import ScanStatus
from hscanner.policy.loader import load_default_policy, parse_quota_policy
from hscanner.report import ScanReport, build_scan_report, cli_exit_code, report_payload
from hscanner.scanner import (
    finalize_unchecked_results,
    run_local_scan,
    run_online_scan,
    single_engine_rotation,
)
from hscanner.state import ScanState
from hscanner.store import open_global_store, open_scan_store

app = typer.Typer()


@app.callback()
def _main_callback() -> None:
    """HScanner — local file triage with optional VirusTotal enrichment."""


def _build_engine_client(
    api_key: str,
    policy,
    max_requests: int | None = None,
    engine_id: str = "virustotal",
) -> ScanEngine:
    quota = parse_quota_policy(policy)
    global_store = open_global_store()
    counter = QuotaCounter(
        global_store,
        engine_id=engine_id,
        daily=quota.daily_request_budget,
        monthly=quota.monthly_request_budget,
    )
    budget = RequestBudget(
        per_minute=quota.requests_per_minute,
        quota=counter,
        max_requests=max_requests,
    )
    return build_engine(
        engine_id,
        api_key,
        budget=budget,
        poll_timeout=quota.polling_timeout_seconds,
    )


def _combined_keys() -> tuple[dict[str, str], list[str]]:
    keys: dict[str, str] = {}
    missing: list[str] = []
    for engine_id in COMBINED_ENGINE_IDS:
        key = resolve_api_key(
            engine_id, lambda engine_id=engine_id: load_saved_api_key(engine_id)
        )
        if key is None:
            missing.append(engine_id)
        else:
            keys[engine_id] = key
    return keys, missing


def _build_combined_rotation(keys, policy, max_requests, *, wait_threshold):
    engines = [
        _build_engine_client(keys[engine_id], policy, max_requests, engine_id=engine_id)
        for engine_id in COMBINED_ENGINE_IDS
    ]
    return build_rotation(
        COMBINED_ENGINE_IDS, engines, wait_threshold=wait_threshold
    )


def _emit(report: ScanReport, json_output: bool) -> None:
    if json_output:
        typer.echo(json.dumps(report_payload(report), indent=2, sort_keys=True))
        return
    for file in report.files:
        typer.echo(
            f"{file.report_category}\t{file.relative_path}\t{file.sha256 or '-'}"
        )


def _export_and_emit(report: ScanReport, report_path: Path | None, json_output: bool) -> None:
    if report_path is not None:
        try:
            export_report(report, report_path)
        except ExportError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(3) from exc
    _emit(report, json_output)


@app.command()
def scan(
    path: Path,
    json_output: bool = typer.Option(
        False, "--json", help="Emit structured JSON output instead of tab-separated text."
    ),
    resume: bool = typer.Option(
        False, "--resume", help="Resume an interrupted scan of this folder."
    ),
    refresh: bool = typer.Option(
        False, "--refresh", help="Ignore the cache and force re-query."
    ),
    report_path: Path | None = typer.Option(  # noqa: B008
        None, "--report", help="Write a .json, .html, or .csv report."
    ),
    require_engine: bool = typer.Option(
        False, "--require-engine", help="Return code 4 if no engine API key is available."
    ),
    max_requests: int | None = typer.Option(
        None,
        "--max-requests",
        help="Override the per-scan request ceiling (per-engine in combined mode).",
    ),
    bypass_low_risk: bool = typer.Option(
        True,
        "--bypass-low-risk/--no-bypass-low-risk",
        help="Hash low-risk files locally but skip their VirusTotal lookups (default on).",
    ),
    engine: str = typer.Option(
        "virustotal",
        "--engine",
        help="Scan engine: virustotal, metadefender, or combined.",
    ),
    wait_threshold: float = typer.Option(
        300.0,
        "--wait-threshold",
        help="Seconds to wait through a cross-engine cooldown before stopping resumably.",
    ),
) -> None:
    # -----------------------------------------------------------------------
    # Pre-scan validation — before key resolution or any scanning starts
    # -----------------------------------------------------------------------
    if not path.is_dir():
        typer.echo(f"Not a directory: {path}", err=True)
        raise typer.Exit(3)
    if max_requests is not None and max_requests <= 0:
        typer.echo("--max-requests must be positive", err=True)
        raise typer.Exit(3)
    if wait_threshold <= 0:
        typer.echo("--wait-threshold must be positive", err=True)
        raise typer.Exit(3)
    if report_path is not None:
        if report_path.suffix.lower() not in {".json", ".html", ".csv"}:
            typer.echo("--report must end in .json, .html, or .csv", err=True)
            raise typer.Exit(3)
        if not report_path.parent.is_dir():
            typer.echo(f"Report directory does not exist: {report_path.parent}", err=True)
            raise typer.Exit(3)

    # -----------------------------------------------------------------------
    # Policy loading — catch bad YAML / validation errors early
    # -----------------------------------------------------------------------
    try:
        policy = load_default_policy()
        quota = parse_quota_policy(policy)
    except ValueError as exc:
        typer.echo(f"Policy error: {exc}", err=True)
        raise typer.Exit(3) from exc

    # -----------------------------------------------------------------------
    # Engine validation
    # -----------------------------------------------------------------------
    valid_engines = set(engine_ids()) | {"combined"}
    if engine not in valid_engines:
        typer.echo(
            f"Unknown engine: {engine}. Choose from: {', '.join(sorted(valid_engines))}",
            err=True,
        )
        raise typer.Exit(3)

    # -----------------------------------------------------------------------
    # Key resolution
    # -----------------------------------------------------------------------
    api_key = None
    if engine != "combined":
        api_key = resolve_api_key(engine, lambda: load_saved_api_key(engine))
        missing_engine_ids = [engine] if api_key is None else []
    else:
        combined_keys, missing_engine_ids = _combined_keys()

    if missing_engine_ids:
        names = ", ".join(ENGINES[engine_id].display_name for engine_id in missing_engine_ids)
        typer.echo(
            f"Missing API key for: {names}. Running local-only inventory.",
            err=True,
        )
        local_results = run_local_scan(path)
        finalize_unchecked_results(local_results, bypass_low_risk=bypass_low_risk)
        status = ScanStatus.KEY_MISSING if require_engine else ScanStatus.COMPLETED
        report_engine_id = "combined" if engine == "combined" else engine
        report_engine_name = "Combined" if engine == "combined" else ENGINES[engine].display_name
        report = build_scan_report(
            path,
            local_results,
            online=False,
            upload_consent=False,
            engine_id=report_engine_id,
            engine_name=report_engine_name,
            status=status,
        )
        _export_and_emit(report, report_path, json_output)
        raise typer.Exit(cli_exit_code(report))

    # -----------------------------------------------------------------------
    # Online scan
    # -----------------------------------------------------------------------
    effective_max_requests = (
        max_requests
        if max_requests is not None
        else quota.per_scan_request_budget
    )
    if engine == "combined":
        rotation = _build_combined_rotation(
            combined_keys, policy, effective_max_requests, wait_threshold=wait_threshold
        )
    else:
        client = _build_engine_client(
            api_key, policy, effective_max_requests, engine_id=engine
        )
        rotation = single_engine_rotation(client, wait_threshold=wait_threshold)
    scan_state = ScanState(open_scan_store(path), path)
    scan_state.start_or_resume(resume=resume)
    cache = EngineCache(open_global_store(), ttl_days=quota.cache_ttl_days)

    async def _run():
        try:
            return await run_online_scan(
                path,
                rotation,
                upload_consent=False,
                cache=cache,
                scan_state=scan_state,
                refresh=refresh,
                bypass_low_risk=bypass_low_risk,
            )
        finally:
            for slot in rotation._slots:
                await slot.engine.close()

    outcome = asyncio.run(_run())
    is_combined = engine == "combined"
    report = build_scan_report(
        path,
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
    _export_and_emit(report, report_path, json_output)
    raise typer.Exit(cli_exit_code(report))


# ---------------------------------------------------------------------------
# Process boundary — maps all exit paths to deterministic codes,
# never prints tracebacks that could expose the API key.
# ---------------------------------------------------------------------------


def main() -> None:
    command = get_command(app)
    try:
        exit_code = command.main(prog_name="hscanner", standalone_mode=False)
    except _click.exceptions.UsageError as exc:
        exc.show()
        raise SystemExit(3) from exc
    except Exception as exc:
        typer.echo("Internal error", err=True)
        raise SystemExit(6) from exc
    raise SystemExit(int(exit_code or 0))
