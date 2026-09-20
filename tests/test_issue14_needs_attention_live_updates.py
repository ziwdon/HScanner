"""
Regression tests for issue #14: Needs-attention live updates on the report page.

1. A per-file scan result must not un-hide tier groups the user filtered out with
   the High / Medium / Lower-risk pills.
2. Empty tier groups are hidden on the initial render, not only after a live update.
3. A tier group created live (fresh Needs-attention section) auto-opens for ``high``.
4. A capped subgroup ("Showing first 500 of N") keeps its count badge and note in
   step with live updates.

The JS lives inline in ``report.html``; tests 1, 3 and 4 drive the real page in jsdom
via ``tests/js/groups_driver.mjs`` and skip without node deps (see
``test_report_page_queue_js.py``). Test 2 only needs the rendered template.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path

import httpx
import pytest
from test_report_page_queue_js import (  # rootdir-relative (no tests/__init__.py)
    JS_DIR,
    NODE,
    SCAN_SECONDS,
    _js_deps_available,
    _LiveServer,
    _SlowNotFoundEngine,
)

from hscanner.engines.base import EngineFileReport
from hscanner.errors import ErrorCode, HScannerError

DRIVER = JS_DIR / "groups_driver.mjs"

needs_js = pytest.mark.skipif(
    not _js_deps_available(),
    reason="node + jsdom/eventsource required (npm --prefix tests/js install)",
)


def _drive(server: _LiveServer, *, pill: str = "", scan_selector: str = "") -> dict[str, dict]:
    env = {
        **os.environ,
        "BASE": server.base,
        "REPORT_ID": server.report_id,
        "PILL": pill,
        "SCAN_SELECTOR": scan_selector,
    }
    proc = subprocess.run(
        [NODE, str(DRIVER)], cwd=JS_DIR, env=env, capture_output=True, text=True, timeout=120
    )
    assert proc.returncode == 0, proc.stderr
    records = [json.loads(line) for line in proc.stdout.splitlines() if line.startswith("{")]
    return {r["label"]: r["section"] for r in records}


def _groups(section: dict) -> dict[str, dict]:
    return {g["key"]: g for g in section["groups"]}


def _write_sh(folder: Path) -> str:
    """Write a unique High-tier file and return its SHA-256."""
    body = f"echo {time.time_ns()}\n".encode()
    (folder / "run.sh").write_bytes(body)
    return hashlib.sha256(body).hexdigest()


def _mixed_folder(tmp_path: Path) -> Path:
    """One High (.sh) and two Medium (.py) unknown files."""
    folder = tmp_path / "root"
    folder.mkdir()
    (folder / "run.sh").write_text(f"echo {time.time_ns()}\n", encoding="utf-8")
    for i in (1, 2):
        (folder / f"a{i}.py").write_text(f"print({i}, {time.time_ns()})\n", encoding="utf-8")
    return folder


@needs_js
def test_live_update_keeps_the_pressed_pill_filter(tmp_path) -> None:
    """Residual 1: with the High pill pressed, finishing a Medium file's scan must
    recount the Medium group but leave it hidden."""
    with _LiveServer(_mixed_folder(tmp_path)) as server:
        snaps = _drive(
            server, pill="high", scan_selector='details.group[data-group="medium"] .btn-scan'
        )

    after_pill = _groups(snaps["after-pill"])
    assert snaps["after-pill"]["pressed"] == "high"
    assert after_pill["high"]["hidden"] is False
    assert after_pill["medium"]["hidden"] is True

    after_scan = snaps["after-scan"]
    assert after_scan["pressed"] == "high", after_scan
    groups = _groups(after_scan)
    assert groups["medium"]["count"] == "1", groups
    assert after_scan["chips"]["medium"] == "1", after_scan
    assert groups["medium"]["hidden"] is True, groups
    assert groups["high"]["hidden"] is False, groups


def test_empty_tier_group_is_hidden_on_initial_render(tmp_path) -> None:
    """Residual 2: with bypass on, "Lower risk" has no files and must not render as a
    visible "Lower risk 0" group."""
    with _LiveServer(_mixed_folder(tmp_path)) as server:
        html = httpx.get(f"{server.base}/reports/{server.report_id}", timeout=5).text

    tags = {
        m.group(1): m.group(0)
        for m in re.finditer(r'<details class="group" data-group="([a-z_]+)"[^>]*>', html)
    }
    assert set(tags) == {"high", "medium", "low_risk"}, tags
    assert " hidden" in tags["low_risk"], tags["low_risk"]
    assert " hidden" not in tags["high"], tags["high"]
    assert " hidden" not in tags["medium"], tags["medium"]


class _ErrorThenUnresolvedEngine(_SlowNotFoundEngine):
    """The first hash lookup of each SHA in ``error_once`` fails (folder scan → Errors);
    every other lookup finds nothing, and an upload's analysis stays incomplete, so a
    rescanned Errors file lands in Needs attention. ``error_once`` is class-level
    because the app builds a fresh engine per job — instance state would not carry
    from the folder scan to the per-file rescan."""

    error_once: set[str] = set()

    async def get_file_report(self, sha256):
        if sha256 in self.error_once:
            self.error_once.discard(sha256)
            raise HScannerError(ErrorCode.ENGINE_CLIENT_ERROR, "boom")
        return None

    async def wait_for_analysis(self, analysis_id, sha256):
        await asyncio.sleep(SCAN_SECONDS / 2)
        return EngineFileReport(engine_stats={}, assessment_complete=False, raw={})


@needs_js
def test_live_created_high_group_auto_opens(tmp_path) -> None:
    """Residual 3: a High group created by a live update (here: an Errors file whose
    rescan ends in Needs attention) is auto-opened like the static render's High group."""
    folder = tmp_path / "root"
    folder.mkdir()
    _ErrorThenUnresolvedEngine.error_once = {_write_sh(folder)}
    with _LiveServer(folder, engine_factory=_ErrorThenUnresolvedEngine) as server:
        snaps = _drive(server, scan_selector="#errors .btn-scan")

    assert snaps["initial"] is None, "Needs attention must start absent"
    after = snaps["after-scan"]
    assert after is not None, "the rescan must move the file into Needs attention"
    groups = _groups(after)
    assert groups["high"]["count"] == "1", groups
    assert groups["high"]["open"] is True, groups


@needs_js
def test_empty_rendered_high_group_opens_when_filled_live(tmp_path) -> None:
    """Residual 2 + 3 together: a High group rendered empty (hidden) must still open
    when a live update fills it — hiding must not cost the static High auto-open."""
    folder = tmp_path / "root"
    folder.mkdir()
    (folder / "a1.py").write_text(f"print({time.time_ns()})\n", encoding="utf-8")
    _ErrorThenUnresolvedEngine.error_once = {_write_sh(folder)}
    with _LiveServer(folder, engine_factory=_ErrorThenUnresolvedEngine) as server:
        snaps = _drive(server, scan_selector="#errors .btn-scan")

    initial = _groups(snaps["initial"])
    assert (initial["high"]["hidden"], initial["high"]["count"]) == (True, "0"), initial
    after = _groups(snaps["after-scan"])
    assert (after["high"]["hidden"], after["high"]["count"]) == (False, "1"), after
    assert after["high"]["open"] is True, after


@needs_js
def test_capped_subgroup_note_and_count_follow_live_updates(tmp_path) -> None:
    """Residual 4: a subgroup over the 500-row cap keeps its true total in the badge
    and its "Showing first N of M" note current after a file leaves it."""
    folder = tmp_path / "root"
    folder.mkdir()
    for i in range(1, 503):
        (folder / f"a{i:03d}.py").write_text(f"print({i}, {time.time_ns()})\n", encoding="utf-8")
    with _LiveServer(folder) as server:
        snaps = _drive(server, scan_selector='details.subgroup[data-subgroup="py"] .btn-scan')

    before = _groups(snaps["initial"])["medium"]["subgroups"][0]
    assert (before["count"], before["cards"]) == ("502", 500), before
    assert before["note"].startswith("Showing first 500 of 502"), before

    after_medium = _groups(snaps["after-scan"])["medium"]
    after = after_medium["subgroups"][0]
    assert after["cards"] == 499, after
    assert after["count"] == "501", after
    assert after_medium["count"] == "501", after_medium
    assert snaps["after-scan"]["chips"]["medium"] == "501", snaps["after-scan"]
    assert snaps["after-scan"]["count"] == "501", snaps["after-scan"]
    assert after["note"].startswith("Showing first 499 of 501"), after
