"""Regression tests for GitHub issue #10: priority tiers must come from a
complete, curated extension -> tier table. File *metadata* (size, exec
bit) must never raise the tier; only content (ELF/shebang) may."""
import copy
from pathlib import Path

import pytest

from hscanner.classifier import classify_file, risk_tier_for_extension
from hscanner.models import (
    ClassificationBucket,
    FileRecord,
    FileResult,
    LookupStatus,
    OutcomeReason,
    RiskTier,
    ScanOutcome,
)
from hscanner.policy.loader import load_default_policy
from hscanner.report import _report_file_from_payload, build_scan_report
from hscanner.report_view import build_report_view


def _record(name: str, size: int = 10, mode: int = 0o100644) -> FileRecord:
    return FileRecord(
        root=Path("/scan"), path=Path("/scan") / name,
        size=size, mtime_ns=1, mode=mode,
        is_symlink=False, is_regular=True, is_hidden=name.startswith("."),
    )


def _soft_limit_plus_one(policy) -> int:
    return policy["size_limits"]["large_upload_soft_block_mb"] * 1024 * 1024 + 1


# --- Fallbacks: metadata never raises the tier -----------------------------


def test_oversized_unknown_extension_is_low_risk_hash_only():
    """Issue repro: a 250 MB foo.zip-like *unknown* file used to become
    SUSPICIOUS_UPLOAD_BLOCKED / HIGH purely because of its size."""
    policy = load_default_policy()
    c = classify_file(_record("blob.qqq", size=_soft_limit_plus_one(policy)), policy)
    assert c.bucket == ClassificationBucket.HASH_ONLY
    assert c.risk_tier == RiskTier.LOW_RISK
    assert c.upload_eligible is False
    assert c.hash_eligible is True


def test_exec_bit_on_unknown_extension_is_low_risk_by_default():
    """Issue repro: chmod +x data.nsp-like unknown file used to become HIGH
    from the mode bits alone (FAT/NTFS copies are 0777 en masse)."""
    policy = load_default_policy()
    c = classify_file(_record("weird.xyz", mode=0o100755), policy)
    assert c.bucket == ClassificationBucket.HASH_ONLY
    assert c.risk_tier == RiskTier.LOW_RISK
    assert c.upload_eligible is False


def test_exec_bit_promotion_remains_available_as_policy_opt_in():
    policy = copy.deepcopy(load_default_policy())
    assert policy["buckets"]["upload_candidate"]["executable_bit"] is False
    policy["buckets"]["upload_candidate"]["executable_bit"] = True
    c = classify_file(_record("weird.xyz", mode=0o100755), policy)
    assert c.bucket == ClassificationBucket.UPLOAD_CANDIDATE
    assert c.risk_tier == RiskTier.HIGH


def test_oversized_medium_archive_keeps_medium_tier_and_blocks_upload():
    policy = load_default_policy()
    c = classify_file(_record("big.zip", size=_soft_limit_plus_one(policy)), policy)
    assert c.bucket == ClassificationBucket.SUSPICIOUS_UPLOAD_BLOCKED
    assert c.risk_tier == RiskTier.MEDIUM
    assert c.upload_eligible is False
    assert c.hash_eligible is True


# --- Table spot checks, one per family --------------------------------------


@pytest.mark.parametrize("name", [
    "a.exe", "a.dll", "a.sys", "a.efi",            # PE / native
    "a.so", "a.dylib", "a.elf", "a.ko", "a.run",   # ELF / Mach-O
    "a.msi", "a.deb", "a.pkg", "a.dmg", "a.apk", "a.snap", "a.flatpak",
    "a.sh", "a.fish", "a.bat", "a.ps1", "a.psm1", "a.vbe", "a.jse", "a.hta",
    "a.scpt", "a.applescript",
    "a.lnk", "a.url", "a.inf", "a.reg", "a.msc", "a.desktop",
])
def test_high_family_extensions(name):
    c = classify_file(_record(name), load_default_policy())
    assert c.bucket == ClassificationBucket.UPLOAD_CANDIDATE, name
    assert c.risk_tier == RiskTier.HIGH, name
    assert c.upload_eligible is True, name


@pytest.mark.parametrize("name", [
    "a.py", "a.pyw", "a.pyo", "a.pyz",             # Python
    "a.rpy", "a.rpa",                              # Ren'Py
    "a.php", "a.lua", "a.tcl", "a.awk", "a.js", "a.mjs", "a.groovy", "a.ahk",
    "a.jar", "a.war", "a.class", "a.dex", "a.wasm",
    "a.o", "a.a", "a.bin",                         # native object, .bin demoted
    "a.zip", "a.7z", "a.rar", "a.tar", "a.gz", "a.xz", "a.zst", "a.cab", "a.iso", "a.img",
    "a.xpi", "a.crx", "a.whl", "a.gem", "a.nupkg",
    "a.docm", "a.xlsm", "a.pptm", "a.doc", "a.xls", "a.ppt", "a.chm",
    "a.nsp", "a.xci", "a.nca", "a.nro", "a.nds", "a.gba",
    "a.pkl", "a.pickle",
])
def test_medium_family_extensions(name):
    c = classify_file(_record(name), load_default_policy())
    assert c.bucket == ClassificationBucket.UPLOAD_CANDIDATE, name
    assert c.risk_tier == RiskTier.MEDIUM, name
    assert c.upload_eligible is True, name


@pytest.mark.parametrize("name", [
    "a.json", "a.ini", "a.plist", "a.db", "a.sqlite", "a.ipynb",
    "a.c", "a.cpp", "a.rs", "a.go", "a.java", "a.ts", "a.tsx", "a.cs", "a.pyx", "a.pxd",
    "a.pdf", "a.docx", "a.odt", "a.rtf", "a.epub",
    "a.gif", "a.webp", "a.bmp", "a.psd", "a.dds",
    "a.mp3", "a.flac", "a.webm", "a.avi", "a.mov", "a.srt",
    "a.woff", "a.woff2",
    "a.pak", "a.assets", "a.ress", "a.resource", "a.uasset", "a.bsa", "a.esp",
    "a.wad", "a.dat", "a.win", "a.gds", "a.sav",
    "a.safetensors", "a.gguf", "a.onnx",
])
def test_low_risk_family_extensions(name):
    c = classify_file(_record(name, mode=0o100755), load_default_policy())
    assert c.bucket == ClassificationBucket.HASH_ONLY, name
    assert c.risk_tier == RiskTier.LOW_RISK, name
    assert c.upload_eligible is False, name


def test_tier_lists_are_disjoint_and_have_no_legacy_key():
    buckets = load_default_policy()["buckets"]
    high = {e.lower() for e in buckets["upload_candidate"]["high_extensions"]}
    medium = {e.lower() for e in buckets["upload_candidate"]["medium_extensions"]}
    low = {e.lower() for e in buckets["hash_only"]["extensions"]}
    skipped = {e.lower() for e in buckets["skipped"]["extensions"]}
    assert not (high & medium)
    assert not ((high | medium) & low)
    assert not ((high | medium | low) & skipped)
    assert "extensions" not in buckets["upload_candidate"]


def test_risk_tier_for_extension_reads_the_table():
    policy = load_default_policy()
    assert risk_tier_for_extension(".EXE", policy) == RiskTier.HIGH
    assert risk_tier_for_extension(".zip", policy) == RiskTier.MEDIUM
    assert risk_tier_for_extension(".json", policy) == RiskTier.LOW_RISK
    assert risk_tier_for_extension(".txt", policy) == RiskTier.SKIPPED
    assert risk_tier_for_extension(".qqq", policy) is None


# --- Legacy History reports: re-derive from extension, not worst-case -------

_LEGACY = {
    "index": 0, "relative_path": "a", "size": 10, "sha256": None,
    "classification_bucket": "upload_candidate", "classification_reason": "x",
    "hash_eligible": True, "upload_eligible": True, "suspicious": True,
    "outcome": "needs_attention", "outcome_reason": "scan_incomplete",
    "lookup_status": "not_checked", "upload_status": "not_uploaded",
    "risk_label": "unknown", "report_category": "full_inventory",
    "action": "hashed", "engine_state": "not_queried",
    "permalink": None, "engine_counts": {},
    "detection_ratio": {"flagged": 0, "total": 0},
    "detections": [], "last_analysis_at": None,
    "analysis_status": "not_applicable",
    "errors": [], "json_reference": "/files/0/raw_result", "raw_result": None,
    "assessment_complete": False, "executable_bit": False,
    "shebang": False, "elf": False, "engine_id": None,
}


def _legacy(**over):
    payload = dict(_LEGACY)
    payload.update(over)
    return payload


@pytest.mark.parametrize(("path", "bucket", "expected"), [
    ("tool.exe", "upload_candidate", "high"),
    ("game.zip", "suspicious_upload_blocked", "medium"),
    ("clip.webm", "upload_candidate", "low_risk"),         # exec-bit era promotion
    ("data.gds", "upload_candidate", "low_risk"),
    ("mystery.qqq", "suspicious_upload_blocked", "low_risk"),  # size-era promotion
    ("notes.txt", "skipped", "skipped"),
])
def test_legacy_payload_tier_is_rederived_from_extension(path, bucket, expected):
    rf = _report_file_from_payload(_legacy(relative_path=path, classification_bucket=bucket))
    assert rf.risk_tier == expected


def test_legacy_payload_with_elf_or_shebang_signal_is_high():
    for signal in ("elf", "shebang"):
        rf = _report_file_from_payload(_legacy(relative_path="runner.qqq", **{signal: True}))
        assert rf.risk_tier == "high", signal


def test_legacy_skipped_outcome_is_skipped_tier_regardless_of_extension():
    rf = _report_file_from_payload(
        _legacy(relative_path="tool.exe", classification_bucket="skipped", outcome="skipped")
    )
    assert rf.risk_tier == "skipped"


def test_payload_with_explicit_risk_tier_is_not_rederived():
    rf = _report_file_from_payload(_legacy(relative_path="clip.webm", risk_tier="high"))
    assert rf.risk_tier == "high"


# --- "Lower risk" pill only renders when the tier has files -----------------


def _needs_attention(name: str) -> FileResult:
    rec = _record(name)
    cls = classify_file(rec, load_default_policy())
    res = FileResult(record=rec, classification=cls)
    res.outcome = ScanOutcome.NEEDS_ATTENTION
    res.outcome_reason = OutcomeReason.ENGINE_NOT_FOUND
    res.lookup_status = LookupStatus.NOT_FOUND
    return res


def test_filter_pills_only_include_tiers_with_files():
    report = build_scan_report(
        Path("/scan"), [_needs_attention("tool.exe"), _needs_attention("app.py")],
        online=True, upload_consent=False,
    )
    view = build_report_view(report)
    needs = next(s for s in view["sections"] if s["outcome"] == "needs_attention")
    assert [p["key"] for p in needs["filters"]] == ["all", "high", "medium"]
    assert [c["key"] for c in needs["risk_chips"]] == ["high", "medium"]
