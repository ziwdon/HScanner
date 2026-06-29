import os
from pathlib import Path

from hscanner.models import ClassificationBucket
from hscanner.scanner import run_local_scan


def test_extensionless_elf_is_promoted_and_flagged(tmp_path: Path):
    f = tmp_path / "launcher"
    f.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 64)
    results = run_local_scan(tmp_path)
    r = next(x for x in results if x.record.path.name == "launcher")
    assert r.elf is True
    assert r.classification.bucket == ClassificationBucket.UPLOAD_CANDIDATE


def test_shebang_script_sets_signal(tmp_path: Path):
    f = tmp_path / "run-me"
    f.write_text("#!/bin/bash\necho hi\n")
    os.chmod(f, 0o755)
    results = run_local_scan(tmp_path)
    r = next(x for x in results if x.record.path.name == "run-me")
    assert r.shebang is True
    assert r.executable_bit is True
