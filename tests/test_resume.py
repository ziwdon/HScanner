from hscanner import scanner
from hscanner.scanner import run_local_scan
from hscanner.state import ScanState
from hscanner.store import open_scan_store


def test_resume_skips_rehash_of_unchanged_file(tmp_path, monkeypatch):
    f = tmp_path / "doc.bin"
    f.write_bytes(b"stable-content")

    st = ScanState(open_scan_store(tmp_path), tmp_path)
    st.start_or_resume(resume=False)
    run_local_scan(tmp_path, scan_state=st)  # first pass records the hash

    calls: list[str] = []
    real = scanner.sha256_file
    monkeypatch.setattr(
        scanner, "sha256_file", lambda p, *a, **k: (calls.append(p.name), real(p, *a, **k))[1]
    )

    st2 = ScanState(open_scan_store(tmp_path), tmp_path)
    resumed_id, resuming = st2.start_or_resume(resume=True)
    assert resuming is True
    results = run_local_scan(tmp_path, scan_state=st2)
    assert calls == []  # unchanged file not re-hashed on resume
    assert results[0].sha256 is not None


def test_changed_file_is_rehashed_on_resume(tmp_path, monkeypatch):
    f = tmp_path / "doc.bin"
    f.write_bytes(b"v1")
    st = ScanState(open_scan_store(tmp_path), tmp_path)
    st.start_or_resume(resume=False)
    run_local_scan(tmp_path, scan_state=st)

    f.write_bytes(b"v2-different-size")  # size + mtime change

    calls: list[str] = []
    real = scanner.sha256_file
    monkeypatch.setattr(
        scanner, "sha256_file", lambda p, *a, **k: (calls.append(p.name), real(p, *a, **k))[1]
    )
    st2 = ScanState(open_scan_store(tmp_path), tmp_path)
    st2.start_or_resume(resume=True)
    run_local_scan(tmp_path, scan_state=st2)
    assert calls == ["doc.bin"]  # changed file re-hashed
