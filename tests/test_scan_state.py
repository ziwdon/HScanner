from hscanner.state import ScanState
from hscanner.store import open_scan_store


def _state(tmp_path):
    return ScanState(open_scan_store(tmp_path), tmp_path)


def test_start_creates_running_scan(tmp_path):
    st = _state(tmp_path)
    scan_id, resuming = st.start_or_resume(resume=False)
    assert scan_id.startswith("scan_")
    assert resuming is False
    row = st.conn.execute("SELECT status FROM scan WHERE scan_id=?", (scan_id,)).fetchone()
    assert row["status"] == "running"


def test_resume_picks_up_unfinished_scan(tmp_path):
    st = _state(tmp_path)
    first, _ = st.start_or_resume(resume=False)
    st2 = ScanState(open_scan_store(tmp_path), tmp_path)
    resumed_id, resuming = st2.start_or_resume(resume=True)
    assert resuming is True
    assert resumed_id == first


def test_resume_without_unfinished_scan_starts_fresh(tmp_path):
    st = _state(tmp_path)
    first, _ = st.start_or_resume(resume=False)
    st.mark_done()
    st2 = ScanState(open_scan_store(tmp_path), tmp_path)
    new_id, resuming = st2.start_or_resume(resume=True)
    assert resuming is False
    assert new_id != first


def test_cached_sha256_returns_hash_only_when_unchanged(tmp_path):
    st = _state(tmp_path)
    st.start_or_resume(resume=False)
    st.record_file("a.bin", size=10, mtime_ns=111, sha256="deadbeef", inode="1:2", stage="hashed")
    assert st.cached_sha256("a.bin", 10, 111) == "deadbeef"
    assert st.cached_sha256("a.bin", 99, 111) is None   # size changed
    assert st.cached_sha256("a.bin", 10, 222) is None   # mtime changed


def test_record_file_upserts(tmp_path):
    st = _state(tmp_path)
    st.start_or_resume(resume=False)
    st.record_file("a.bin", 10, 111, None, None, "new")
    st.record_file("a.bin", 10, 111, "cafe", "1:2", "hashed")
    assert st.cached_sha256("a.bin", 10, 111) == "cafe"
