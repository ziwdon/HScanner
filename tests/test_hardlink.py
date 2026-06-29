import os

from hscanner import scanner
from hscanner.scanner import run_local_scan


def test_hardlinks_are_hashed_once(tmp_path, monkeypatch):
    a = tmp_path / "a.bin"
    a.write_bytes(b"payload-bytes")
    b = tmp_path / "b.bin"
    os.link(a, b)  # hardlink: same inode as a.bin

    calls: list[str] = []
    real = scanner.sha256_file

    def counting(path, *args, **kwargs):
        calls.append(path.name)
        return real(path, *args, **kwargs)

    monkeypatch.setattr(scanner, "sha256_file", counting)

    results = run_local_scan(tmp_path)
    by_path = {r.record.relative_path: r for r in results}
    assert by_path["a.bin"].sha256 == by_path["b.bin"].sha256
    assert len(calls) == 1  # bytes hashed once across the two hardlinked paths
