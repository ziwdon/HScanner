import hashlib

from hscanner.hash import sha256_file
from hscanner.inventory import iter_inventory


def test_inventory_includes_hidden_and_nested_files(tmp_path) -> None:
    (tmp_path / ".hidden").write_text("hidden", encoding="utf-8")
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "file.sh").write_text("#!/bin/sh\n", encoding="utf-8")

    records = list(iter_inventory(tmp_path))
    relative = sorted(record.relative_path for record in records)

    assert relative == [".hidden", "nested/file.sh"]


def test_inventory_does_not_follow_symlinks(tmp_path) -> None:
    target = tmp_path / "target.txt"
    target.write_text("x", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(target)

    records = list(iter_inventory(tmp_path))

    assert "link.txt" in [record.relative_path for record in records]
    link_record = next(record for record in records if record.relative_path == "link.txt")
    assert link_record.is_symlink is True
    assert link_record.is_regular is False


def test_inventory_does_not_descend_into_symlinked_directories(tmp_path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret", encoding="utf-8")

    scan_root = tmp_path / "scan"
    scan_root.mkdir()
    (scan_root / "real.txt").write_text("ok", encoding="utf-8")
    (scan_root / "link_dir").symlink_to(outside, target_is_directory=True)

    records = list(iter_inventory(scan_root))
    relative = sorted(record.relative_path for record in records)

    assert "real.txt" in relative
    assert "link_dir" in relative
    assert "link_dir/secret.txt" not in relative
    link_record = next(record for record in records if record.relative_path == "link_dir")
    assert link_record.is_symlink is True
    assert link_record.is_regular is False


def test_sha256_file_streams_file(tmp_path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc")

    assert sha256_file(sample) == hashlib.sha256(b"abc").hexdigest()
