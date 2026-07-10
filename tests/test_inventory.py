import pytest

from hscanner.inventory import InventoryPathError, record_from_path


def test_record_from_path_rejects_absolute_path(tmp_path) -> None:
    root = tmp_path / "scan"
    root.mkdir()

    with pytest.raises(InventoryPathError):
        record_from_path(root, str(tmp_path / "outside.sh"))


def test_record_from_path_rejects_parent_escape(tmp_path) -> None:
    root = tmp_path / "scan"
    root.mkdir()
    (tmp_path / "outside.sh").write_text("#!/bin/sh\n")

    with pytest.raises(InventoryPathError):
        record_from_path(root, "../outside.sh")


def test_record_from_path_rejects_symlink_target_outside_root(tmp_path) -> None:
    root = tmp_path / "scan"
    root.mkdir()
    outside = tmp_path / "outside.sh"
    outside.write_text("#!/bin/sh\n")
    (root / "link.sh").symlink_to(outside)

    with pytest.raises(InventoryPathError):
        record_from_path(root, "link.sh")


def test_record_from_path_allows_nested_in_tree_file(tmp_path) -> None:
    root = tmp_path / "scan"
    nested = root / "bin"
    nested.mkdir(parents=True)
    (nested / "tool.sh").write_text("#!/bin/sh\n")

    record = record_from_path(root, "bin/tool.sh")

    assert record.path == root / "bin/tool.sh"
    assert record.relative_path == "bin/tool.sh"
