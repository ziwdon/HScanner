"""Tests for the root-scoped .hscanner directory exclusion in iter_inventory."""

from pathlib import Path

from hscanner.inventory import iter_inventory


def test_root_hscanner_excluded_nested_hscanner_included(tmp_path: Path) -> None:
    """Root .hscanner store must be skipped; a nested .hscanner must be inventoried."""
    # Root store — must be excluded
    root_store = tmp_path / ".hscanner"
    root_store.mkdir()
    (root_store / "scan.db").write_bytes(b"db")

    # Nested .hscanner — must be inventoried
    sub = tmp_path / "sub"
    sub.mkdir()
    nested_store = sub / ".hscanner"
    nested_store.mkdir()
    (nested_store / "nested.db").write_bytes(b"nested")

    # Ordinary file that must also appear
    (sub / "real.txt").write_text("hello", encoding="utf-8")

    records = list(iter_inventory(tmp_path))
    relative = {r.relative_path for r in records}

    # Root store and its contents must NOT appear
    assert ".hscanner/scan.db" not in relative
    assert not any(p.startswith(".hscanner") for p in relative), (
        f"Root .hscanner leaked into inventory: {relative}"
    )

    # Nested store content MUST appear
    assert "sub/.hscanner/nested.db" in relative, (
        f"Nested .hscanner not inventoried. Got: {relative}"
    )

    # Regular file must appear
    assert "sub/real.txt" in relative
