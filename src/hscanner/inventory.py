import os
from collections.abc import Iterator
from pathlib import Path

from hscanner.models import FileRecord


def iter_inventory(root: Path) -> Iterator[FileRecord]:
    root = root.resolve()
    candidates: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        # A symlink to a directory is recorded as a symlink entry but never
        # descended into, upholding the follow_symlinks=false invariant. Real
        # subdirectories are recursed; they are not yielded as records.
        real_dirnames: list[str] = []
        for name in dirnames:
            if name == ".hscanner" and base == root:
                continue  # skip the scan root's own HScanner metadata directory
            entry = base / name
            if entry.is_symlink():
                candidates.append(entry)
            else:
                real_dirnames.append(name)
        dirnames[:] = real_dirnames
        for name in filenames:
            candidates.append(base / name)
    for path in sorted(candidates):
        try:
            stat = path.lstat()
        except OSError:
            continue
        is_symlink = path.is_symlink()
        is_regular = path.is_file() and not is_symlink
        if not (is_regular or is_symlink):
            continue
        yield FileRecord(
            root=root,
            path=path,
            size=stat.st_size,
            mtime_ns=stat.st_mtime_ns,
            mode=stat.st_mode,
            is_symlink=is_symlink,
            is_regular=is_regular,
            is_hidden=any(part.startswith(".") for part in path.relative_to(root).parts),
        )


def record_from_path(root: Path, relative_path: str) -> FileRecord:
    path = root / relative_path
    stat = path.lstat()  # raises FileNotFoundError if missing; symlink's own metadata
    is_symlink = path.is_symlink()
    is_regular = path.is_file() and not is_symlink
    return FileRecord(
        root=root,
        path=path,
        size=stat.st_size,
        mtime_ns=stat.st_mtime_ns,
        mode=stat.st_mode,
        is_symlink=is_symlink,
        is_regular=is_regular,
        is_hidden=any(part.startswith(".") for part in path.relative_to(root).parts),
    )
