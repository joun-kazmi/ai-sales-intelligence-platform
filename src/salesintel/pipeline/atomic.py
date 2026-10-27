"""Atomic outputs and manifests (D32): temp file or dir in the same directory, fsync, rename."""

import hashlib
import json
import os
import shutil
import subprocess
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


def fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def fsync_file(path: Path) -> None:
    with open(path, "rb") as f:
        os.fsync(f.fileno())


@contextmanager
def atomic_file(target: Path) -> Iterator[Path]:
    """Yield a temp path; on success it is fsynced and renamed onto `target`."""
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(f".tmp-{uuid.uuid4().hex}-{target.name}")
    try:
        yield tmp
        fsync_file(tmp)
        os.replace(tmp, target)
        fsync_dir(target.parent)
    finally:
        tmp.unlink(missing_ok=True)


@contextmanager
def atomic_dir(target: Path, replace: bool = False) -> Iterator[Path]:
    """Yield a temp dir; on success it is fsynced and renamed onto `target`.

    A crash leaves only a `.tmp-*` dir, never a half-written `target`.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(f".tmp-{uuid.uuid4().hex}-{target.name}")
    tmp.mkdir()
    try:
        yield tmp
        for child in tmp.iterdir():
            fsync_file(child)
        fsync_dir(tmp)
        if target.exists():
            if not replace:
                raise FileExistsError(target)
            old = target.with_name(f".old-{uuid.uuid4().hex}-{target.name}")
            os.replace(target, old)
            os.replace(tmp, target)
            shutil.rmtree(old)
        else:
            os.replace(tmp, target)
        fsync_dir(target.parent)
    finally:
        if tmp.exists():
            shutil.rmtree(tmp)


def write_json(path: Path, obj: dict) -> None:
    with atomic_file(path) as tmp:
        tmp.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")


def file_sha256(path: Path) -> str:
    with open(path, "rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def code_commit() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, check=True, cwd=Path(__file__).parent,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            capture_output=True, text=True, check=True, cwd=Path(__file__).parents[3],
        ).stdout.strip()
        return out + ("-dirty" if dirty else "")
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
