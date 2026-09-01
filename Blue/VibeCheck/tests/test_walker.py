from __future__ import annotations

import os
from pathlib import Path

import pytest

from vibecheck.scanner.walker import discover_source_files


def test_discovers_python_and_js_files(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.js").write_text("const x = 1;\n")
    (tmp_path / "readme.md").write_text("not source\n")
    files, warnings = discover_source_files(tmp_path)
    names = {f.rel_path for f in files}
    assert names == {"a.py", "b.js"}


def test_skips_excluded_directories(tmp_path: Path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.js").write_text("skip me\n")
    (tmp_path / "app.js").write_text("keep me\n")
    files, _ = discover_source_files(tmp_path)
    assert {f.rel_path for f in files} == {"app.js"}


def test_does_not_follow_symlinked_file_outside_root(tmp_path: Path):
    outside_dir = tmp_path.parent / f"vibecheck_outside_{tmp_path.name}"
    outside_dir.mkdir(exist_ok=True)
    secret_file = outside_dir / "secret.py"
    secret_file.write_text('AWS_KEY = "AKIAABCDEFGHIJKLMNOP"\n')

    scan_root = tmp_path / "project"
    scan_root.mkdir()
    link_path = scan_root / "notes.py"
    try:
        os.symlink(secret_file, link_path)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted in this environment")

    try:
        files, warnings = discover_source_files(scan_root)
        assert files == []
    finally:
        secret_file.unlink(missing_ok=True)
        outside_dir.rmdir()


def test_does_not_descend_into_symlinked_directory(tmp_path: Path):
    outside_dir = tmp_path.parent / f"vibecheck_outside_dir_{tmp_path.name}"
    outside_dir.mkdir(exist_ok=True)
    (outside_dir / "secret.py").write_text('AWS_KEY = "AKIAABCDEFGHIJKLMNOP"\n')

    scan_root = tmp_path / "project"
    scan_root.mkdir()
    link_dir = scan_root / "linked"
    try:
        os.symlink(outside_dir, link_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted in this environment")

    try:
        files, warnings = discover_source_files(scan_root)
        assert files == []
    finally:
        link_dir.unlink(missing_ok=True)
        (outside_dir / "secret.py").unlink(missing_ok=True)
        outside_dir.rmdir()
