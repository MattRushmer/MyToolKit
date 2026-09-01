"""Discover and read source files under a scan root."""
from __future__ import annotations

import os
from pathlib import Path

from vibecheck.config import settings
from vibecheck.models import Language, SourceFile, language_for_path

# Directories an LLM never hand-wrote and that would otherwise dominate
# duplication clustering and dependency parsing with vendored/generated code.
_EXCLUDED_DIR_NAMES = {
    ".git", ".hg", ".svn", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".venv", "venv", "env", "node_modules", "dist", "build", ".next", ".nuxt",
    "vendor", "site-packages", ".tox", ".vibecheck_cache", "coverage", "htmlcov",
}


def is_excluded_dir_name(name: str) -> bool:
    return name in _EXCLUDED_DIR_NAMES or (name.startswith(".") and name not in (".", ".."))


def discover_source_files(root: Path) -> tuple[list[SourceFile], list[str]]:
    """Walk `root` for Python/JS/TS files. Returns (files, warnings) -
    warnings covers files skipped for being unreadable, too large, or binary,
    so a scan degrades per-file instead of aborting.

    VibeCheck's whole purpose is scanning code nobody has fully vetted yet, so
    the walk is deliberately symlink-hostile: `os.walk(..., followlinks=False)`
    never descends into a symlinked directory, and every candidate file is
    re-checked with `is_symlink()` before it's read. Without this, a
    committed symlink pointing outside the scan root (e.g. `notes.py ->
    ~/.ssh/id_rsa`) would have its target's content silently read as "source"
    and, if it matched a secrets pattern, re-published verbatim into the scan
    report - turning a scan of untrusted code into an exfiltration primitive.
    """
    root = root.resolve()
    files: list[SourceFile] = []
    warnings: list[str] = []

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dir_path = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames if not is_excluded_dir_name(d) and not (dir_path / d).is_symlink())

        for filename in sorted(filenames):
            path = dir_path / filename
            if path.is_symlink():
                continue

            language = language_for_path(path)
            if language is Language.UNKNOWN:
                continue

            try:
                resolved = path.resolve()
            except OSError as exc:
                warnings.append(f"could not resolve {path}: {exc}")
                continue
            if root not in resolved.parents and resolved != root:
                warnings.append(f"skipped {path}: resolves outside the scan root")
                continue

            try:
                size = path.stat().st_size
            except OSError as exc:
                warnings.append(f"could not stat {path}: {exc}")
                continue
            if size > settings.max_file_bytes:
                warnings.append(f"skipped {path} ({size} bytes > max_file_bytes)")
                continue

            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError) as exc:
                warnings.append(f"skipped unreadable file {path}: {exc}")
                continue

            rel_path = path.relative_to(root).as_posix()
            files.append(SourceFile(abs_path=path, rel_path=rel_path, language=language, text=text, lines=tuple(text.splitlines())))

    return files, warnings
