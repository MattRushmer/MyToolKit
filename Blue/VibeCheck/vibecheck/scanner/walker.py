"""Discover and read source files under a scan root."""
from __future__ import annotations

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


def _is_excluded(path: Path, root: Path) -> bool:
    return any(part in _EXCLUDED_DIR_NAMES or part.startswith(".") and part not in (".", "..") for part in path.relative_to(root).parts[:-1])


def discover_source_files(root: Path) -> tuple[list[SourceFile], list[str]]:
    """Walk `root` for Python/JS/TS files. Returns (files, warnings) -
    warnings covers files skipped for being unreadable, too large, or binary,
    so a scan degrades per-file instead of aborting."""
    root = root.resolve()
    files: list[SourceFile] = []
    warnings: list[str] = []

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if _is_excluded(path, root):
            continue
        language = language_for_path(path)
        if language is Language.UNKNOWN:
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
