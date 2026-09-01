"""Parse declared (not imported) dependencies out of requirements.txt,
pyproject.toml, and package.json. Working from what's *declared* rather than
walking every `import`/`require` avoids an entirely separate false-positive
surface (shadowing a stdlib module name, a local package with the same name
as a PyPI one, etc.) - see README's Known limitations for the tradeoff this
implies (an import with no manifest entry is invisible to this check).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from vibecheck.dependencies.models import DeclaredDependency

_REQUIREMENTS_NAME_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")
_UNCHECKABLE_VERSION_PREFIXES = ("file:", "link:", "workspace:", "git+", "git:", "http:", "https:", ".", "/", "*")


def _parse_requirements_txt(path: Path, rel_path: str) -> list[DeclaredDependency]:
    deps: list[DeclaredDependency] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return deps

    for line_no, raw in enumerate(lines, start=1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        if "://" in line:  # VCS/URL requirement, not a registry name
            continue
        match = _REQUIREMENTS_NAME_RE.match(line)
        if not match:
            continue
        name = match.group(1).split("[", 1)[0]  # drop extras, e.g. flask[async]
        deps.append(DeclaredDependency(name=name, ecosystem="pypi", manifest_file=rel_path, line=line_no))
    return deps


# Minimal, dependency-free extraction of `dependencies = [...]` from a
# pyproject.toml [project] table, and `[tool.poetry.dependencies]` entries.
# Not a full TOML parser - documented as a known limitation for unusual
# formatting (inline tables, multi-line strings with brackets, etc.).
_PEP621_DEPS_BLOCK_RE = re.compile(r"dependencies\s*=\s*\[(.*?)\]", re.DOTALL)
_QUOTED_ITEM_RE = re.compile(r"""["']([^"']+)["']""")
_POETRY_SECTION_RE = re.compile(r"\[tool\.poetry(?:\.dev)?-?dependencies\]\s*(.*?)(?=\n\[|\Z)", re.DOTALL)
_POETRY_LINE_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=", re.MULTILINE)


def _parse_pyproject_toml(path: Path, rel_path: str) -> list[DeclaredDependency]:
    deps: list[DeclaredDependency] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return deps

    for block_match in _PEP621_DEPS_BLOCK_RE.finditer(text):
        block = block_match.group(1)
        line_offset = text[: block_match.start()].count("\n")
        for item_match in _QUOTED_ITEM_RE.finditer(block):
            name_match = _REQUIREMENTS_NAME_RE.match(item_match.group(1).strip())
            if name_match:
                line_no = line_offset + block[: item_match.start()].count("\n") + 1
                deps.append(DeclaredDependency(name=name_match.group(1), ecosystem="pypi", manifest_file=rel_path, line=line_no))

    for section_match in _POETRY_SECTION_RE.finditer(text):
        section = section_match.group(1)
        line_offset = text[: section_match.start()].count("\n")
        for line_match in _POETRY_LINE_RE.finditer(section):
            name = line_match.group(1)
            if name.lower() == "python":
                continue
            line_no = line_offset + section[: line_match.start()].count("\n") + 1
            deps.append(DeclaredDependency(name=name, ecosystem="pypi", manifest_file=rel_path, line=line_no))

    return deps


def _parse_package_json(path: Path, rel_path: str) -> list[DeclaredDependency]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    deps: list[DeclaredDependency] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        entries = data.get(section)
        if not isinstance(entries, dict):
            continue
        for name, version in entries.items():
            if not isinstance(version, str) or version.strip().startswith(_UNCHECKABLE_VERSION_PREFIXES):
                continue
            deps.append(DeclaredDependency(name=name, ecosystem="npm", manifest_file=rel_path))
    return deps


_PARSERS = {
    "requirements.txt": _parse_requirements_txt,
    "pyproject.toml": _parse_pyproject_toml,
    "package.json": _parse_package_json,
}


def extract_declared_dependencies(root: Path) -> list[DeclaredDependency]:
    root = root.resolve()
    deps: list[DeclaredDependency] = []
    for filename, parser in _PARSERS.items():
        for path in root.rglob(filename):
            if "node_modules" in path.parts or ".venv" in path.parts or "venv" in path.parts:
                continue
            deps.extend(parser(path, path.relative_to(root).as_posix()))
    return deps
