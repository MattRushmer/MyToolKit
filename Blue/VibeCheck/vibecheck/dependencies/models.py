"""Shared shape for a package declared in a manifest file."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DeclaredDependency:
    name: str
    ecosystem: str  # "pypi" or "npm"
    manifest_file: str
    line: int = 0
