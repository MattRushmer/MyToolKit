from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

from vibecheck.models import Language, SourceFile


def make_source(text: str, rel_path: str = "test.py", language: Language = Language.PYTHON) -> SourceFile:
    text = dedent(text)
    return SourceFile(abs_path=Path(rel_path), rel_path=rel_path, language=language, text=text, lines=tuple(text.splitlines()))


@pytest.fixture
def demo_app_root() -> Path:
    return Path(__file__).resolve().parent.parent / "fixtures" / "vibe_demo_app"
