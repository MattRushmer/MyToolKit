from __future__ import annotations

from pathlib import Path

import pytest

from agentwarden.store.connection import Store


@pytest.fixture
async def store(tmp_path: Path) -> Store:
    s = Store(tmp_path / "test.db")
    await s.open()
    yield s
    await s.close()
