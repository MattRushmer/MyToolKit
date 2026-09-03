"""The single chokepoint every store module runs SQLite through.

`sqlite3` is blocking; called directly from a coroutine it would park the
whole event loop while holding the connection. Every access goes through
`Store.run()`, which offloads to a worker thread via `anyio.to_thread` - but
since a *different* worker thread can service each call, the underlying
connection is opened with `check_same_thread=False` and every access is
additionally serialized behind one `anyio.Lock`, so at most one thread ever
touches the connection at a time (never simultaneously, which is sqlite3's
actual requirement - check_same_thread only exists to catch the common
accidental-simultaneous-use bug, and this design avoids that bug a different
way). This also closes the rate-limit TOCTOU broker/lifecycle.py's mint()
depends on: every write in one call to `run()` happens inside one lock
acquisition, so a check-then-insert sequence a caller writes is atomic with
respect to every other store access.
"""
from __future__ import annotations

import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

import anyio

from agentwarden.store.schema import initialize_schema

T = TypeVar("T")


class Store:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._lock = anyio.Lock()
        self._conn: sqlite3.Connection | None = None

    async def open(self) -> None:
        db_path = self._db_path

        def _open() -> sqlite3.Connection:
            db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(db_path), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            initialize_schema(conn)
            return conn

        async with self._lock:
            self._conn = await anyio.to_thread.run_sync(_open)

    async def close(self) -> None:
        async with self._lock:
            if self._conn is not None:
                await anyio.to_thread.run_sync(self._conn.close)
                self._conn = None

    async def run(self, fn: Callable[[sqlite3.Connection], T]) -> T:
        """Run `fn(connection)` under the single-writer lock, off the event
        loop thread. `fn` should do its own `conn.commit()` if it writes -
        this method never commits implicitly, so a caller doing several
        related writes can wrap them in one transaction."""
        if self._conn is None:
            raise RuntimeError("Store.open() must be awaited before use")
        conn = self._conn
        async with self._lock:
            return await anyio.to_thread.run_sync(fn, conn)
