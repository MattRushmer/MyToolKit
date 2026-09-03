"""Injectable time source. EXPIRED_GRANT_REUSE and POST_TASK_ACTIVITY tests
need to move time forward without a real sleep; every module that needs "now"
takes a `Clock` (defaulting to `SystemClock()`) instead of calling
`datetime.now()` directly, so a test can pass a `FakeClock` instead."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class FakeClock:
    """Test double: starts at a fixed instant and only moves when told to."""

    def __init__(self, start: datetime | None = None) -> None:
        self._now = start or datetime.now(timezone.utc)

    def now(self) -> datetime:
        return self._now

    def advance(self, seconds: float) -> None:
        from datetime import timedelta

        self._now = self._now + timedelta(seconds=seconds)
