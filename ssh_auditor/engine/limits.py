from __future__ import annotations

import asyncio


class LimitRegistry:
    """One memoized semaphore per host, so several scans against the same device
    (from different engineers) never add up to more load than allowed."""

    def __init__(self):
        self._sems: dict[str, asyncio.Semaphore] = {}

    def semaphore(self, host: str, limit: int) -> asyncio.Semaphore:
        if host not in self._sems:
            self._sems[host] = asyncio.Semaphore(limit)
        return self._sems[host]
