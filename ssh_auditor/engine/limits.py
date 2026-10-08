from __future__ import annotations

import asyncio


class LimitRegistry:
    """Un semáforo por host, memoizado, para que varios análisis contra el mismo
    equipo (de distintos ingenieros) no sumen más carga de la permitida."""

    def __init__(self):
        self._sems: dict[str, asyncio.Semaphore] = {}

    def semaphore(self, host: str, limit: int) -> asyncio.Semaphore:
        if host not in self._sems:
            self._sems[host] = asyncio.Semaphore(limit)
        return self._sems[host]
