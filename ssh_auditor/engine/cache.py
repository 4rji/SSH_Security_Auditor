from __future__ import annotations

import time

from ssh_auditor.models import ScanResult


class TTLCache:
    def __init__(self, ttl_s: int):
        self.ttl_s = ttl_s
        self._d: dict[str, tuple[float, ScanResult]] = {}

    def put(self, scan_id: str, sr: ScanResult) -> None:
        self._d[scan_id] = (time.monotonic(), sr)

    def get(self, scan_id: str) -> ScanResult | None:
        item = self._d.get(scan_id)
        if not item:
            return None
        ts, sr = item
        if time.monotonic() - ts > self.ttl_s:
            self._d.pop(scan_id, None)
            return None
        return sr

    def ids(self) -> list[str]:
        return list(self._d.keys())
