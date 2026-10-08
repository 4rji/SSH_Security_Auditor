from __future__ import annotations

import asyncio
import time

from ssh_auditor.models import Evidence, Finding, Status
from ssh_auditor.plugins.base import Context, Meta, register


class ConnectivityPlugin:
    meta = Meta(
        id="connectivity", version="1", category="A",
        name="TCP connectivity and banner", impact="none",
        requires_auth=False, timeout_s=10.0,
    )

    async def collect(self, ctx: Context) -> Evidence:
        data: dict = {"tcp_open": False, "connect_ms": None, "banner": None}
        t0 = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ctx.host, ctx.port), timeout=self.meta.timeout_s
            )
        except Exception as e:  # noqa: BLE001
            data["error"] = f"{type(e).__name__}: {e}"
            return Evidence(data=data)
        data["tcp_open"] = True
        data["connect_ms"] = int((time.monotonic() - t0) * 1000)
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=5.0)
            data["banner"] = line.decode("ascii", "replace").strip() or None
        except Exception:  # noqa: BLE001
            data["banner"] = None
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
        return Evidence(data=data)

    def evaluate(self, evidence: Evidence, policy: dict) -> list[Finding]:
        d = evidence.data
        if not d["tcp_open"]:
            return [
                Finding(
                    id="tcp", status=Status.FAIL,
                    summary=f"Could not open TCP {d.get('error', '')}".strip(),
                    recommendation="Check the network, port and allowlist.",
                )
            ]
        out = [Finding(id="tcp", status=Status.PASS, summary=f"TCP open in {d['connect_ms']} ms")]
        if d.get("banner"):
            out.append(Finding(id="banner", status=Status.INFO, summary=d["banner"]))
        return out


register(ConnectivityPlugin())
