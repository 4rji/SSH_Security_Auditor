from __future__ import annotations

import asyncio
import json
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

import ssh_auditor.plugins  # noqa: F401  (registra los plugins)
from ssh_auditor.compare import compare
from ssh_auditor.config import (
    Config, list_policies, list_profiles, load_policy, load_profile, target_allowed,
)
from ssh_auditor.engine.cache import TTLCache
from ssh_auditor.engine.runner import run_scan
from ssh_auditor.export import from_json, to_csv, to_html, to_json
from ssh_auditor.models import ScanRequest, ScanResult
from ssh_auditor.plugins.base import catalog

TOOL_VERSION = "0.1.0"
_STATIC = Path(__file__).parent / "static"


def _concurrency_limit(cfg: Config, profile: str) -> int:
    prof = load_profile(cfg, profile)
    return int((prof.get("limites") or {}).get("concurrencia_max", 4))


def create_app(cfg: Config) -> FastAPI:
    app = FastAPI(title="SSH Security Auditor", version=TOOL_VERSION)
    cache = TTLCache(ttl_s=cfg.cache_ttl_s)

    @app.get("/api/v1/tests")
    async def tests():
        return [
            {
                "id": m.id, "name": m.name, "category": m.category,
                "impact": m.impact, "requires_auth": m.requires_auth,
            }
            for m in catalog()
        ]

    @app.get("/api/v1/profiles")
    async def profiles():
        return {"profiles": list_profiles(cfg), "policies": list_policies(cfg)}

    def _guard(host: str) -> None:
        if not target_allowed(cfg, host):
            raise HTTPException(
                status_code=403,
                detail=f"Objetivo fuera de la allowlist o allowlist vacía: {host}",
            )

    @app.post("/api/v1/scans")
    async def start_scan(req: ScanRequest):
        _guard(req.target_host)
        policy = load_policy(cfg, req.policy)
        limit = _concurrency_limit(cfg, req.profile)
        sr = await run_scan(req, policy=policy, tool_version=TOOL_VERSION,
                            limit=limit, cache=cache)
        return sr

    @app.post("/api/v1/scans/stream")
    async def start_scan_stream(req: ScanRequest):
        _guard(req.target_host)
        policy = load_policy(cfg, req.policy)
        limit = _concurrency_limit(cfg, req.profile)
        queue: asyncio.Queue = asyncio.Queue()

        def on_event(ev: dict) -> None:
            queue.put_nowait(ev)

        async def worker():
            sr = await run_scan(req, policy=policy, tool_version=TOOL_VERSION,
                                limit=limit, cache=cache, on_event=on_event)
            queue.put_nowait({"type": "result", "result": json.loads(to_json(sr))})
            queue.put_nowait(None)

        async def gen():
            task = asyncio.create_task(worker())
            try:
                while True:
                    ev = await queue.get()
                    if ev is None:
                        break
                    yield f"data: {json.dumps(ev)}\n\n"
            finally:
                if not task.done():
                    task.cancel()

        return StreamingResponse(gen(), media_type="text/event-stream")

    @app.get("/api/v1/scans/{scan_id}")
    async def get_scan(scan_id: str):
        sr = cache.get(scan_id)
        if sr is None:
            raise HTTPException(status_code=404, detail="Análisis no encontrado o expirado")
        return sr

    @app.get("/api/v1/scans/{scan_id}/export")
    async def export_scan(scan_id: str, format: str = "json"):
        sr = cache.get(scan_id)
        if sr is None:
            raise HTTPException(status_code=404, detail="Análisis no encontrado o expirado")
        if format == "json":
            return Response(content=to_json(sr), media_type="application/json",
                            headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.json"})
        if format == "csv":
            return PlainTextResponse(to_csv(sr), media_type="text/csv",
                                     headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.csv"})
        if format == "html":
            return HTMLResponse(to_html(sr),
                                headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.html"})
        raise HTTPException(status_code=422, detail=f"Formato no soportado: {format}")

    @app.post("/api/v1/compare")
    async def compare_scans(request: Request):
        body = await request.json()
        try:
            if "a_id" in body and "b_id" in body:
                a = cache.get(body["a_id"])
                b = cache.get(body["b_id"])
                if a is None or b is None:
                    raise HTTPException(status_code=404, detail="Uno de los análisis no está en caché")
            elif "a" in body and "b" in body:
                a = ScanResult.model_validate(body["a"])
                b = ScanResult.model_validate(body["b"])
            else:
                raise HTTPException(status_code=422, detail="Enviar {a_id,b_id} o {a,b}")
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=422, detail=f"Entrada inválida: {e}")
        return compare(a, b)

    @app.post("/api/v1/import")
    async def import_scan(request: Request):
        """Valida una exportación JSON pegada por el usuario (para comparar)."""
        text = (await request.body()).decode("utf-8", "replace")
        try:
            sr = from_json(text)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=422, detail=f"JSON inválido: {e}")
        return sr

    if _STATIC.exists():
        app.mount("/", StaticFiles(directory=str(_STATIC), html=True), name="static")

    return app
