from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import (
    HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import BaseModel

import ssh_auditor.plugins  # noqa: F401  (registers the plugins)
from ssh_auditor.compare import compare
from ssh_auditor.config import Config
from ssh_auditor.export import from_json, to_csv, to_html, to_json
from ssh_auditor.mcp.bundle import build_mcpb, mcp_json
from ssh_auditor.mcp.server import build_mcp
from ssh_auditor.models import ScanRequest, ScanResult
from ssh_auditor.plugins.base import catalog
from ssh_auditor.service import Admitted, AuditService, ScanRejected
from ssh_auditor.store import NOUN, StoreError, example_text, parse

TOOL_VERSION = "0.1.0"
_STATIC = Path(__file__).parent / "static"


class Upload(BaseModel):
    yaml: str
    uploaded_by: str = ""


def _yaml_download(text: str, filename: str) -> Response:
    return Response(content=text, media_type="application/yaml",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


def create_app(cfg: Config) -> FastAPI:
    service = AuditService(cfg, TOOL_VERSION)
    cache, stores = service.cache, service.stores
    mcp = build_mcp(service)
    mcp_app = mcp.streamable_http_app(
        streamable_http_path="/mcp", stateless_http=True, json_response=True,
        # Internal network without a token (spec §10): the same exposure as the REST
        # API, so no Host/Origin allowlist. Engineers reach the server by IP or by name.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        # Starlette never runs a mounted app's lifespan; the host app starts the manager.
        async with mcp.session_manager.run():
            yield

    app = FastAPI(title="SSH Security Auditor", version=TOOL_VERSION, lifespan=lifespan)
    app.router.routes.extend(mcp_app.routes)  # /mcp, ahead of the static catch-all

    @app.exception_handler(RequestValidationError)
    async def readable_validation_error(_request: Request, exc: RequestValidationError):
        # One line per field ("port: Input should be ..."): the web shows `detail` as is,
        # and FastAPI's default is a list of objects.
        parts = []
        for err in exc.errors():
            loc = ".".join(str(p) for p in err.get("loc", ()) if p != "body")
            parts.append(f"{loc}: {err.get('msg', '')}" if loc else err.get("msg", ""))
        return JSONResponse(status_code=422, content={"detail": "; ".join(parts)})

    @app.get("/api/v1/tests")
    async def tests():
        return [
            {
                "id": m.id, "name": m.name, "category": m.category,
                "impact": m.impact, "requires_auth": m.requires_auth,
                "privilege": m.privilege, "credential_method": m.credential_method,
                "actions": list(m.actions),
            }
            for m in catalog()
        ]

    # --- profiles and policies (built-in + shared custom uploads) ---------------------

    def _register_store_routes(kind: str) -> None:
        store = stores[kind]
        noun = NOUN[kind]

        @app.get(f"/api/v1/{kind}", name=f"list_{kind}")
        async def list_items():
            return store.list()

        @app.get(f"/api/v1/{kind}/example.yaml", name=f"example_{noun}")
        async def example():
            return _yaml_download(example_text(kind), f"{noun}.example.yaml")

        @app.get(f"/api/v1/{kind}/{{item_id}}/yaml", name=f"download_{noun}")
        async def download(item_id: str):
            try:
                return _yaml_download(store.text(item_id), f"{item_id}.yaml")
            except StoreError as e:
                raise HTTPException(status_code=e.status, detail=e.detail) from e

        @app.post(f"/api/v1/{kind}", status_code=201, name=f"upload_{noun}")
        async def upload(body: Upload):
            try:
                if kind == "profiles":
                    doc = parse(kind, body.yaml)
                    if not stores["policies"].exists(doc.policy):
                        raise StoreError(422, f"Unknown policy '{doc.policy}': upload it "
                                              "first or use an existing one.")
                item_id, token = store.add(body.yaml, body.uploaded_by)
            except StoreError as e:
                raise HTTPException(status_code=e.status, detail=e.detail) from e
            return {"id": item_id, "owner_token": token}

        @app.delete(f"/api/v1/{kind}/{{item_id}}", status_code=204, name=f"delete_{noun}")
        async def delete(item_id: str, x_owner_token: str = Header(default="")):
            try:
                if kind == "policies":
                    users = [p["id"] for p in stores["profiles"].list()
                             if p.get("policy") == item_id]
                    if users:
                        raise StoreError(409, f"Policy '{item_id}' is used by profile(s) "
                                              f"{', '.join(users)}.")
                store.delete(item_id, x_owner_token)
            except StoreError as e:
                raise HTTPException(status_code=e.status, detail=e.detail) from e
            return Response(status_code=204)

    for kind in stores:
        _register_store_routes(kind)

    # --- scans ------------------------------------------------------------------------

    def _admit(req: ScanRequest) -> Admitted:
        try:
            return service.admit(req)
        except ScanRejected as e:
            raise HTTPException(status_code=e.status, detail=e.detail) from e

    @app.post("/api/v1/scans")
    async def start_scan(req: ScanRequest):
        return await service.run(_admit(req))

    @app.post("/api/v1/scans/stream")
    async def start_scan_stream(req: ScanRequest):
        adm = _admit(req)
        queue: asyncio.Queue = asyncio.Queue()

        def on_event(ev: dict) -> None:
            queue.put_nowait(ev)

        async def worker():
            try:
                sr = await service.run(adm, on_event=on_event)
                queue.put_nowait({"type": "result", "result": json.loads(to_json(sr))})
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                # Exception text can contain parser input. Only expose its class.
                queue.put_nowait({"type": "error", "error": type(exc).__name__})
            finally:
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
            raise HTTPException(status_code=404, detail="Scan not found or expired")
        return sr

    @app.get("/api/v1/scans/{scan_id}/export")
    async def export_scan(scan_id: str, format: str = "json"):
        sr = cache.get(scan_id)
        if sr is None:
            raise HTTPException(status_code=404, detail="Scan not found or expired")
        if format == "json":
            return Response(content=to_json(sr), media_type="application/json",
                            headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.json"})
        if format == "csv":
            return PlainTextResponse(to_csv(sr), media_type="text/csv",
                                     headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.csv"})
        if format == "html":
            return HTMLResponse(to_html(sr),
                                headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.html"})
        raise HTTPException(status_code=422, detail=f"Unsupported format: {format}")

    @app.post("/api/v1/compare")
    async def compare_scans(request: Request):
        body = await request.json()
        try:
            if "a_id" in body and "b_id" in body:
                a = cache.get(body["a_id"])
                b = cache.get(body["b_id"])
                if a is None or b is None:
                    raise HTTPException(status_code=404, detail="One of the scans is not cached")
            elif "a" in body and "b" in body:
                a = ScanResult.model_validate(body["a"])
                b = ScanResult.model_validate(body["b"])
            else:
                raise HTTPException(status_code=422, detail="Send {a_id, b_id} or {a, b}")
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=422, detail=f"Invalid input: {e}")
        return compare(a, b)

    @app.post("/api/v1/import")
    async def import_scan(request: Request):
        """Validate a JSON export pasted by the user (for comparing)."""
        text = (await request.body()).decode("utf-8", "replace")
        try:
            sr = from_json(text)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=422, detail=f"Invalid JSON: {e}")
        return sr

    # --- "Connect with Claude" ----------------------------------------------------------

    def _mcp_url(request: Request) -> str:
        # The address the engineer used to open the page, so it works by IP or by name.
        return str(request.base_url).rstrip("/") + "/mcp"

    @app.get("/claude", include_in_schema=False)
    async def claude_page():
        return RedirectResponse("/claude.html")

    @app.get("/claude/mcp.json", include_in_schema=False)
    async def claude_mcp_json(request: Request):
        return Response(json.dumps(mcp_json(_mcp_url(request)), indent=2) + "\n",
                        media_type="application/json",
                        headers={"Content-Disposition": 'attachment; filename="mcp.json"'})

    @app.get("/claude/ssh-auditor.mcpb", include_in_schema=False)
    async def claude_mcpb(request: Request):
        tools = [{"name": t.name, "description": (t.description or "").strip().split("\n")[0]}
                 for t in await mcp.list_tools()]
        return Response(build_mcpb(_mcp_url(request), TOOL_VERSION, tools),
                        media_type="application/zip",
                        headers={"Content-Disposition":
                                 'attachment; filename="ssh-auditor.mcpb"'})

    if _STATIC.exists():
        app.mount("/", StaticFiles(directory=str(_STATIC), html=True), name="static")

    return app
