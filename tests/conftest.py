import asyncio

import asyncssh
import pytest
import pytest_asyncio
import uvicorn

from ssh_auditor.models import Evidence, Finding, Status
from ssh_auditor.plugins.base import REGISTRY, Meta, register


class _Server(asyncssh.SSHServer):
    def begin_auth(self, username):
        # True forces authentication; Phase 1 tests don't authenticate, they only
        # read the negotiation, so the value doesn't affect KEXINIT.
        return True


@pytest_asyncio.fixture
async def ssh_server():
    server = await asyncssh.create_server(
        _Server, "127.0.0.1", 0,
        server_host_keys=[asyncssh.generate_private_key("ssh-ed25519")],
        server_version="SSH-2.0-TestServer_1.0",
    )
    sock = server.sockets[0]
    host, port = sock.getsockname()[0], sock.getsockname()[1]
    yield host, port
    server.close()
    await server.wait_closed()



@pytest.fixture
def risky_plugin():
    """A registered test with medium impact, to exercise confirm_impact."""
    class _Risky:
        meta = Meta(id="risky_test", version="1", category="F", name="Risky",
                    impact="medium", requires_auth=False, timeout_s=1.0)

        async def collect(self, ctx):
            return Evidence(data={})

        def evaluate(self, evidence, policy):
            return [Finding(id="risky_test", status=Status.INFO, summary="ok")]

    register(_Risky())
    yield "risky_test"
    REGISTRY.pop("risky_test", None)


@pytest_asyncio.fixture
async def live_app():
    """Serve an app on a free local port. MCP over HTTP needs a real socket and the
    app's lifespan, which httpx's ASGITransport doesn't run."""
    running = []

    async def start(app) -> str:
        server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0,
                                               log_level="warning", lifespan="on"))
        task = asyncio.create_task(server.serve())
        while not server.started:
            if task.done():
                task.result()  # surface a startup error
            await asyncio.sleep(0.01)
        running.append((server, task))
        port = server.servers[0].sockets[0].getsockname()[1]
        return f"http://127.0.0.1:{port}"

    yield start
    for server, task in running:
        server.should_exit = True
        await task
