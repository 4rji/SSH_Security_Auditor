from types import SimpleNamespace

import asyncssh
import pytest
import pytest_asyncio

from ssh_auditor.engine.cache import TTLCache
from ssh_auditor.engine.runner import run_scan
from ssh_auditor.models import AuthMethod, Credentials, ScanRequest


class _PasswordServer(asyncssh.SSHServer):
    def begin_auth(self, _username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return username == "audit" and password == "server-password-marker"


def _process(process):
    if process.command == "id":
        process.stdout.write("uid=1000(audit)\n")
        process.exit(0)
    else:
        process.stderr.write("unsupported\n")
        process.exit(127)


@pytest_asyncio.fixture
async def password_server():
    server = await asyncssh.create_server(
        _PasswordServer, "127.0.0.1", 0,
        server_host_keys=[asyncssh.generate_private_key("ssh-ed25519")],
        process_factory=_process,
    )
    sock = server.sockets[0].getsockname()
    yield sock[0], sock[1]
    server.close()
    await server.wait_closed()


@pytest.mark.asyncio
async def test_concurrency_bounded_runs_small(password_server):
    host, port = password_server
    req = ScanRequest(
        target_host=host, port=port, profile="generic",
        tests=["concurrency_bounded"], confirm_impact=True,
        params={"load": {"iterations": 5, "error_rate_pct": 100, "p95_factor": 100}},
        credentials=Credentials(method=AuthMethod.PASSWORD, username="audit",
                                password="server-password-marker"),
    )
    sr = await run_scan(
        req, policy={"performance": {}}, tool_version="0", limit=2,
        cache=TTLCache(60), profile=SimpleNamespace(safe_command="id"),
    )
    result = next(r for r in sr.results if r.test_id == "concurrency_bounded")
    assert result.evidence.data["completed"] >= 1
    assert result.evidence.data["succeeded"] >= 1
    assert "latency_ms" in result.evidence.data
