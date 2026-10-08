import asyncssh
import pytest_asyncio


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
