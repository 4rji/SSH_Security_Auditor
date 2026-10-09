import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace

import asyncssh
import pytest

from ssh_auditor.models import AuthMethod, Credentials, Status
from ssh_auditor.plugins import authentication as auth
from ssh_auditor.plugins.base import Context


def _ctx(credentials: Credentials, safe_command: str = "id") -> Context:
    return Context(
        host="127.0.0.1", port=22, policy={}, params={}, emit=lambda _msg: None,
        credentials=credentials, profile=SimpleNamespace(safe_command=safe_command),
    )


def _plugin(test_id: str):
    return next(plugin for plugin in auth.AUTH_PLUGINS if plugin.meta.id == test_id)


class _PasswordServer(asyncssh.SSHServer):
    def begin_auth(self, _username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return username == "audit" and password == "server-password-marker"


def _password_process(process):
    if process.command == "id":
        process.stdout.write("uid=1000(audit)\n")
        process.exit(0)
    else:
        process.stderr.write("unsupported command\n")
        process.exit(127)


class _CertificateServer(asyncssh.SSHServer):
    def __init__(self, ca_public_data, user_public_data, *, accept_ca, accept_raw):
        self._ca_public_data = ca_public_data
        self._user_public_data = user_public_data
        self._accept_ca = accept_ca
        self._accept_raw = accept_raw

    def begin_auth(self, _username):
        return True

    def public_key_auth_supported(self):
        return True

    def validate_ca_key(self, username, key):
        return (self._accept_ca and username == "audit"
                and key.public_data == self._ca_public_data)

    def validate_public_key(self, username, key):
        return (self._accept_raw and username == "audit"
                and key.public_data == self._user_public_data)


class _PublicKeyServer(asyncssh.SSHServer):
    def __init__(self, public_data):
        self._public_data = public_data

    def begin_auth(self, _username):
        return True

    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        return username == "audit" and key.public_data == self._public_data


class _KeyboardInteractiveServer(asyncssh.SSHServer):
    def begin_auth(self, _username):
        return True

    def kbdint_auth_supported(self):
        return True

    def get_kbdint_challenge(self, username, _lang, _submethods):
        if username != "audit":
            return False
        return (
            "Lab challenge", "Answer both prompts", "",
            [("First response: ", False), ("Second response: ", False)],
        )

    def validate_kbdint_response(self, username, responses):
        return username == "audit" and responses == ["alpha-marker", "beta-marker"]


def _success_process(process):
    process.exit(0)


@pytest.mark.asyncio
async def test_password_login_and_expected_rejection_against_real_server():
    server = await asyncssh.create_server(
        _PasswordServer, "127.0.0.1", 0,
        server_host_keys=[asyncssh.generate_private_key("ssh-ed25519")],
        process_factory=_password_process,
    )
    port = server.sockets[0].getsockname()[1]
    credentials = Credentials(
        method="password", username="audit", password="server-password-marker",
    )
    ctx = Context(
        host="127.0.0.1", port=port, policy={}, params={}, emit=lambda _msg: None,
        credentials=credentials, profile=SimpleNamespace(safe_command="id"),
    )
    try:
        positive = _plugin("auth_password")
        positive_evidence = await positive.collect(ctx)
        assert positive.evaluate(positive_evidence, {})[0].status == Status.PASS

        negative = _plugin("auth_reject_wrong_password")
        negative_evidence = await negative.collect(ctx)
        assert negative.evaluate(negative_evidence, {})[0].status == Status.PASS

        publickey_only = _plugin("auth_publickey_only")
        policy_evidence = await publickey_only.collect(ctx)
        assert publickey_only.evaluate(policy_evidence, {})[0].status == Status.FAIL
    finally:
        server.close()
        await server.wait_closed()

    rendered = (positive_evidence.model_dump_json()
                + negative_evidence.model_dump_json() + policy_evidence.model_dump_json())
    assert "server-password-marker" not in rendered


@pytest.mark.asyncio
async def test_private_key_login_against_real_server():
    user_key = asyncssh.generate_private_key("ssh-ed25519")
    server = await asyncssh.create_server(
        lambda: _PublicKeyServer(user_key.convert_to_public().public_data),
        "127.0.0.1", 0,
        server_host_keys=[asyncssh.generate_private_key("ssh-ed25519")],
        process_factory=_success_process,
    )
    port = server.sockets[0].getsockname()[1]
    credentials = Credentials(
        method="private_key", username="audit",
        private_key=user_key.export_private_key().decode(),
    )
    ctx = Context(
        host="127.0.0.1", port=port, policy={}, params={}, emit=lambda _msg: None,
        credentials=credentials, profile=SimpleNamespace(safe_command="id"),
    )
    try:
        plugin = _plugin("auth_private_key")
        evidence = await plugin.collect(ctx)
        assert plugin.evaluate(evidence, {})[0].status == Status.PASS
        assert credentials.private_key.get_secret_value() not in evidence.model_dump_json()
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_keyboard_interactive_login_against_real_server():
    server = await asyncssh.create_server(
        _KeyboardInteractiveServer, "127.0.0.1", 0,
        server_host_keys=[asyncssh.generate_private_key("ssh-ed25519")],
        process_factory=_success_process,
    )
    port = server.sockets[0].getsockname()[1]
    credentials = Credentials(
        method="keyboard_interactive", username="audit",
        keyboard_interactive_responses=["alpha-marker", "beta-marker"],
    )
    ctx = Context(
        host="127.0.0.1", port=port, policy={}, params={}, emit=lambda _msg: None,
        credentials=credentials, profile=SimpleNamespace(safe_command="id"),
    )
    try:
        plugin = _plugin("auth_keyboard_interactive")
        evidence = await plugin.collect(ctx)
        assert plugin.evaluate(evidence, {})[0].status == Status.PASS
        assert all(secret not in evidence.model_dump_json()
                   for secret in credentials.secret_values())
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("accept_ca", "accept_raw", "expected"),
    [
        (True, False, Status.PASS),
        # A certificate rejected by its CA must not fall back to the raw key, even
        # when that exact key would otherwise be authorized by the server.
        (False, True, Status.FAIL),
    ],
)
async def test_certificate_login_uses_only_the_certificate_pair(
    accept_ca, accept_raw, expected,
):
    user_key = asyncssh.generate_private_key("ssh-ed25519")
    user_public = user_key.convert_to_public()
    ca_key = asyncssh.generate_private_key("ssh-ed25519")
    certificate = ca_key.generate_user_certificate(
        user_public, "phase3-test", principals=["audit"],
    )
    server_factory = lambda: _CertificateServer(  # noqa: E731
        ca_key.convert_to_public().public_data,
        user_public.public_data,
        accept_ca=accept_ca,
        accept_raw=accept_raw,
    )
    server = await asyncssh.create_server(
        server_factory, "127.0.0.1", 0,
        server_host_keys=[asyncssh.generate_private_key("ssh-ed25519")],
        process_factory=_success_process,
    )
    port = server.sockets[0].getsockname()[1]
    credentials = Credentials(
        method="certificate", username="audit",
        private_key=user_key.export_private_key().decode(),
        certificate=certificate.export_certificate().decode(),
    )
    ctx = Context(
        host="127.0.0.1", port=port, policy={}, params={}, emit=lambda _msg: None,
        credentials=credentials, profile=SimpleNamespace(safe_command="id"),
    )
    try:
        plugin = _plugin("auth_certificate")
        evidence = await plugin.collect(ctx)
        assert plugin.evaluate(evidence, {})[0].status == expected
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("test_id", "credentials"),
    [
        ("auth_password", Credentials(method="password", username="audit",
                                      password="password-marker")),
        ("auth_private_key", Credentials(method="private_key", username="audit",
                                         private_key="key-marker")),
        ("auth_certificate", Credentials(method="certificate", username="audit",
                                         private_key="key-marker",
                                         certificate="certificate-marker")),
        ("auth_keyboard_interactive",
         Credentials(method="keyboard_interactive", username="audit",
                     keyboard_interactive_responses=["response-marker"])),
    ],
)
async def test_positive_plugins_run_safe_command_without_returning_secrets(
    monkeypatch, test_id, credentials,
):
    calls = []

    async def run(_ctx, command, **kwargs):
        calls.append((command, kwargs))
        return auth.CommandResult("secret-looking output is not evidence", "", 0)

    monkeypatch.setattr(auth, "run_authenticated_command", run)
    plugin = _plugin(test_id)
    evidence = await plugin.collect(_ctx(credentials))
    findings = plugin.evaluate(evidence, {})

    assert calls[0][0] == "id"
    assert findings[0].status == Status.PASS
    rendered = evidence.model_dump_json() + repr(findings)
    for secret in credentials.secret_values():
        assert secret not in rendered


@pytest.mark.asyncio
async def test_positive_plugin_mismatch_is_skip(monkeypatch):
    async def should_not_run(*_args, **_kwargs):
        raise AssertionError("command must not run")

    monkeypatch.setattr(auth, "run_authenticated_command", should_not_run)
    plugin = _plugin("auth_private_key")
    evidence = await plugin.collect(_ctx(Credentials(
        method="password", username="audit", password="pw",
    )))
    assert plugin.evaluate(evidence, {})[0].status == Status.SKIP


@pytest.mark.asyncio
async def test_exception_text_is_never_returned(monkeypatch):
    marker = "exception-contains-password-marker"

    async def fail(*_args, **_kwargs):
        raise RuntimeError(marker)

    monkeypatch.setattr(auth, "run_authenticated_command", fail)
    plugin = _plugin("auth_password")
    evidence = await plugin.collect(_ctx(Credentials(
        method="password", username="audit", password=marker,
    )))
    findings = plugin.evaluate(evidence, {})
    assert findings[0].status == Status.ERROR
    assert marker not in evidence.model_dump_json() + repr(findings)


@pytest.mark.asyncio
async def test_invalid_private_key_text_is_not_returned():
    marker = "invalid-private-key-canary"
    plugin = _plugin("auth_private_key")
    evidence = await plugin.collect(_ctx(Credentials(
        method="private_key", username="audit", private_key=marker,
    )))
    findings = plugin.evaluate(evidence, {})
    assert findings[0].status == Status.ERROR
    assert marker not in evidence.model_dump_json() + repr(findings)


@pytest.mark.asyncio
async def test_connection_uses_only_the_selected_password_method(monkeypatch):
    captured = {}

    class ConnectionManager:
        async def __aenter__(self):
            return object()

        async def __aexit__(self, *_args):
            return False

    def connect(**options):
        captured.update(options)
        return ConnectionManager()

    monkeypatch.setattr(auth.asyncssh, "connect", connect)
    credentials = Credentials(method="password", username="audit", password="pw-marker")
    async with auth.open_authenticated_connection(_ctx(credentials)):
        pass

    assert captured["preferred_auth"] == ["password"]
    assert captured["password_auth"] is True
    assert captured["public_key_auth"] is False
    assert captured["kbdint_auth"] is False
    assert captured["client_keys"] is None
    assert captured["agent_path"] is None
    assert captured["host_based_auth"] is False
    assert captured["gss_auth"] is False and captured["gss_kex"] is False
    assert captured["config"] is None


@pytest.mark.asyncio
async def test_certificate_is_imported_in_memory_and_paired(monkeypatch):
    captured = {}
    key = object()
    certificate = object()
    certificate_pair = SimpleNamespace(has_cert=True)
    raw_key_pair = SimpleNamespace(has_cert=False)

    class ConnectionManager:
        async def __aenter__(self):
            return object()

        async def __aexit__(self, *_args):
            return False

    monkeypatch.setattr(auth.asyncssh, "import_private_key", lambda *_args, **_kw: key)
    monkeypatch.setattr(auth.asyncssh, "import_certificate", lambda *_args, **_kw: certificate)
    monkeypatch.setattr(
        auth.asyncssh, "load_keypairs",
        lambda pairs: ([certificate_pair, raw_key_pair]
                       if pairs == [(key, certificate)] else []),
    )
    monkeypatch.setattr(
        auth.asyncssh, "connect",
        lambda **options: captured.update(options) or ConnectionManager(),
    )
    credentials = Credentials(
        method="certificate", username="audit", private_key="private-marker",
        private_key_passphrase="passphrase-marker", certificate="certificate-marker",
    )
    async with auth.open_authenticated_connection(_ctx(credentials)):
        pass

    assert captured["client_keys"] == [certificate_pair]
    assert captured["client_certs"] == []
    assert captured["preferred_auth"] == ["publickey"]
    assert captured["password"] is None and captured["password_auth"] is False


def test_keyboard_interactive_callback_consumes_bounded_answers_in_order():
    client = auth._KeyboardInteractiveClient(("first-marker", "second-marker"))
    assert client.kbdint_auth_requested() == ""
    assert client.kbdint_challenge_received("", "", "", [("one", False)]) == [
        "first-marker"
    ]
    assert client.kbdint_challenge_received("", "", "", [("two", False)]) == [
        "second-marker"
    ]
    assert client.kbdint_challenge_received("", "", "", [("extra", False)]) is None

    client = auth._KeyboardInteractiveClient(("", "otp-marker"))
    assert client.kbdint_challenge_received(
        "", "", "", [("optional", False), ("otp", False)],
    ) == ["", "otp-marker"]


@pytest.mark.asyncio
async def test_wrong_password_rejection_is_pass_and_uses_one_random_value(monkeypatch):
    class Denied(Exception):
        pass

    attempts = []

    @asynccontextmanager
    async def reject(_ctx, _credentials, _method, **kwargs):
        attempts.append((kwargs["password_override"], kwargs["disable_trivial_auth"]))
        raise Denied()
        yield  # pragma: no cover

    monkeypatch.setattr(auth.asyncssh, "PermissionDenied", Denied)
    monkeypatch.setattr(auth, "_open_with_method", reject)
    credentials = Credentials(method="password", username="audit",
                              password="real-password-marker")
    plugin = _plugin("auth_reject_wrong_password")
    evidence = await plugin.collect(_ctx(credentials))
    finding = plugin.evaluate(evidence, {})[0]

    assert finding.status == Status.PASS
    assert len(attempts) == 1
    assert attempts[0][0] != "real-password-marker" and attempts[0][1] is False
    assert "real-password-marker" not in evidence.model_dump_json() + repr(finding)


@pytest.mark.asyncio
async def test_negative_check_accepts_username_only_credentials(monkeypatch):
    @asynccontextmanager
    async def reject(*_args, **_kwargs):
        raise auth.asyncssh.PermissionDenied("rejected")
        yield  # pragma: no cover

    monkeypatch.setattr(auth, "_open_with_method", reject)
    plugin = _plugin("auth_reject_wrong_password")
    evidence = await plugin.collect(_ctx(Credentials(method="none", username="audit")))
    assert plugin.evaluate(evidence, {})[0].status == Status.PASS


@pytest.mark.asyncio
async def test_unauthorized_key_acceptance_is_fail(monkeypatch):
    @asynccontextmanager
    async def accept(*_args, **_kwargs):
        yield object()

    monkeypatch.setattr(auth.asyncssh, "generate_private_key", lambda _alg: object())
    monkeypatch.setattr(auth, "_open_with_method", accept)
    plugin = _plugin("auth_reject_unauthorized_key")
    evidence = await plugin.collect(_ctx(Credentials(
        method="password", username="audit", password="pw",
    )))
    assert plugin.evaluate(evidence, {})[0].status == Status.FAIL


@pytest.mark.asyncio
async def test_publickey_only_needs_known_password(monkeypatch):
    @asynccontextmanager
    async def should_not_open(*_args, **_kwargs):
        raise AssertionError("connection must not open")
        yield  # pragma: no cover

    monkeypatch.setattr(auth, "_open_with_method", should_not_open)
    plugin = _plugin("auth_publickey_only")
    evidence = await plugin.collect(_ctx(Credentials(
        method="private_key", username="audit", private_key="key",
    )))
    assert plugin.evaluate(evidence, {})[0].status == Status.SKIP


@pytest.mark.asyncio
async def test_repeated_sessions_are_small_and_sequential(monkeypatch):
    calls = 0

    async def run(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return auth.CommandResult("", "", 0)

    monkeypatch.setattr(auth, "run_authenticated_command", run)
    plugin = _plugin("auth_repeated_sessions")
    evidence = await plugin.collect(_ctx(Credentials(
        method="password", username="audit", password="pw",
    )))
    assert plugin.evaluate(evidence, {})[0].status == Status.PASS
    assert calls == auth.REPEATED_SESSION_COUNT == 3


@pytest.mark.asyncio
async def test_bounded_reader_drains_everything_but_retains_only_limit():
    class Reader:
        def __init__(self):
            self.chunks = [b"abcd", b"efgh", b""]
            self.reads = 0

        async def read(self, _size):
            self.reads += 1
            return self.chunks.pop(0)

    reader = Reader()
    text, truncated = await auth._read_bounded(reader, 5)
    assert text == "abcde" and truncated
    assert reader.reads == 3


@pytest.mark.asyncio
async def test_command_cancellation_closes_process_and_connection(monkeypatch):
    started = asyncio.Event()
    never = asyncio.Event()

    class Reader:
        async def read(self, _size):
            started.set()
            await never.wait()

    class Process:
        def __init__(self):
            self.stdout = Reader()
            self.stderr = Reader()
            self.stdin = SimpleNamespace(write_eof=lambda: None)
            self.exit_status = None
            self.closed = False
            self.terminated = False

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            self.close()
            return False

        async def wait_closed(self):
            return None

        def terminate(self):
            self.terminated = True

        def close(self):
            self.closed = True

    process = Process()

    class Connection:
        async def create_process(self, _command, **_kwargs):
            return process

    connection_closed = False

    @asynccontextmanager
    async def connection(_ctx, _credentials=None):
        nonlocal connection_closed
        try:
            yield Connection()
        finally:
            connection_closed = True

    monkeypatch.setattr(auth, "open_authenticated_connection", connection)
    task = asyncio.create_task(auth.run_authenticated_command(
        _ctx(Credentials(method="password", username="audit", password="pw")), "id",
    ))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert process.closed and process.terminated and connection_closed
