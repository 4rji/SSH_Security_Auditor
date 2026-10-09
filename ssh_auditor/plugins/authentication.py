"""Functional SSH authentication checks (catalog category C).

Credential material is consumed here and never copied into Evidence or Finding. All
errors crossing the plugin boundary are deliberately allowlisted summaries; exception
messages from key parsers, SSH servers, and command execution are not returned because
they can contain user-provided input.
"""
from __future__ import annotations

import asyncio
import secrets
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, AsyncIterator

import asyncssh

from ssh_auditor.models import AuthMethod, Credentials, Evidence, Finding, Status
from ssh_auditor.plugins.base import Context, Meta, connection_slot, register

CONNECT_TIMEOUT_S = 10.0
COMMAND_TIMEOUT_S = 10.0
MAX_COMMAND_OUTPUT_BYTES = 64 * 1024
REPEATED_SESSION_COUNT = 3


class CredentialUnavailable(ValueError):
    """The selected test has no usable credential. Its message is always non-sensitive."""


@dataclass(frozen=True)
class CommandResult:
    stdout: str
    stderr: str
    exit_status: int | None
    truncated: bool = False


class _KeyboardInteractiveClient(asyncssh.SSHClient):
    """Supply a bounded, ordered set of answers to keyboard-interactive prompts."""

    def __init__(self, responses: tuple[str, ...]):
        self._responses = responses
        self._next = 0

    def kbdint_auth_requested(self) -> str:
        return ""

    def kbdint_challenge_received(self, _name, _instructions, _lang, prompts):
        count = len(prompts)
        if count == 0:
            return []
        end = self._next + count
        if end > len(self._responses):
            return None
        answers = list(self._responses[self._next:end])
        self._next = end
        return answers


def _context_credentials(ctx: Context, supplied: Credentials | None = None) -> Credentials:
    raw = supplied if supplied is not None else getattr(ctx, "credentials", None)
    if isinstance(raw, Credentials):
        return raw
    try:
        return Credentials.model_validate(raw or {})
    except Exception as exc:  # Never include the validation text: it may contain input.
        raise CredentialUnavailable("The credentials are invalid.") from exc


def _secret(value, missing: str) -> str:
    if value is None or not value.get_secret_value():
        raise CredentialUnavailable(missing)
    return value.get_secret_value()


def _username(credentials: Credentials) -> str:
    if not credentials.username:
        raise CredentialUnavailable("A username is required for this test.")
    return credentials.username


def _base_options(ctx: Context, credentials: Credentials, method: AuthMethod) -> dict[str, Any]:
    """Options which prevent ambient machine credentials or auth fallbacks."""
    return {
        "host": ctx.host,
        "port": ctx.port,
        "username": _username(credentials),
        "known_hosts": None,
        "config": None,
        "connect_timeout": CONNECT_TIMEOUT_S,
        "disable_trivial_auth": True,
        "preferred_auth": [method.value.replace("_", "-")],
        "password": None,
        "client_keys": None,
        "client_certs": [],
        "client_host_keys": None,
        "agent_path": None,
        "pkcs11_provider": None,
        "host_based_auth": False,
        "public_key_auth": False,
        "kbdint_auth": False,
        "password_auth": False,
        "gss_kex": False,
        "gss_auth": False,
        "gss_host": None,
    }


@asynccontextmanager
async def _open_with_method(
    ctx: Context,
    credentials: Credentials,
    method: AuthMethod,
    *,
    password_override: str | None = None,
    client_key_override: Any | None = None,
    disable_trivial_auth: bool = True,
) -> AsyncIterator[Any]:
    options = _base_options(ctx, credentials, method)
    options["disable_trivial_auth"] = disable_trivial_auth

    if method == AuthMethod.PASSWORD:
        password = password_override
        if password is None:
            password = _secret(credentials.password, "A password is required for this test.")
        options.update(password=password, password_auth=True, preferred_auth=["password"])
    elif method == AuthMethod.PRIVATE_KEY:
        key = client_key_override
        if key is None:
            key_text = _secret(
                credentials.private_key, "A private key is required for this test."
            )
            passphrase = (credentials.private_key_passphrase.get_secret_value()
                          if credentials.private_key_passphrase else None)
            key = asyncssh.import_private_key(key_text, passphrase=passphrase)
        options.update(client_keys=[key], public_key_auth=True,
                       preferred_auth=["publickey"])
    elif method == AuthMethod.CERTIFICATE:
        key_text = _secret(
            credentials.private_key,
            "A private key and matching certificate are required for this test.",
        )
        certificate_text = _secret(
            credentials.certificate,
            "A private key and matching certificate are required for this test.",
        )
        passphrase = (credentials.private_key_passphrase.get_secret_value()
                      if credentials.private_key_passphrase else None)
        key = asyncssh.import_private_key(key_text, passphrase=passphrase)
        certificate = asyncssh.import_certificate(certificate_text)
        # load_keypairs() deliberately returns both a certificate pair and the raw
        # private key as a fallback. This check is specifically about certificate
        # authentication, so only offer pairs which carry the supplied certificate.
        cert_pairs = [
            pair for pair in asyncssh.load_keypairs([(key, certificate)])
            if pair.has_cert
        ]
        if not cert_pairs:
            raise CredentialUnavailable(
                "The private key does not match the supplied SSH certificate."
            )
        options.update(client_keys=cert_pairs, client_certs=[], public_key_auth=True,
                       preferred_auth=["publickey"])
    elif method == AuthMethod.KEYBOARD_INTERACTIVE:
        responses = tuple(
            response.get_secret_value()
            for response in credentials.keyboard_interactive_responses
        )
        if not responses:
            raise CredentialUnavailable(
                "At least one keyboard-interactive response is required for this test."
            )
        options.update(
            client_factory=lambda: _KeyboardInteractiveClient(responses),
            kbdint_auth=True,
            preferred_auth=["keyboard-interactive"],
        )
    else:
        raise CredentialUnavailable("Choose an authentication method for this test.")

    async with connection_slot(ctx):
        async with asyncssh.connect(**options) as connection:
            yield connection


@asynccontextmanager
async def open_authenticated_connection(
    ctx: Context, credentials: Credentials | None = None,
) -> AsyncIterator[Any]:
    """Open one connection using only the explicitly selected credential method."""
    selected = _context_credentials(ctx, credentials)
    async with _open_with_method(ctx, selected, selected.method) as connection:
        yield connection


async def _read_bounded(reader, max_bytes: int) -> tuple[str, bool]:
    """Drain a remote stream while retaining at most max_bytes locally."""
    if max_bytes < 0:
        raise ValueError("max_output_bytes must be non-negative")
    kept = bytearray()
    truncated = False
    while True:
        chunk = await reader.read(32 * 1024)
        if not chunk:
            break
        raw = chunk if isinstance(chunk, bytes) else chunk.encode("utf-8", "replace")
        remaining = max_bytes - len(kept)
        if remaining > 0:
            kept.extend(raw[:remaining])
        if len(raw) > max(remaining, 0):
            truncated = True
    return kept.decode("utf-8", "replace"), truncated


async def run_authenticated_command(
    ctx: Context,
    command: str,
    *,
    timeout_s: float = COMMAND_TIMEOUT_S,
    max_output_bytes: int = MAX_COMMAND_OUTPUT_BYTES,
) -> CommandResult:
    """Run a command through the selected credential with bounded captured output."""
    async with open_authenticated_connection(ctx) as connection:
        return await run_command_on_connection(
            connection, command, timeout_s=timeout_s,
            max_output_bytes=max_output_bytes,
        )


async def run_command_on_connection(
    connection: Any,
    command: str,
    *,
    timeout_s: float = COMMAND_TIMEOUT_S,
    max_output_bytes: int = MAX_COMMAND_OUTPUT_BYTES,
) -> CommandResult:
    """Run one bounded command on an already authenticated SSH connection."""
    process = await connection.create_process(command, encoding=None)
    process.stdin.write_eof()

    async def collect_output():
        streams = await asyncio.gather(
            _read_bounded(process.stdout, max_output_bytes),
            _read_bounded(process.stderr, max_output_bytes),
        )
        await process.wait_closed()
        return streams

    try:
        async with process:
            (stdout, stdout_truncated), (stderr, stderr_truncated) = \
                await asyncio.wait_for(collect_output(), timeout=timeout_s)
    except BaseException:
        # Closing the channel is reliable even on servers which ignore TERM.
        try:
            process.terminate()
        except OSError:
            pass
        process.close()
        raise
    return CommandResult(
        stdout=stdout,
        stderr=stderr,
        exit_status=process.exit_status,
        truncated=stdout_truncated or stderr_truncated,
    )


def _safe_command(ctx: Context) -> str:
    profile = getattr(ctx, "profile", None)
    command = (profile.get("safe_command") if isinstance(profile, dict)
               else getattr(profile, "safe_command", ""))
    if not isinstance(command, str) or not command.strip():
        raise CredentialUnavailable("The device profile has no harmless command configured.")
    return command.strip()


def _failure(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, CredentialUnavailable):
        return {"outcome": "skip", "reason": str(exc)}
    if isinstance(exc, asyncssh.PermissionDenied):
        return {"outcome": "rejected"}
    name = type(exc).__name__
    if name in {"KeyImportError", "KeyEncryptionError", "KeyExportError"}:
        return {"outcome": "invalid", "error": "The key or certificate could not be read."}
    if isinstance(exc, (TimeoutError, asyncio.TimeoutError)):
        return {"outcome": "error", "error": "The SSH operation timed out."}
    return {"outcome": "error", "error": f"The SSH operation failed ({name})."}


_METHOD_LABEL = {
    AuthMethod.PASSWORD: "password",
    AuthMethod.PRIVATE_KEY: "private key",
    AuthMethod.CERTIFICATE: "SSH certificate",
    AuthMethod.KEYBOARD_INTERACTIVE: "keyboard-interactive",
}


class PositiveAuthenticationPlugin:
    def __init__(self, test_id: str, name: str, method: AuthMethod):
        self.method = method
        self.meta = Meta(
            id=test_id, version="1", category="C", name=name, impact="low",
            requires_auth=True, timeout_s=25.0, privilege="normal",
            credential_method=method.value,
            actions=(f"Authenticate with {_METHOD_LABEL[method]}",
                     "Run the device profile's harmless command", "Close the session"),
        )

    async def collect(self, ctx: Context) -> Evidence:
        credentials = _context_credentials(ctx)
        if credentials.method != self.method:
            return Evidence(data={
                "outcome": "skip", "method": self.method.value,
                "reason": f"Select {_METHOD_LABEL[self.method]} credentials to run this test.",
            })
        try:
            result = await run_authenticated_command(
                ctx, _safe_command(ctx), timeout_s=COMMAND_TIMEOUT_S,
            )
        except Exception as exc:  # noqa: BLE001 -- converted without exception text
            return Evidence(data={"method": self.method.value, **_failure(exc)})
        return Evidence(data={
            "outcome": "success", "method": self.method.value,
            "command_exit_status": result.exit_status,
            "command_output_truncated": result.truncated,
        })

    def evaluate(self, evidence: Evidence, _policy: dict) -> list[Finding]:
        data = evidence.data
        outcome = data.get("outcome")
        label = _METHOD_LABEL[self.method]
        if outcome == "skip":
            return [Finding(id=self.meta.id, status=Status.SKIP,
                            summary=data["reason"])]
        if outcome == "rejected":
            return [Finding(
                id=self.meta.id, status=Status.FAIL,
                summary=f"The server rejected the supplied {label} credential.",
                recommendation="Check the credential and the server authentication policy.",
            )]
        if outcome in {"invalid", "error"}:
            return [Finding(id=self.meta.id, status=Status.ERROR,
                            summary=data.get("error", "The SSH operation failed."))]
        if outcome == "success" and data.get("command_exit_status") == 0:
            return [Finding(
                id=self.meta.id, status=Status.PASS,
                summary=f"Login with {label} succeeded and the harmless command completed.",
            )]
        return [Finding(
            id=self.meta.id, status=Status.FAIL,
            summary=f"Login with {label} succeeded, but the harmless command failed.",
            recommendation="Check the device profile's safe_command for this platform.",
        )]


class ExpectedRejectionPlugin:
    def __init__(self, test_id: str, name: str, kind: str):
        self.kind = kind
        self.meta = Meta(
            id=test_id, version="1", category="C", name=name, impact="medium",
            requires_auth=True, timeout_s=20.0, privilege="normal",
            credential_method="password" if kind == "publickey_only" else "username",
            actions=({
                "wrong_password": ("Attempt one deliberately incorrect password",
                                   "Close the connection"),
                "unauthorized_key": ("Attempt one ephemeral unauthorized key",
                                     "Close the connection"),
                "publickey_only": ("Attempt the supplied password once",
                                   "Verify that the server rejects it"),
            }[kind]),
        )

    async def collect(self, ctx: Context) -> Evidence:
        credentials = _context_credentials(ctx)
        if not credentials.username:
            return Evidence(data={"outcome": "skip", "reason":
                                  "A username is required for this test."})

        try:
            if self.kind == "wrong_password":
                # One high-entropy value and one connection: no spraying or retries.
                bad_password = secrets.token_urlsafe(32)
                async with _open_with_method(
                    ctx, credentials, AuthMethod.PASSWORD,
                    password_override=bad_password,
                    disable_trivial_auth=False,
                ):
                    pass
            elif self.kind == "unauthorized_key":
                key = asyncssh.generate_private_key("ssh-ed25519")
                async with _open_with_method(
                    ctx, credentials, AuthMethod.PRIVATE_KEY,
                    client_key_override=key,
                    disable_trivial_auth=False,
                ):
                    pass
            else:  # publickey_only
                if credentials.method != AuthMethod.PASSWORD:
                    raise CredentialUnavailable(
                        "Select the known-valid password credential to test publickey-only."
                    )
                async with _open_with_method(
                    ctx, credentials, AuthMethod.PASSWORD,
                    disable_trivial_auth=False,
                ):
                    pass
        except Exception as exc:  # noqa: BLE001 -- converted without exception text
            return Evidence(data=_failure(exc))
        return Evidence(data={"outcome": "accepted"})

    def evaluate(self, evidence: Evidence, _policy: dict) -> list[Finding]:
        data = evidence.data
        outcome = data.get("outcome")
        if outcome == "skip":
            return [Finding(id=self.meta.id, status=Status.SKIP,
                            summary=data["reason"])]
        if outcome == "rejected":
            return [Finding(id=self.meta.id, status=Status.PASS,
                            summary=self._expected_summary())]
        if outcome in {"invalid", "error"}:
            return [Finding(id=self.meta.id, status=Status.ERROR,
                            summary=data.get("error", "The SSH operation failed."))]
        return [Finding(
            id=self.meta.id, status=Status.FAIL, summary=self._accepted_summary(),
            recommendation="Review the SSH authentication policy for this account.",
        )]

    def _expected_summary(self) -> str:
        return {
            "wrong_password": "The server rejected one deliberately incorrect password.",
            "unauthorized_key": "The server rejected one ephemeral unauthorized key.",
            "publickey_only": "The server rejected password authentication as expected.",
        }[self.kind]

    def _accepted_summary(self) -> str:
        return {
            "wrong_password": "The server accepted a deliberately incorrect password.",
            "unauthorized_key": "The server accepted an ephemeral unauthorized key.",
            "publickey_only": (
                "The server accepted a password despite the publickey-only expectation."
            ),
        }[self.kind]


class RepeatedSessionsPlugin:
    meta = Meta(
        id="auth_repeated_sessions", version="1", category="C",
        name="Repeated authenticated sessions", impact="medium", requires_auth=True,
        timeout_s=60.0, privilege="normal", credential_method="selected",
        actions=("Open three authenticated sessions sequentially",
                 "Run the device profile's harmless command in each", "Close each session"),
    )

    async def collect(self, ctx: Context) -> Evidence:
        credentials = _context_credentials(ctx)
        if credentials.method == AuthMethod.NONE:
            return Evidence(data={"outcome": "skip",
                                  "reason": "Choose an authentication method for this test."})
        completed = 0
        try:
            command = _safe_command(ctx)
            for _ in range(REPEATED_SESSION_COUNT):
                result = await run_authenticated_command(
                    ctx, command, timeout_s=COMMAND_TIMEOUT_S,
                )
                if result.exit_status != 0:
                    return Evidence(data={
                        "outcome": "command_failed", "sessions_completed": completed,
                        "expected_sessions": REPEATED_SESSION_COUNT,
                    })
                completed += 1
        except Exception as exc:  # noqa: BLE001 -- converted without exception text
            return Evidence(data={
                **_failure(exc), "sessions_completed": completed,
                "expected_sessions": REPEATED_SESSION_COUNT,
            })
        return Evidence(data={
            "outcome": "success", "sessions_completed": completed,
            "expected_sessions": REPEATED_SESSION_COUNT,
        })

    def evaluate(self, evidence: Evidence, _policy: dict) -> list[Finding]:
        data = evidence.data
        outcome = data.get("outcome")
        if outcome == "skip":
            return [Finding(id=self.meta.id, status=Status.SKIP,
                            summary=data["reason"])]
        if outcome == "success":
            return [Finding(
                id=self.meta.id, status=Status.PASS,
                summary=f"Opened, used, and closed {data['sessions_completed']} sessions.",
            )]
        if outcome == "rejected":
            return [Finding(
                id=self.meta.id, status=Status.FAIL,
                summary="The server rejected the credential during repeated sessions.",
            )]
        if outcome == "command_failed":
            return [Finding(
                id=self.meta.id, status=Status.FAIL,
                summary="A harmless command failed during repeated sessions.",
                recommendation="Check the device profile's safe_command for this platform.",
            )]
        return [Finding(id=self.meta.id, status=Status.ERROR,
                        summary=data.get("error", "The SSH operation failed."))]


AUTH_PLUGINS = (
    PositiveAuthenticationPlugin(
        "auth_password", "Password login", AuthMethod.PASSWORD,
    ),
    PositiveAuthenticationPlugin(
        "auth_private_key", "Private-key login", AuthMethod.PRIVATE_KEY,
    ),
    PositiveAuthenticationPlugin(
        "auth_certificate", "SSH certificate login", AuthMethod.CERTIFICATE,
    ),
    PositiveAuthenticationPlugin(
        "auth_keyboard_interactive", "Keyboard-interactive login",
        AuthMethod.KEYBOARD_INTERACTIVE,
    ),
    ExpectedRejectionPlugin(
        "auth_reject_wrong_password", "Reject an incorrect password", "wrong_password",
    ),
    ExpectedRejectionPlugin(
        "auth_reject_unauthorized_key", "Reject an unauthorized key", "unauthorized_key",
    ),
    ExpectedRejectionPlugin(
        "auth_publickey_only", "Publickey-only rejects passwords", "publickey_only",
    ),
    RepeatedSessionsPlugin(),
)

for _plugin in AUTH_PLUGINS:
    register(_plugin)
