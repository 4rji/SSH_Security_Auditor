from __future__ import annotations

import asyncio
import struct

import asyncssh

from ssh_auditor.kexinit import (
    FIPS_CLIENT, REFERENCE_CLIENT, STRICT_KEX_MARKER, has_pq_kex, is_aead,
    is_terrapin_vulnerable, negotiate, parse_kexinit, pq_kex_algs,
)
from ssh_auditor.models import Evidence, Finding, Status
from ssh_auditor.plugins.base import Context, Meta, register

CLIENT_IDENT = b"SSH-2.0-SSHAuditor_0.1\r\n"

# (policy key, evidence field, finding id prefix, text, sshd_config directive)
_FORBIDDEN_CHECKS = [
    ("kex", "kex", "kex-forbidden", "Forbidden key exchange algorithm offered", "KexAlgorithms"),
    ("ciphers", "enc_s2c", "cipher-forbidden", "Forbidden cipher offered", "Ciphers"),
    ("macs", "mac_s2c", "mac-forbidden", "Forbidden MAC offered", "MACs"),
    ("host_key", "server_host_key", "hostkey-forbidden",
     "Forbidden host key algorithm offered", "HostKeyAlgorithms"),
]

_NEGOTIATED_LABEL = {"kex": "KEX", "host_key": "Host key", "cipher": "Cipher", "mac": "MAC"}


AUTH_PROBE_USER = "audit"


def _software(banner: str | None) -> str | None:
    # "SSH-2.0-OpenSSH_9.9p1 Debian-2" -> "OpenSSH_9.9p1 Debian-2"
    parts = (banner or "").split("-", 2)
    return parts[2] if len(parts) == 3 and parts[0] == "SSH" else None


async def _auth_methods(host: str, port: int, timeout: float) -> tuple[list[str] | None, str | None]:
    """Methods the server announces after KEX (a "none" request, no credentials)."""
    try:
        methods = await asyncio.wait_for(
            asyncssh.get_server_auth_methods(host, port, username=AUTH_PROBE_USER, config=None),
            timeout=timeout,
        )
        return list(methods), None
    except Exception as e:  # noqa: BLE001
        return None, f"{type(e).__name__}: {e}"


async def _read_ident_and_kexinit(host: str, port: int, timeout: float):
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    try:
        writer.write(CLIENT_IDENT)
        await writer.drain()
        banner = None
        # The server may send lines before its ident; the ident starts with "SSH-".
        for _ in range(50):
            line = await asyncio.wait_for(reader.readline(), timeout)
            if not line:
                raise ConnectionError("the server closed before sending its ident")
            text = line.decode("ascii", "replace").strip()
            if text.startswith("SSH-"):
                banner = text
                break
        # First binary packet (RFC 4253): uint32 packet_length, byte padding_length,
        # payload, padding. packet_length counts everything but its own 4-byte field.
        header = await asyncio.wait_for(reader.readexactly(5), timeout)
        (pkt_len,) = struct.unpack(">I", header[:4])
        pad_len = header[4]
        body = await asyncio.wait_for(reader.readexactly(pkt_len - 1), timeout)
        payload = body[: len(body) - pad_len]
        return banner, payload
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass


class NegotiationPlugin:
    meta = Meta(
        id="negotiation", version="3", category="B",
        name="SSH negotiation", impact="none",
        requires_auth=False, timeout_s=15.0,
    )

    async def collect(self, ctx: Context) -> Evidence:
        banner, payload = await _read_ident_and_kexinit(ctx.host, ctx.port, self.meta.timeout_s)
        k = parse_kexinit(payload)
        fps: dict[str, str] = {}
        for alg in k.server_host_key:
            try:
                key = await asyncio.wait_for(
                    asyncssh.get_server_host_key(ctx.host, ctx.port, server_host_key_algs=[alg]),
                    timeout=self.meta.timeout_s,
                )
                if key is not None:
                    fps[alg] = key.get_fingerprint("sha256")
            except Exception:  # noqa: BLE001
                continue
        auth_methods, auth_error = await _auth_methods(ctx.host, ctx.port, self.meta.timeout_s)
        return Evidence(data={
            "banner": banner,
            "software": _software(banner),
            "negotiated": negotiate(REFERENCE_CLIENT, k),
            "kex": k.kex,
            "server_host_key": k.server_host_key,
            "enc_s2c": k.enc_s2c,
            "mac_s2c": k.mac_s2c,
            "comp_s2c": k.comp_s2c,
            "strict_kex": STRICT_KEX_MARKER in k.kex,
            "terrapin": is_terrapin_vulnerable(k),
            "pq_kex": has_pq_kex(k),
            "pq_kex_algs": pq_kex_algs(k),
            "aead": [a for a in k.enc_s2c if is_aead(a)],
            "etm": [a for a in k.mac_s2c if a.endswith("-etm@openssh.com")],
            "fips_path": negotiate(FIPS_CLIENT, k),
            "auth_methods": auth_methods,
            "auth_methods_error": auth_error,
            "host_key_fingerprints": fps,
        })

    def evaluate(self, evidence: Evidence, policy: dict) -> list[Finding]:
        d = evidence.data
        out: list[Finding] = []

        out.append(Finding(
            id="version", status=Status.INFO,
            summary=f"SSH server: {d.get('software') or d.get('banner') or 'unknown'}",
        ))

        # What a modern OpenSSH client would negotiate with this server.
        for key, label in _NEGOTIATED_LABEL.items():
            alg = d["negotiated"].get(key)
            if alg:
                out.append(Finding(
                    id=f"negotiated:{key}", status=Status.INFO,
                    summary=f"{label} negotiated with a modern client: {alg}",
                ))
            else:
                out.append(Finding(
                    id=f"negotiated:{key}", status=Status.FAIL,
                    summary=f"{label}: no algorithm in common with a modern OpenSSH client",
                    recommendation="A current client could not connect; "
                                   "enable modern algorithms in sshd_config.",
                ))

        forbidden = 0
        for pol_key, field, prefix, text, directive in _FORBIDDEN_CHECKS:
            banned = set((policy.get(pol_key) or {}).get("forbidden", []))
            for a in d.get(field, []):
                if a in banned:
                    forbidden += 1
                    out.append(Finding(
                        id=f"{prefix}:{a}", status=Status.FAIL,
                        summary=f"{text}: {a}",
                        recommendation=f"Disable it in sshd_config ({directive}).",
                    ))
        if not forbidden:
            out.append(Finding(
                id="no-forbidden", status=Status.PASS,
                summary="The server offers no algorithm forbidden by the policy",
            ))

        out.append(Finding(
            id="strict-kex",
            status=Status.PASS if d["strict_kex"] else Status.WARN,
            summary="Offers Strict KEX (kex-strict-s-v00@openssh.com)" if d["strict_kex"]
                    else "Does not offer Strict KEX (kex-strict-s-v00@openssh.com)",
            recommendation="" if d["strict_kex"]
                           else "Upgrade OpenSSH to 9.6+ to get Strict KEX.",
        ))
        out.append(Finding(
            id="terrapin",
            status=Status.FAIL if d["terrapin"] else Status.PASS,
            summary="Vulnerable to Terrapin (CVE-2023-48795)" if d["terrapin"]
                    else "Not vulnerable to Terrapin",
            recommendation="Enable kex-strict (upgrade OpenSSH) and avoid chacha20-poly1305 "
                           "and CBC ciphers with -etm MACs." if d["terrapin"] else "",
        ))
        pq = d.get("pq_kex_algs") or []
        out.append(Finding(
            id="pq-kex",
            status=Status.PASS if pq else Status.WARN,
            summary=f"Offers post-quantum key exchange: {', '.join(pq)}" if pq
                    else "No post-quantum key exchange",
            recommendation="" if pq else "Upgrade OpenSSH to 9.9+/10 for mlkem768x25519.",
        ))
        aead = d.get("aead") or []
        out.append(Finding(
            id="aead",
            status=Status.PASS if aead else Status.WARN,
            summary=f"Offers authenticated encryption (AEAD): {', '.join(aead)}" if aead
                    else "Does not offer authenticated encryption (AEAD)",
            recommendation="" if aead
                           else "Enable aes256-gcm@openssh.com or aes128-gcm@openssh.com.",
        ))
        etm = d.get("etm") or []
        only_aead = bool(d["enc_s2c"]) and all(is_aead(a) for a in d["enc_s2c"])
        if etm:
            out.append(Finding(id="etm", status=Status.PASS,
                               summary=f"Offers Encrypt-then-MAC MACs: {', '.join(etm)}"))
        elif only_aead:
            out.append(Finding(id="etm", status=Status.INFO,
                               summary="No Encrypt-then-MAC MACs; not needed because "
                                       "every cipher is AEAD"))
        else:
            out.append(Finding(
                id="etm", status=Status.WARN,
                summary="Does not offer Encrypt-then-MAC MACs",
                recommendation="Prefer hmac-sha2-256-etm@openssh.com / "
                               "hmac-sha2-512-etm@openssh.com.",
            ))

        methods = d.get("auth_methods")
        if methods is None:
            out.append(Finding(
                id="auth-methods", status=Status.WARN,
                summary="Could not read the authentication methods: "
                        f"{d.get('auth_methods_error') or 'unknown error'}",
            ))
        elif "none" in methods:
            # asyncssh returns ["none"] when the server accepts the request without credentials.
            out.append(Finding(
                id="auth-methods", status=Status.FAIL,
                summary=f"The server accepted user {AUTH_PROBE_USER} without authentication",
                recommendation="Review sshd_config: unauthenticated access is not expected.",
            ))
        elif not methods:
            out.append(Finding(
                id="auth-methods", status=Status.WARN,
                summary="The server requires authentication but announces no method",
            ))
        else:
            out.append(Finding(
                id="auth-methods", status=Status.INFO,
                summary=f"Authentication methods announced: {', '.join(methods)}",
            ))

        fips = d["fips_path"]
        missing = [_NEGOTIATED_LABEL[k] for k, v in fips.items() if not v]
        fips_note = ("Negotiating approved algorithms does not prove FIPS 140-3: "
                     "verify the module and its CMVP certificate.")
        if missing:
            out.append(Finding(
                id="fips", status=Status.WARN,
                summary="FIPS-oriented path not confirmed: no approved algorithm in common "
                        f"for {', '.join(missing)}",
                recommendation=fips_note,
            ))
        else:
            out.append(Finding(
                id="fips", status=Status.PASS,
                summary="FIPS-oriented path negotiable: " + " · ".join(
                    v for v in fips.values() if v),
                recommendation=fips_note,
            ))

        for alg, fp in d["host_key_fingerprints"].items():
            out.append(Finding(id=f"hostkey:{alg}", status=Status.INFO, summary=f"{alg} {fp}"))
        return out


register(NegotiationPlugin())
