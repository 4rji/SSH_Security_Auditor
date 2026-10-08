from __future__ import annotations

import asyncio
import struct

import asyncssh

from ssh_auditor.kexinit import has_pq_kex, is_terrapin_vulnerable, parse_kexinit
from ssh_auditor.models import Evidence, Finding, Status
from ssh_auditor.plugins.base import Context, Meta, register

CLIENT_IDENT = b"SSH-2.0-SSHAuditor_0.1\r\n"


async def _read_ident_and_kexinit(host: str, port: int, timeout: float):
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    try:
        writer.write(CLIENT_IDENT)
        await writer.drain()
        banner = None
        # El servidor puede enviar líneas previas al ident; el ident empieza por "SSH-".
        for _ in range(50):
            line = await asyncio.wait_for(reader.readline(), timeout)
            if not line:
                raise ConnectionError("el servidor cerró antes de enviar el ident")
            text = line.decode("ascii", "replace").strip()
            if text.startswith("SSH-"):
                banner = text
                break
        # Primer paquete binario (RFC 4253): uint32 packet_length, byte padding_length,
        # payload, padding. packet_length cuenta todo menos su propio campo de 4 bytes.
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
        id="negotiation", version="1", category="B",
        name="Negociación SSH", impact="none",
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
        return Evidence(data={
            "banner": banner,
            "kex": k.kex,
            "server_host_key": k.server_host_key,
            "enc_s2c": k.enc_s2c,
            "mac_s2c": k.mac_s2c,
            "comp_s2c": k.comp_s2c,
            "host_key_fingerprints": fps,
            "terrapin": is_terrapin_vulnerable(k),
            "pq_kex": has_pq_kex(k),
        })

    def evaluate(self, evidence: Evidence, policy: dict) -> list[Finding]:
        d = evidence.data
        out: list[Finding] = []

        kex_pol = policy.get("kex") or {}
        prohibidos_kex = set(kex_pol.get("prohibidos", []))
        for a in d["kex"]:
            if a in prohibidos_kex:
                out.append(Finding(
                    id=f"kex-prohibido:{a}", status=Status.FAIL,
                    summary=f"Algoritmo de intercambio de claves prohibido ofrecido: {a}",
                    recommendation="Deshabilitarlo en sshd_config (KexAlgorithms).",
                ))

        enc_pol = policy.get("cifrados") or {}
        prohibidos_enc = set(enc_pol.get("prohibidos", []))
        for a in d["enc_s2c"]:
            if a in prohibidos_enc:
                out.append(Finding(
                    id=f"cifrado-prohibido:{a}", status=Status.FAIL,
                    summary=f"Cifrado prohibido ofrecido: {a}",
                    recommendation="Deshabilitarlo en sshd_config (Ciphers).",
                ))

        hk_pol = policy.get("host_key") or {}
        prohibidos_hk = set(hk_pol.get("prohibidos", []))
        for a in d["server_host_key"]:
            if a in prohibidos_hk:
                out.append(Finding(
                    id=f"hostkey-prohibido:{a}", status=Status.FAIL,
                    summary=f"Algoritmo de host key prohibido ofrecido: {a}",
                    recommendation="Deshabilitarlo en sshd_config (HostKeyAlgorithms).",
                ))

        out.append(Finding(
            id="terrapin",
            status=Status.FAIL if d["terrapin"] else Status.PASS,
            summary="Vulnerable a Terrapin (CVE-2023-48795)" if d["terrapin"]
                    else "No vulnerable a Terrapin",
            recommendation="Habilitar kex-strict (actualizar OpenSSH) y evitar chacha20-poly1305 "
                           "y cifrados CBC con MAC -etm." if d["terrapin"] else "",
        ))
        out.append(Finding(
            id="pq-kex",
            status=Status.PASS if d["pq_kex"] else Status.WARN,
            summary="Ofrece intercambio de claves post-cuántico" if d["pq_kex"]
                    else "Sin intercambio de claves post-cuántico",
            recommendation="" if d["pq_kex"] else "Actualizar OpenSSH a 9.9+/10 para mlkem768x25519.",
        ))
        for alg, fp in d["host_key_fingerprints"].items():
            out.append(Finding(id=f"hostkey:{alg}", status=Status.INFO, summary=f"{alg} {fp}"))
        return out


register(NegotiationPlugin())
