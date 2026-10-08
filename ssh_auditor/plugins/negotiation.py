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

# (clave de política, campo de evidencia, prefijo del hallazgo, texto, directiva de sshd)
_PROHIBITED_CHECKS = [
    ("kex", "kex", "kex-prohibido",
     "Algoritmo de intercambio de claves prohibido ofrecido", "KexAlgorithms"),
    ("cifrados", "enc_s2c", "cifrado-prohibido", "Cifrado prohibido ofrecido", "Ciphers"),
    ("macs", "mac_s2c", "mac-prohibido", "MAC prohibido ofrecido", "MACs"),
    ("host_key", "server_host_key", "hostkey-prohibido",
     "Algoritmo de host key prohibido ofrecido", "HostKeyAlgorithms"),
]

_NEGOTIATED_LABEL = {"kex": "KEX", "host_key": "Host key", "cipher": "Cifrado", "mac": "MAC"}


AUTH_PROBE_USER = "audit"


def _software(banner: str | None) -> str | None:
    # "SSH-2.0-OpenSSH_9.9p1 Debian-2" -> "OpenSSH_9.9p1 Debian-2"
    parts = (banner or "").split("-", 2)
    return parts[2] if len(parts) == 3 and parts[0] == "SSH" else None


async def _auth_methods(host: str, port: int, timeout: float) -> tuple[list[str] | None, str | None]:
    """Métodos que anuncia el servidor tras el KEX (petición "none", sin credenciales)."""
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
        id="negotiation", version="2", category="B",
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
            summary=f"Servidor SSH: {d.get('software') or d.get('banner') or 'desconocido'}",
        ))

        # Lo que negociaría un cliente OpenSSH moderno con este servidor.
        for key, label in _NEGOTIATED_LABEL.items():
            alg = d["negotiated"].get(key)
            if alg:
                out.append(Finding(
                    id=f"negociado:{key}", status=Status.INFO,
                    summary=f"{label} negociado con un cliente moderno: {alg}",
                ))
            else:
                out.append(Finding(
                    id=f"negociado:{key}", status=Status.FAIL,
                    summary=f"{label}: ningún algoritmo en común con un cliente OpenSSH moderno",
                    recommendation="Un cliente actual no podría conectarse; "
                                   "habilitar algoritmos modernos en sshd_config.",
                ))

        prohibited = 0
        for pol_key, field, prefix, text, directive in _PROHIBITED_CHECKS:
            banned = set((policy.get(pol_key) or {}).get("prohibidos", []))
            for a in d.get(field, []):
                if a in banned:
                    prohibited += 1
                    out.append(Finding(
                        id=f"{prefix}:{a}", status=Status.FAIL,
                        summary=f"{text}: {a}",
                        recommendation=f"Deshabilitarlo en sshd_config ({directive}).",
                    ))
        if not prohibited:
            out.append(Finding(
                id="prohibidos", status=Status.PASS,
                summary="El servidor no ofrece ningún algoritmo prohibido por la política",
            ))

        out.append(Finding(
            id="strict-kex",
            status=Status.PASS if d["strict_kex"] else Status.WARN,
            summary="Ofrece Strict KEX (kex-strict-s-v00@openssh.com)" if d["strict_kex"]
                    else "No ofrece Strict KEX (kex-strict-s-v00@openssh.com)",
            recommendation="" if d["strict_kex"]
                           else "Actualizar OpenSSH a 9.6+ para tener Strict KEX.",
        ))
        out.append(Finding(
            id="terrapin",
            status=Status.FAIL if d["terrapin"] else Status.PASS,
            summary="Vulnerable a Terrapin (CVE-2023-48795)" if d["terrapin"]
                    else "No vulnerable a Terrapin",
            recommendation="Habilitar kex-strict (actualizar OpenSSH) y evitar chacha20-poly1305 "
                           "y cifrados CBC con MAC -etm." if d["terrapin"] else "",
        ))
        pq = d.get("pq_kex_algs") or []
        out.append(Finding(
            id="pq-kex",
            status=Status.PASS if pq else Status.WARN,
            summary=f"Ofrece intercambio de claves post-cuántico: {', '.join(pq)}" if pq
                    else "Sin intercambio de claves post-cuántico",
            recommendation="" if pq else "Actualizar OpenSSH a 9.9+/10 para mlkem768x25519.",
        ))
        aead = d.get("aead") or []
        out.append(Finding(
            id="aead",
            status=Status.PASS if aead else Status.WARN,
            summary=f"Ofrece cifrado autenticado (AEAD): {', '.join(aead)}" if aead
                    else "No ofrece cifrados autenticados (AEAD)",
            recommendation="" if aead
                           else "Habilitar aes256-gcm@openssh.com o aes128-gcm@openssh.com.",
        ))
        etm = d.get("etm") or []
        only_aead = bool(d["enc_s2c"]) and all(is_aead(a) for a in d["enc_s2c"])
        if etm:
            out.append(Finding(id="etm", status=Status.PASS,
                               summary=f"Ofrece MACs Encrypt-then-MAC: {', '.join(etm)}"))
        elif only_aead:
            out.append(Finding(id="etm", status=Status.INFO,
                               summary="No ofrece MACs Encrypt-then-MAC; no hacen falta "
                                       "porque todos los cifrados son AEAD"))
        else:
            out.append(Finding(
                id="etm", status=Status.WARN,
                summary="No ofrece MACs Encrypt-then-MAC",
                recommendation="Preferir hmac-sha2-256-etm@openssh.com / "
                               "hmac-sha2-512-etm@openssh.com.",
            ))

        methods = d.get("auth_methods")
        if methods is None:
            out.append(Finding(
                id="auth-metodos", status=Status.WARN,
                summary="No se pudieron leer los métodos de autenticación: "
                        f"{d.get('auth_methods_error') or 'error desconocido'}",
            ))
        elif "none" in methods:
            # asyncssh devuelve ["none"] cuando el servidor acepta la petición sin credenciales.
            out.append(Finding(
                id="auth-metodos", status=Status.FAIL,
                summary=f"El servidor aceptó al usuario {AUTH_PROBE_USER} sin autenticación",
                recommendation="Revisar sshd_config: un acceso sin autenticar no es esperable.",
            ))
        elif not methods:
            out.append(Finding(
                id="auth-metodos", status=Status.WARN,
                summary="El servidor exige autenticación pero no anuncia ningún método",
            ))
        else:
            out.append(Finding(
                id="auth-metodos", status=Status.INFO,
                summary=f"Métodos de autenticación anunciados: {', '.join(methods)}",
            ))

        fips = d["fips_path"]
        missing = [_NEGOTIATED_LABEL[k] for k, v in fips.items() if not v]
        fips_note = ("Que se negocien algoritmos aprobados no demuestra FIPS 140-3: "
                     "hay que verificar el módulo y su certificado CMVP.")
        if missing:
            out.append(Finding(
                id="fips", status=Status.WARN,
                summary=f"Camino FIPS no confirmado: sin algoritmo aprobado en común para "
                        f"{', '.join(missing)}",
                recommendation=fips_note,
            ))
        else:
            out.append(Finding(
                id="fips", status=Status.PASS,
                summary="Camino FIPS negociable: " + " · ".join(
                    v for v in fips.values() if v),
                recommendation=fips_note,
            ))

        for alg, fp in d["host_key_fingerprints"].items():
            out.append(Finding(id=f"hostkey:{alg}", status=Status.INFO, summary=f"{alg} {fp}"))
        return out


register(NegotiationPlugin())
