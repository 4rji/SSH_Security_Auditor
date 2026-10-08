from __future__ import annotations

import struct
from dataclasses import dataclass

SSH_MSG_KEXINIT = 20
STRICT_KEX_MARKER = "kex-strict-s-v00@openssh.com"
PQ_KEX = {"mlkem768x25519-sha256", "sntrup761x25519-sha512"}


class KexInitError(Exception):
    pass


@dataclass
class KexInit:
    kex: list[str]
    server_host_key: list[str]
    enc_c2s: list[str]
    enc_s2c: list[str]
    mac_c2s: list[str]
    mac_s2c: list[str]
    comp_c2s: list[str]
    comp_s2c: list[str]
    first_kex_follows: bool


def _read_namelist(buf: bytes, off: int) -> tuple[list[str], int]:
    if off + 4 > len(buf):
        raise KexInitError("truncado leyendo longitud de name-list")
    (length,) = struct.unpack_from(">I", buf, off)
    off += 4
    if off + length > len(buf):
        raise KexInitError("truncado leyendo name-list")
    raw = buf[off:off + length].decode("ascii", "replace")
    off += length
    names = [n for n in raw.split(",") if n] if raw else []
    return names, off


def parse_kexinit(payload: bytes) -> KexInit:
    if len(payload) < 1 + 16:
        raise KexInitError("payload demasiado corto")
    if payload[0] != SSH_MSG_KEXINIT:
        raise KexInitError(f"no es KEXINIT (tipo {payload[0]})")
    off = 1 + 16  # tipo de mensaje + cookie de 16 bytes
    lists: list[list[str]] = []
    for _ in range(10):
        names, off = _read_namelist(payload, off)
        lists.append(names)
    if off + 1 > len(payload):
        raise KexInitError("truncado leyendo first_kex_follows")
    first = payload[off] != 0
    return KexInit(
        kex=lists[0],
        server_host_key=lists[1],
        enc_c2s=lists[2],
        enc_s2c=lists[3],
        mac_c2s=lists[4],
        mac_s2c=lists[5],
        comp_c2s=lists[6],
        comp_s2c=lists[7],
        first_kex_follows=first,
    )


def has_pq_kex(k: KexInit) -> bool:
    return any(a in PQ_KEX for a in k.kex)


def is_terrapin_vulnerable(k: KexInit) -> bool:
    if STRICT_KEX_MARKER in k.kex:
        return False
    enc = set(k.enc_s2c)
    mac = set(k.mac_s2c)
    if "chacha20-poly1305@openssh.com" in enc:
        return True
    has_cbc = any(a.endswith("-cbc") for a in enc)
    has_etm = any(a.endswith("-etm@openssh.com") for a in mac)
    return has_cbc and has_etm
