from __future__ import annotations

import struct
from dataclasses import dataclass

SSH_MSG_KEXINIT = 20
STRICT_KEX_MARKER = "kex-strict-s-v00@openssh.com"
PQ_KEX_PREFIXES = ("mlkem", "sntrup")
AEAD_CIPHERS_SUFFIXES = ("-gcm@openssh.com", "chacha20-poly1305@openssh.com")

# Default preferences of an OpenSSH 10.0 client (`ssh -G`): used to work out what a
# modern client would negotiate, without opening more connections.
REFERENCE_CLIENT = {
    "kex": [
        "mlkem768x25519-sha256", "sntrup761x25519-sha512",
        "sntrup761x25519-sha512@openssh.com", "curve25519-sha256",
        "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521", "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group16-sha512", "diffie-hellman-group18-sha512",
        "diffie-hellman-group14-sha256",
    ],
    "host_key": [
        "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
        "rsa-sha2-512", "rsa-sha2-256",
    ],
    "cipher": [
        "chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
        "aes128-ctr", "aes192-ctr", "aes256-ctr",
    ],
    "mac": [
        "umac-64-etm@openssh.com", "umac-128-etm@openssh.com", "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com", "hmac-sha1-etm@openssh.com", "umac-64@openssh.com",
        "umac-128@openssh.com", "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1",
    ],
}

# Client restricted to NIST-approved algorithms (indicative only: negotiating them does
# not prove a validated FIPS 140-3 module).
FIPS_CLIENT = {
    "kex": [
        "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
        "diffie-hellman-group16-sha512", "diffie-hellman-group18-sha512",
        "diffie-hellman-group14-sha256",
    ],
    "host_key": [
        "rsa-sha2-512", "rsa-sha2-256", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
    ],
    "cipher": [
        "aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr", "aes192-ctr",
        "aes128-ctr",
    ],
    "mac": [
        "hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512",
        "hmac-sha2-256",
    ],
}


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
        raise KexInitError("truncated while reading a name-list length")
    (length,) = struct.unpack_from(">I", buf, off)
    off += 4
    if off + length > len(buf):
        raise KexInitError("truncated while reading a name-list")
    raw = buf[off:off + length].decode("ascii", "replace")
    off += length
    names = [n for n in raw.split(",") if n] if raw else []
    return names, off


def parse_kexinit(payload: bytes) -> KexInit:
    if len(payload) < 1 + 16:
        raise KexInitError("payload too short")
    if payload[0] != SSH_MSG_KEXINIT:
        raise KexInitError(f"not a KEXINIT (type {payload[0]})")
    off = 1 + 16  # message type + 16-byte cookie
    lists: list[list[str]] = []
    for _ in range(10):
        names, off = _read_namelist(payload, off)
        lists.append(names)
    if off + 1 > len(payload):
        raise KexInitError("truncated while reading first_kex_follows")
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


def pq_kex_algs(k: KexInit) -> list[str]:
    return [a for a in k.kex if a.startswith(PQ_KEX_PREFIXES)]


def has_pq_kex(k: KexInit) -> bool:
    return bool(pq_kex_algs(k))


def is_aead(cipher: str) -> bool:
    return cipher.endswith(AEAD_CIPHERS_SUFFIXES)


def negotiate(client: dict[str, list[str]], k: KexInit) -> dict[str, str | None]:
    """Algorithms `client` would choose (RFC 4253 §7.1: the client's first one that the
    server also offers). None = nothing in common. With an AEAD cipher the MAC is
    implicit and is returned as "implicit (AEAD)"."""
    def pick(mine: list[str], theirs: list[str]) -> str | None:
        return next((a for a in mine if a in theirs), None)

    cipher = pick(client["cipher"], k.enc_s2c)
    if cipher and is_aead(cipher):
        mac = "implicit (AEAD)"
    else:
        mac = pick(client["mac"], k.mac_s2c)
    return {
        "kex": pick(client["kex"], k.kex),
        "host_key": pick(client["host_key"], k.server_host_key),
        "cipher": cipher,
        "mac": mac,
    }


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
