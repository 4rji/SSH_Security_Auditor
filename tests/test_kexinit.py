import struct

import pytest

from ssh_auditor.kexinit import KexInitError, parse_kexinit


def _namelist(s: str) -> bytes:
    b = s.encode()
    return struct.pack(">I", len(b)) + b


def _build(kex, hostkey, enc, mac, comp, first_follows=False) -> bytes:
    body = b"\x14"            # SSH_MSG_KEXINIT
    body += b"\x00" * 16      # cookie
    for nl in (kex, hostkey, enc, enc, mac, mac, comp, comp, "", ""):
        body += _namelist(nl)
    body += b"\x01" if first_follows else b"\x00"
    body += struct.pack(">I", 0)  # reserved
    return body


def test_parse_basic_kexinit():
    payload = _build(
        kex="mlkem768x25519-sha256,curve25519-sha256",
        hostkey="ssh-ed25519,rsa-sha2-512",
        enc="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
        mac="hmac-sha2-256-etm@openssh.com",
        comp="none",
    )
    k = parse_kexinit(payload)
    assert k.kex == ["mlkem768x25519-sha256", "curve25519-sha256"]
    assert k.server_host_key == ["ssh-ed25519", "rsa-sha2-512"]
    assert k.enc_s2c == ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"]
    assert k.comp_c2s == ["none"]
    assert k.first_kex_follows is False


def test_rejects_wrong_message_type():
    with pytest.raises(KexInitError):
        parse_kexinit(b"\x15" + b"\x00" * 16 + struct.pack(">I", 0) * 10)


def test_rejects_truncated_namelist():
    bad = b"\x14" + b"\x00" * 16 + struct.pack(">I", 1000)
    with pytest.raises(KexInitError):
        parse_kexinit(bad)


def test_rejects_empty_payload():
    with pytest.raises(KexInitError):
        parse_kexinit(b"")
