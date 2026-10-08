from ssh_auditor.kexinit import (
    FIPS_CLIENT, REFERENCE_CLIENT, KexInit, has_pq_kex, is_terrapin_vulnerable, negotiate,
    pq_kex_algs,
)


def _k(kex, enc, mac):
    return KexInit(
        kex=kex, server_host_key=["ssh-ed25519"],
        enc_c2s=enc, enc_s2c=enc, mac_c2s=mac, mac_s2c=mac,
        comp_c2s=["none"], comp_s2c=["none"], first_kex_follows=False,
    )


def test_terrapin_vulnerable_chacha_without_strict():
    k = _k(["curve25519-sha256"], ["chacha20-poly1305@openssh.com"], ["hmac-sha2-256"])
    assert is_terrapin_vulnerable(k) is True


def test_terrapin_safe_with_strict_kex():
    k = _k(
        ["curve25519-sha256", "kex-strict-s-v00@openssh.com"],
        ["chacha20-poly1305@openssh.com"], ["hmac-sha2-256"],
    )
    assert is_terrapin_vulnerable(k) is False


def test_terrapin_vulnerable_cbc_etm():
    k = _k(["curve25519-sha256"], ["aes256-cbc"], ["hmac-sha2-256-etm@openssh.com"])
    assert is_terrapin_vulnerable(k) is True


def test_terrapin_safe_gcm_only():
    k = _k(["curve25519-sha256"], ["aes256-gcm@openssh.com"], ["hmac-sha2-256-etm@openssh.com"])
    assert is_terrapin_vulnerable(k) is False


def test_pq_kex_detected():
    assert has_pq_kex(_k(["mlkem768x25519-sha256"], ["aes256-gcm@openssh.com"], [])) is True
    assert has_pq_kex(_k(["curve25519-sha256"], ["aes256-gcm@openssh.com"], [])) is False


def test_pq_kex_algs_lists_all_hybrids():
    k = _k(["sntrup761x25519-sha512@openssh.com", "curve25519-sha256", "mlkem768x25519-sha256"],
           ["aes256-gcm@openssh.com"], [])
    assert pq_kex_algs(k) == ["sntrup761x25519-sha512@openssh.com", "mlkem768x25519-sha256"]


def test_negotiate_picks_first_client_preference_and_implicit_mac():
    k = _k(["diffie-hellman-group14-sha256", "curve25519-sha256"],
           ["aes256-ctr", "aes256-gcm@openssh.com"], ["hmac-sha2-256"])
    n = negotiate(REFERENCE_CLIENT, k)
    assert n["kex"] == "curve25519-sha256"
    assert n["host_key"] == "ssh-ed25519"
    assert n["cipher"] == "aes256-gcm@openssh.com"
    assert n["mac"] == "implicit (AEAD)"


def test_negotiate_reports_missing_common_algorithm():
    k = _k(["curve25519-sha256"], ["chacha20-poly1305@openssh.com"], ["umac-64-etm@openssh.com"])
    n = negotiate(FIPS_CLIENT, k)
    assert n["kex"] is None and n["host_key"] is None and n["cipher"] is None
    assert n["mac"] is None
