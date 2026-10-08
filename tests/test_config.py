from ssh_auditor.config import load_config, target_allowed


def test_empty_allowlist_denies(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("listen_port: 7284\nallow_networks: []\n")
    cfg = load_config(cfg_file)
    assert target_allowed(cfg, "10.0.0.5") is False


def test_cidr_allows_and_denies(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("allow_networks: ['10.0.0.0/24']\n")
    cfg = load_config(cfg_file)
    assert target_allowed(cfg, "10.0.0.5") is True
    assert target_allowed(cfg, "192.168.1.5") is False
