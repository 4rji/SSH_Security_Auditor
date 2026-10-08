import importlib


def test_main_module_importable():
    m = importlib.import_module("ssh_auditor.__main__")
    assert hasattr(m, "main")
