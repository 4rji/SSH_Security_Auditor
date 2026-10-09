import pytest

from ssh_auditor.service import ScanRejected, normalize_load_params


def test_iterations_default_is_capped_to_profile():
    # generic max_connections = 20 → default iterations min(50, 20) = 20
    assert normalize_load_params({}, 20)["iterations"] == 20
    assert normalize_load_params({}, 100)["iterations"] == 50


def test_iterations_above_max_connections_is_rejected():
    with pytest.raises(ScanRejected) as exc:
        normalize_load_params({"iterations": 999}, 20)
    assert "iterations" in str(exc.value)


def test_invalid_field_is_rejected():
    with pytest.raises(ScanRejected):
        normalize_load_params({"error_rate_pct": 999}, 20)


def test_defaults_are_filled():
    out = normalize_load_params({}, 20)
    assert out["error_rate_pct"] == 10 and out["p95_factor"] == 3.0
