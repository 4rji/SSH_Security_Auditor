from ssh_auditor.models import Evidence, Status
from ssh_auditor.plugins.memory import MemoryYescryptPlugin

PERF = {"hash_cost_mib": 16, "expected_method": "yescrypt",
        "login_latency_limit_ms": 1500, "mem_warn_fraction": 0.75,
        "concurrency_success_floor_pct": 95}


def _ev(**over):
    data = {"applicable": True, "mem_available_mib": 1531,
            "maxstartups": {"start": 10, "rate": 30, "full": 100},
            "configured_method": "yescrypt", "login_ms": 410, "errors": {}}
    data.update(over)
    return Evidence(data=data)


def _by_id(findings):
    return {f.id: f for f in findings}


def test_worst_case_over_available_is_fail():
    # 100 * 16 = 1600 MiB > 1531 available
    f = _by_id(MemoryYescryptPlugin().evaluate(_ev(), {"performance": PERF}))
    assert f["pre-auth-memory"].status == Status.FAIL


def test_comfortable_margin_is_pass():
    # full=40 -> 640 MiB, well under 0.75*1531
    f = _by_id(MemoryYescryptPlugin().evaluate(
        _ev(maxstartups={"start": 10, "rate": 30, "full": 40}), {"performance": PERF}))
    assert f["pre-auth-memory"].status == Status.PASS


def test_latency_over_limit_is_warn_or_fail():
    f = _by_id(MemoryYescryptPlugin().evaluate(_ev(login_ms=4000), {"performance": PERF}))
    assert f["login-latency"].status in (Status.WARN, Status.FAIL)


def test_wrong_method_is_warn():
    f = _by_id(MemoryYescryptPlugin().evaluate(
        _ev(configured_method="sha512"), {"performance": PERF}))
    assert f["hash-method"].status == Status.WARN


def test_missing_maxstartups_does_not_crash_or_error():
    f = _by_id(MemoryYescryptPlugin().evaluate(
        _ev(maxstartups=None, errors={"maxstartups": "sshd -T unavailable"}),
        {"performance": PERF}))
    assert "pre-auth-memory" not in f or f["pre-auth-memory"].status != Status.ERROR
