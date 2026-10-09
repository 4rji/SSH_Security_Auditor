from ssh_auditor.store import Policy, parse


def test_performance_defaults():
    p = Policy.model_validate({"id": "x"})
    assert p.performance.hash_cost_mib == 16
    assert p.performance.expected_method == "yescrypt"
    assert p.performance.login_latency_limit_ms == 1500
    assert p.performance.mem_warn_fraction == 0.75
    assert p.performance.concurrency_success_floor_pct == 95


def test_performance_from_yaml():
    text = ("id: hard\nperformance:\n  hash_cost_mib: 32\n"
            "  login_latency_limit_ms: 800\n  concurrency_success_floor_pct: 90\n")
    p = parse("policies", text)
    assert p.performance.hash_cost_mib == 32
    assert p.performance.login_latency_limit_ms == 800
    assert p.performance.concurrency_success_floor_pct == 90
