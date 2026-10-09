import pytest

import ssh_auditor.plugins  # noqa: F401  (fuerza el registro de plugins)
from ssh_auditor.engine.cache import TTLCache
from ssh_auditor.engine.runner import _redact_result, _redact_text, run_scan
from ssh_auditor.models import Evidence, Finding, ScanRequest, Status, TestResult
from ssh_auditor.plugins.base import REGISTRY, Meta, register


@pytest.mark.asyncio
async def test_run_scan_negotiation(ssh_server):
    host, port = ssh_server
    cache = TTLCache(ttl_s=60)
    events = []
    req = ScanRequest(
        target_host=host, port=port, profile="generic",
        tests=["connectivity", "negotiation"], policy="base",
    )
    sr = await run_scan(req, policy={}, tool_version="0.1.0", limit=4,
                        cache=cache, on_event=lambda e: events.append(e))
    assert sr.status == "done"
    ids = {r.test_id for r in sr.results}
    assert ids == {"connectivity", "negotiation"}
    assert all(r.status != Status.ERROR for r in sr.results)
    assert cache.get(sr.scan_id) is not None
    assert any(e["type"] == "finished" for e in events)


@pytest.mark.asyncio
async def test_run_scan_unknown_test_is_error(ssh_server):
    host, port = ssh_server
    req = ScanRequest(target_host=host, port=port, tests=["no_existe"], policy="base")
    sr = await run_scan(req, policy={}, tool_version="0.1.0", limit=4, cache=TTLCache(60))
    assert sr.results[0].status == Status.ERROR


def test_secret_redaction_keeps_evidence_keys_and_finding_ids_stable():
    result = TestResult(
        test_id="device_inventory", test_version="1", category="A",
        status=Status.WARN,
        findings=[Finding(
            id="id", status=Status.WARN, summary="model id",
            recommendation="review model",
        )],
        evidence=Evidence(data={"model": "model", "nested": {"id": "id"}}),
        duration_ms=1, impact="none",
    )
    redacted = _redact_result(result, ("model", "id"))

    assert set(redacted.evidence.data) == {"model", "nested"}
    assert set(redacted.evidence.data["nested"]) == {"id"}
    assert redacted.findings[0].id == "id"
    assert redacted.evidence.data["model"] == "[REDACTED]"
    assert redacted.evidence.data["nested"]["id"] == "[REDACTED]"
    assert redacted.findings[0].summary == "[REDACTED] [REDACTED]"


@pytest.mark.parametrize("secret", ["[REDACTED]", "R", "*", "<hidden>"])
def test_redaction_marker_never_reintroduces_the_secret(secret):
    assert secret not in _redact_text(f"before {secret} after", (secret,))


@pytest.mark.asyncio
async def test_runner_connects_to_the_address_admitted_by_the_allowlist():
    class HostProbe:
        meta = Meta(
            id="host_probe", version="1", category="A", name="Host probe",
            impact="none", requires_auth=False, timeout_s=1.0,
        )

        async def collect(self, ctx):
            return Evidence(data={"connected_host": ctx.host})

        def evaluate(self, _evidence, _policy):
            return [Finding(id="host", status=Status.INFO, summary="collected")]

    register(HostProbe())
    try:
        req = ScanRequest(target_host="router.example", tests=["host_probe"], policy="base")
        result = await run_scan(
            req, policy={}, tool_version="0.1.0", limit=1, cache=TTLCache(60),
            connect_host="10.0.0.8",
        )
    finally:
        REGISTRY.pop("host_probe", None)

    assert result.target_host == "router.example"
    assert result.results[0].evidence.data["connected_host"] == "10.0.0.8"
