import pytest

import ssh_auditor.plugins  # noqa: F401
from ssh_auditor.config import Config
from ssh_auditor.models import ScanRequest
from ssh_auditor.service import AuditService, ScanRejected


def _service(allow=("127.0.0.0/8",)) -> AuditService:
    return AuditService(Config(allow_networks=list(allow), policies_dir="config/policies",
                               profiles_dir="config/profiles", custom_dir=""), "0.1.0")


def _req(**kw) -> ScanRequest:
    return ScanRequest(**{"target_host": "127.0.0.1", "tests": ["connectivity"], **kw})


def _rejected(svc: AuditService, req: ScanRequest) -> ScanRejected:
    with pytest.raises(ScanRejected) as e:
        svc.admit(req)
    return e.value


def test_target_outside_allowlist_is_rejected():
    e = _rejected(_service(["10.0.0.0/24"]), _req(target_host="192.168.1.1"))
    assert e.status == 403


def test_tests_must_be_known_and_not_empty():
    svc = _service()
    assert _rejected(svc, _req(tests=[])).status == 422
    e = _rejected(svc, _req(tests=["connectivity", "nope"]))
    assert e.status == 422 and "nope" in e.detail and "negotiation" in e.detail


def test_concurrency_above_profile_limit_is_rejected():
    svc = _service()  # generic: max_concurrency 4
    e = _rejected(svc, _req(concurrency=5))
    assert e.status == 422 and "exceeds" in e.detail and "(4)" in e.detail
    assert svc.admit(_req(concurrency=4)).req.concurrency == 4


def test_admit_fills_in_profile_defaults_and_dedupes_tests():
    adm = _service().admit(_req(tests=["negotiation", "connectivity", "negotiation"]))
    assert adm.req.policy == "base"  # the generic profile's policy
    assert adm.req.concurrency == 4 and adm.limit == 4
    assert adm.req.tests == ["negotiation", "connectivity"]
    assert "kex" in adm.policy


def test_medium_impact_needs_confirmation(risky_plugin):
    svc = _service()
    e = _rejected(svc, _req(tests=[risky_plugin]))
    assert e.status == 422 and "confirm_impact" in e.detail
    assert svc.admit(_req(tests=[risky_plugin], confirm_impact=True)).req.tests == [risky_plugin]


def test_unknown_profile_is_404():
    assert _rejected(_service(), _req(profile="nope")).status == 404


def test_request_rejects_bad_port_and_empty_host():
    with pytest.raises(ValueError):
        _req(port=70000)
    with pytest.raises(ValueError):
        _req(target_host="")


@pytest.mark.asyncio
async def test_background_scan_end_to_end(ssh_server):
    host, port = ssh_server
    svc = _service()
    sid = svc.start(_req(target_host=host, port=port, tests=["connectivity", "negotiation"]))
    await svc.wait(sid, 30)
    st = svc.status(sid)
    assert st["state"] == "done" and st["result"]["scan_id"] == sid
    assert {r["test_id"] for r in st["result"]["results"]} == {"connectivity", "negotiation"}
    assert svc.result(sid).policy_name == "base"
    for call in (svc.status, svc.result, svc.cancel):
        with pytest.raises(ScanRejected) as e:
            call("nope")
        assert e.value.status == 404
