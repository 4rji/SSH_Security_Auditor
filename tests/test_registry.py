from ssh_auditor.models import Evidence, Finding, Status
from ssh_auditor.plugins.base import Meta, catalog, get, register


class _Dummy:
    meta = Meta(
        id="dummy", version="1", category="B", name="Dummy",
        impact="none", requires_auth=False, timeout_s=5.0,
    )

    async def collect(self, ctx):
        return Evidence(data={"ok": True})

    def evaluate(self, evidence, policy):
        return [Finding(id="dummy", status=Status.INFO, summary="x")]


def test_register_and_get():
    register(_Dummy())
    assert get("dummy").meta.name == "Dummy"
    assert any(m.id == "dummy" for m in catalog())
