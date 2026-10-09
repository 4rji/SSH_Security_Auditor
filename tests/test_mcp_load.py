from ssh_auditor.models import ScanRequest


def test_scanrequest_carries_load_params():
    req = ScanRequest(target_host="10.0.0.5", tests=["concurrency_bounded"],
                      confirm_impact=True, params={"load": {"iterations": 5}})
    assert req.params["load"]["iterations"] == 5
