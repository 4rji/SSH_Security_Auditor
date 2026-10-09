import json
import logging
import subprocess
import sys

import pytest
from mcp import Client

import ssh_auditor.plugins  # noqa: F401
from ssh_auditor.config import Config
from ssh_auditor.mcp.server import build_mcp
from ssh_auditor.service import AuditService

TOOLS = {"list_tests", "list_profiles", "start_scan", "get_scan", "cancel_scan",
         "compare_scans"}


def _mcp(allow=("127.0.0.0/8",)):
    return build_mcp(AuditService(Config(
        allow_networks=list(allow), policies_dir="config/policies",
        profiles_dir="config/profiles", custom_dir="",
    ), "0.1.0"))


def _text(r) -> str:
    return r.content[0].text


@pytest.mark.asyncio
async def test_catalog_tools_and_instructions():
    async with Client(_mcp()) as c:
        assert "Recommended flow" in c.instructions
        tools = (await c.list_tools()).tools
        assert {t.name for t in tools} == TOOLS
        start_scan = next(tool for tool in tools if tool.name == "start_scan")
        credential_help = start_scan.input_schema["properties"]["credentials"]["description"]
        for field in (
            "password", "private_key", "private_key_passphrase", "certificate",
            "keyboard_interactive_responses",
        ):
            assert field in credential_help
        tests = (await c.call_tool("list_tests", {})).structured_content["tests"]
        assert {t["id"] for t in tests} >= {"connectivity", "negotiation"}
        by_id = {t["id"]: t for t in tests}
        assert by_id["connectivity"]["needs_confirm_impact"] is False
        assert by_id["auth_reject_wrong_password"]["needs_confirm_impact"] is True
        assert by_id["sshd_config"]["privilege"] == "root-or-sudo"
        profs = (await c.call_tool("list_profiles", {})).structured_content
        generic = next(p for p in profs["device_profiles"] if p["id"] == "generic")
        assert generic["limits"]["max_concurrency"] == 4 and generic["policy"] == "base"
        assert [p["id"] for p in profs["policies"]] == ["base"]


@pytest.mark.asyncio
async def test_scan_then_compare_by_id_and_by_export(ssh_server):
    host, port = ssh_server
    async with Client(_mcp()) as c:
        runs = []
        for _ in range(2):
            r = await c.call_tool("start_scan", {
                "target_host": host, "port": port,
                "tests": ["connectivity", "negotiation"], "run_by": "Ana",
            })
            assert not r.is_error, _text(r)
            sid = r.structured_content["scan_id"]
            st = (await c.call_tool("get_scan", {"scan_id": sid, "wait_s": 30})).structured_content
            assert st["state"] == "done" and st["result"]["run_by"] == "Ana"
            runs.append((sid, st["result"]))
        r = await c.call_tool("compare_scans", {"a_id": runs[0][0], "b_id": runs[1][0]})
        assert not r.is_error, _text(r)
        assert r.structured_content["summary"]["tests"] == {"Unchanged": 2}
        r = await c.call_tool("compare_scans", {
            "a_export": json.dumps(runs[0][1]), "b_id": runs[1][0],
        })
        assert not r.is_error, _text(r)
        assert r.structured_content["meta"]["a"]["scan_id"] == runs[0][0]


@pytest.mark.asyncio
async def test_server_side_limits_reach_claude(risky_plugin):
    async with Client(_mcp(["10.0.0.0/24"])) as c:
        r = await c.call_tool("start_scan", {"target_host": "192.168.1.1",
                                             "tests": ["connectivity"]})
        assert r.is_error and "allowlist" in _text(r)
    async with Client(_mcp()) as c:
        r = await c.call_tool("start_scan", {"target_host": "127.0.0.1",
                                             "tests": ["connectivity"], "concurrency": 5})
        assert r.is_error and "exceeds" in _text(r)
        r = await c.call_tool("start_scan", {"target_host": "127.0.0.1", "tests": [risky_plugin]})
        assert r.is_error and "confirm_impact" in _text(r)
        r = await c.call_tool("start_scan", {"target_host": "127.0.0.1",
                                             "tests": ["connectivity"], "port": 70000})
        assert r.is_error and "Invalid input" in _text(r)


@pytest.mark.asyncio
async def test_credentials_never_leave_mcp_results_or_validation_errors(ssh_server):
    host, port = ssh_server
    secrets = (
        "MCP-PASSWORD-SECRET-1c62fa",
        "MCP-PRIVATE-KEY-SECRET-1c62fa",
        "MCP-PASSPHRASE-SECRET-1c62fa",
        "MCP-CERTIFICATE-SECRET-1c62fa",
        "MCP-KBDINT-SECRET-1c62fa",
    )
    async with Client(_mcp()) as c:
        started = await c.call_tool("start_scan", {
            "target_host": host,
            "port": port,
            "tests": ["connectivity"],
            "credentials": {
                "method": "password",
                "username": "auditor",
                "password": secrets[0],
                "private_key": secrets[1],
                "private_key_passphrase": secrets[2],
                "certificate": secrets[3],
                "keyboard_interactive_responses": [secrets[4]],
            },
        })
        assert not started.is_error, _text(started)
        assert all(secret not in repr(started) for secret in secrets)

        scan_id = started.structured_content["scan_id"]
        finished = await c.call_tool("get_scan", {"scan_id": scan_id, "wait_s": 30})
        assert not finished.is_error, _text(finished)
        assert finished.structured_content["state"] == "done"
        assert all(secret not in repr(finished) for secret in secrets)
        assert "credentials" not in finished.structured_content["result"]

        invalid_secret = "MCP-INVALID-SECRET-9d47c1"
        invalid = await c.call_tool("start_scan", {
            "target_host": host,
            "port": port,
            "tests": ["connectivity"],
            "credentials": {
                "method": "password",
                "username": "auditor",
                "password": invalid_secret + ("x" * 4096),
            },
        })
        assert invalid.is_error
        assert "password" in _text(invalid)
        assert invalid_secret not in repr(invalid)

        # These values used to be rejected by the MCP SDK before start_scan ran,
        # and its default validation error included input_value verbatim.
        wrong_object_secret = "MCP-WRONG-OBJECT-SECRET-c8e31a"
        wrong_object = await c.call_tool("start_scan", {
            "target_host": host,
            "port": port,
            "tests": ["connectivity"],
            "credentials": wrong_object_secret,
        })
        assert wrong_object.is_error
        assert "credentials" in _text(wrong_object)
        assert wrong_object_secret not in repr(wrong_object)

        wrong_field_secret = "MCP-WRONG-FIELD-SECRET-a09d74"
        wrong_field = await c.call_tool("start_scan", {
            "target_host": host,
            "port": port,
            "tests": ["connectivity"],
            "credentials": {
                "method": "password",
                "username": "auditor",
                "password": [wrong_field_secret],
            },
        })
        assert wrong_field.is_error
        assert "password" in _text(wrong_field)
        assert wrong_field_secret not in repr(wrong_field)


@pytest.mark.asyncio
async def test_bad_ids_and_exports_are_clear_errors():
    async with Client(_mcp()) as c:
        r = await c.call_tool("get_scan", {"scan_id": "nope"})
        assert r.is_error and "not found" in _text(r)
        r = await c.call_tool("cancel_scan", {"scan_id": "nope"})
        assert r.is_error
        r = await c.call_tool("compare_scans", {"a_export": "{not json", "b_export": "{}"})
        assert r.is_error and "Side A" in _text(r)
        r = await c.call_tool("compare_scans", {"a_id": "x"})
        assert r.is_error and "side B" in _text(r)
        r = await c.call_tool("compare_scans", {"a_export": "x" * (2 * 1024 * 1024),
                                                "b_id": "x"})
        assert r.is_error and "too large" in _text(r)
        r = await c.call_tool("compare_scans", {"a_export": '{"schema_version": "9"}',
                                                "b_id": "x"})
        assert r.is_error and "schema_version" in _text(r)


def test_building_the_mcp_server_leaves_logging_alone():
    # Under pytest the root logger already has handlers, so check in a clean process.
    code = (
        "import logging, ssh_auditor.plugins\n"
        "from ssh_auditor.config import Config\n"
        "from ssh_auditor.mcp.server import build_mcp\n"
        "from ssh_auditor.service import AuditService\n"
        "build_mcp(AuditService(Config(custom_dir=''), '0'))\n"
        "print(logging.getLogger().getEffectiveLevel())\n"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         check=True).stdout.strip()
    assert out == str(logging.WARNING)  # INFO would send every SSH connection to journald


def test_wait_is_capped_below_client_request_timeouts():
    from ssh_auditor.mcp.server import MAX_WAIT_S, clamp_wait

    assert MAX_WAIT_S < 60  # MCP clients commonly give up on a request at 60 s
    assert clamp_wait(1000) == MAX_WAIT_S
    assert clamp_wait(-5) == 0
    assert clamp_wait(float("nan")) == 0
