import os
import threading

import pytest

from ssh_auditor.store import Policy, Profile, Store, StoreError, example_text, parse

POLICY = "id: strict\nname: Strict\nmacs:\n  forbidden: [hmac-sha1]\n"


def _stores(tmp_path):
    return Store("policies", "config/policies", tmp_path), Store("profiles", "config/profiles", tmp_path)


def test_examples_are_valid_and_builtins_load():
    assert isinstance(parse("policies", example_text("policies")), Policy)
    assert isinstance(parse("profiles", example_text("profiles")), Profile)
    pol, prof = Store("policies", "config/policies", None), Store("profiles", "config/profiles", None)
    assert pol.load("base").macs.forbidden
    assert prof.load("generic").policy == "base"


@pytest.mark.parametrize("text, msg", [
    ("id: x\nkex: {prohibidos: [a]}\n", "kex.prohibidos"),
    ("id: x\nbogus: 1\n", "bogus"),
    ("- a\n- b\n", "mapping"),
    ("id: [unclosed\n", "Invalid YAML"),
    ("id: ../etc/passwd\n", "Invalid id"),
    ("name: no id\n", "id"),
])
def test_parse_rejects_bad_policies(text, msg):
    with pytest.raises(StoreError) as e:
        parse("policies", text)
    assert e.value.status == 422 and msg in e.value.detail


def test_parse_rejects_bad_profile_values():
    with pytest.raises(StoreError) as e:
        parse("profiles", "id: p\nshell: linux_2\nlimits: {max_concurrency: 0}\n")
    assert "shell" in e.value.detail and "max_concurrency" in e.value.detail


def test_parse_rejects_oversized_yaml():
    with pytest.raises(StoreError) as e:
        parse("policies", "id: big\n" + "#" * 70000)
    assert e.value.status == 413


def test_add_list_download_and_delete_with_token(tmp_path):
    pol, _ = _stores(tmp_path)
    item_id, token = pol.add(POLICY, "Ana")
    assert item_id == "strict"
    listed = {e["id"]: e for e in pol.list()}
    assert listed["base"]["builtin"] is True
    assert listed["strict"]["builtin"] is False and listed["strict"]["uploaded_by"] == "Ana"
    assert pol.text("strict") == POLICY
    meta = (tmp_path / "policies" / "strict.meta.json").read_text()
    assert token not in meta  # only its hash is stored

    with pytest.raises(StoreError) as e:
        pol.delete("strict", "wrong-token")
    assert e.value.status == 403
    pol.delete("strict", token)
    assert not pol.exists("strict")
    assert os.listdir(tmp_path / "policies") == []


def test_builtin_ids_are_protected(tmp_path):
    pol, _ = _stores(tmp_path)
    with pytest.raises(StoreError) as e:
        pol.add("id: base\n", "Ana")
    assert e.value.status == 409
    with pytest.raises(StoreError) as e:
        pol.delete("base", "anything")
    assert e.value.status == 403


def test_duplicate_upload_rejected_even_when_racing(tmp_path):
    pol, _ = _stores(tmp_path)
    results = []

    def up():
        try:
            results.append(pol.add(POLICY, "x")[0])
        except StoreError as e:
            results.append(e.status)

    threads = [threading.Thread(target=up) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count("strict") == 1 and results.count(409) == 7
    assert not [n for n in os.listdir(tmp_path / "policies") if n.startswith(".upload-")]


def test_file_whose_id_differs_from_its_name_is_ignored(tmp_path):
    d = tmp_path / "profiles"
    d.mkdir()
    (d / "copy.yaml").write_text("id: other\n")
    store = Store("profiles", "config/profiles", tmp_path)
    assert "copy" not in {e["id"] for e in store.list()}
    with pytest.raises(StoreError):
        store.load("copy")


def test_uploads_disabled_without_custom_dir():
    with pytest.raises(StoreError) as e:
        Store("policies", "config/policies", None).add(POLICY, "Ana")
    assert e.value.status == 503
