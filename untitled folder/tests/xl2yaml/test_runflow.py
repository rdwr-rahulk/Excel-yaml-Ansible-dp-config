"""End-to-end `xl2yaml run` against a fake ansible-playbook (no device, no network).

Covers acceptance tests 7, 8, 9, 10 and 11 at flow level: input logging, no
fallback, single allowlisted target, apply only in an authorized Phase B, and
partial failure stops the run before Phase B.
"""

import json

import yaml

from conftest import LAB_IP
from fixture_writer import workbook_from_config
from xl2yaml.manifest import Manifest
from xl2yaml.runflow import RunArgs, run


def _wb(repo, cfg, **rc):
    repo.input_dir.mkdir(exist_ok=True)
    workbook_from_config(str(repo.default_workbook), cfg, **rc)


def _manifest(repo):
    paths = sorted(repo.runs_dir.glob("*/run_manifest.json"))
    return Manifest.load(paths[-1])


def test_phase_a_then_b_excel_mode(repo, known_good, fake_ansible):
    _wb(repo, known_good, authorize_policy_apply=True, change_ticket="CHG100", authorized_by="Lead")
    rc = run(RunArgs(phase="AB", confirm_targets="dp1"), repo)
    m = _manifest(repo)
    assert rc == 0, m.__dict__
    assert m.input["mode"] == "EXCEL" and m.input["sha256"]
    assert m.phases["A"]["result"] == "PASS" and m.readback["result"] == "PASS" and m.phases["B"]["result"] == "PASS"
    assert fake_ansible.playbooks() == ["create_full_config.yml", "get_network_class.yml", "update_policies.yml"]
    # Phase A staged file had apply off; Phase B used a one-device, stop-on-error update_vars.yml
    assert all("create_vars.yml" in c["vars"] or c["playbook"] != "create_full_config.yml" for c in fake_ansible.read())
    assert not list(repo.staging_root.glob("*")), "staging directories must be removed"


def test_phase_b_refused_without_authorization(repo, known_good, fake_ansible):
    _wb(repo, known_good)
    rc = run(RunArgs(phase="AB", confirm_targets="dp1"), repo)
    assert rc != 0
    assert "update_policies.yml" not in fake_ansible.playbooks()
    m = _manifest(repo)
    assert m.result == "FAILED_PREFLIGHT_B"
    assert any(c["check"] == "APPLY_NOT_AUTHORIZED" for c in m.preflight["B"]["checks"])


def test_partial_failure_stops_before_apply(repo, known_good, fake_ansible, monkeypatch):
    monkeypatch.setenv("FAKE_MODE", "partial_nc")
    _wb(repo, known_good, authorize_policy_apply=True, change_ticket="CHG1", authorized_by="Lead")
    rc = run(RunArgs(phase="AB", confirm_targets="dp1"), repo)
    assert rc != 0
    assert fake_ansible.playbooks() == ["create_full_config.yml"]
    assert _manifest(repo).result == "FAILED_PHASE_A"


def test_failed_module_stops_before_apply(repo, known_good, fake_ansible, monkeypatch):
    monkeypatch.setenv("FAKE_MODE", "fail_bdos")
    _wb(repo, known_good, authorize_policy_apply=True, change_ticket="CHG1", authorized_by="Lead")
    assert run(RunArgs(phase="AB", confirm_targets="dp1"), repo) != 0
    assert "update_policies.yml" not in fake_ansible.playbooks()


def test_unclear_apply_confirmation_fails_phase_b(repo, known_good, fake_ansible, monkeypatch):
    monkeypatch.setenv("FAKE_MODE", "apply_unclear")
    _wb(repo, known_good, authorize_policy_apply=True, change_ticket="CHG1", authorized_by="Lead")
    assert run(RunArgs(phase="AB", confirm_targets="dp1"), repo) != 0
    assert _manifest(repo).result == "FAILED_PHASE_B"


def test_phase_b_later_requires_matching_phase_a(repo, known_good, fake_ansible):
    _wb(repo, known_good)
    assert run(RunArgs(phase="A", confirm_targets="dp1"), repo) == 0
    run_a = _manifest(repo).run_id
    # approval recorded afterwards in Run_Control - the configuration itself is unchanged
    _wb(repo, known_good, authorize_policy_apply=True, change_ticket="CHG2", authorized_by="Lead")
    assert run(RunArgs(phase="B", after_run=run_a, confirm_targets="dp1"), repo) == 0
    # a changed configuration cannot reuse that Phase A
    changed = json.loads(json.dumps(known_good))
    changed["create_security_policies"][0]["priority"] = "701"
    _wb(repo, changed, authorize_policy_apply=True, change_ticket="CHG3", authorized_by="Lead")
    assert run(RunArgs(phase="B", after_run=run_a, confirm_targets="dp1"), repo) != 0


def test_invalid_workbook_never_falls_back_to_yaml(repo, known_good, fake_ansible):
    repo.create_vars.write_text(yaml.safe_dump(known_good))      # a perfectly valid YAML is present
    bad = json.loads(json.dumps(known_good))
    del bad["cl_protections"][0]["app_port_group"]
    _wb(repo, bad)
    rc = run(RunArgs(phase="A", confirm_targets="dp1"), repo)
    m = _manifest(repo)
    assert rc != 0 and m.result == "FAILED_VALIDATION" and m.input["mode"] == "EXCEL"
    assert fake_ansible.playbooks() == []


def test_yaml_mode_is_today_s_file_staged_for_one_device(repo, known_good, fake_ansible):
    cfg = json.loads(json.dumps(known_good))
    cfg["dp_ip"] = [LAB_IP, "10.105.192.33"]
    repo.create_vars.write_text(yaml.safe_dump(cfg))
    rc = run(RunArgs(phase="A", env="lab", device="dp1", confirm_targets="dp1"), repo)
    m = _manifest(repo)
    assert rc == 0, m.__dict__
    assert m.input["mode"] == "YAML"
    assert any("narrowed" in n for n in m.notes)
    assert yaml.safe_load((repo.runs_dir / m.run_id / "create_vars_dp1.yml").read_text())["dp_ip"] == [LAB_IP]


def test_target_not_on_allowlist_never_runs(repo, known_good, fake_ansible):
    cfg = json.loads(json.dumps(known_good))
    cfg["dp_ip"] = ["10.1.1.1"]
    _wb(repo, cfg)
    assert run(RunArgs(phase="A", confirm_targets="dp1"), repo) != 0
    assert fake_ansible.playbooks() == []


def test_unconfirmed_run_never_starts(repo, known_good, fake_ansible):
    _wb(repo, known_good)
    assert run(RunArgs(phase="A", confirm_targets="someone-else"), repo) != 0
    assert fake_ansible.playbooks() == []
