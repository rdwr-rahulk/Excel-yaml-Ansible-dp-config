"""Acceptance tests 8 and 10: only intended devices; no stale variables."""

import copy
import shutil
import subprocess

import pytest
import yaml

from conftest import LAB_IP
from xl2yaml.preflight import Authorization, Target, run_preflight
from xl2yaml.report import Report
from xl2yaml.staging import cleanup, stage
from xl2yaml.yamlio import dump, sha256_text

TARGET = Target("dp1", LAB_IP)


def _stage(repo, cfg, name="create_vars.yml"):
    text = dump(cfg)
    return stage(repo, "t1", "dp1", "A", {name: text}), sha256_text(text)


def _pf(repo, staged, sha, target=TARGET, env="lab", **kw):
    report = Report()
    kw.setdefault("confirm_targets", target.name)
    res = run_preflight(repo, env, target, "A", staged, "create_vars.yml", sha, report, Authorization(), **kw)
    return res, report


def test_preflight_passes_for_allowlisted_single_device(repo, known_good):
    staged, sha = _stage(repo, known_good)
    res, rep = _pf(repo, staged, sha)
    assert res.passed, rep.render()


@pytest.mark.parametrize("case", ["not_allowlisted", "two_ips", "prod_ip_in_lab", "wrong_name", "controller",
                                  "hash", "group_vars", "inventory_vars", "confirm_mismatch", "non_interactive",
                                  "apply_on", "missing_allowlist"])
def test_preflight_blocks(repo, known_good, case):
    cfg = copy.deepcopy(known_good)
    target, env, kw = TARGET, "lab", {}
    if case == "not_allowlisted":
        target = Target("dp1", "10.1.1.1")
        cfg["dp_ip"] = ["10.1.1.1"]
    if case == "two_ips":
        cfg["dp_ip"] = [LAB_IP, "10.105.192.33"]
    if case == "prod_ip_in_lab":
        (repo.targets_dir / "allowlist_lab.yml").write_text(yaml.safe_dump(
            {"environment": "lab", "controller": "10.0.0.5", "devices": [{"name": "prod1", "ip": "10.9.9.9"}]}))
        target = Target("prod1", "10.9.9.9")
        cfg["dp_ip"] = ["10.9.9.9"]
    if case == "wrong_name":
        target = Target("dp-other", LAB_IP)
    if case == "controller":
        repo.cc_vars.write_text('cc:\n  cc_ip: "10.0.0.9"\n  username: u\n  password: p\n')
    if case == "apply_on":
        cfg["security_policy_config"]["apply_policies_after_creation"] = True
    if case == "missing_allowlist":
        (repo.targets_dir / "allowlist_lab.yml").unlink()
    staged, sha = _stage(repo, cfg)
    if case == "hash":
        (staged.dir / "vars" / "create_vars.yml").write_text(dump(cfg) + "# edited\n")
    if case == "group_vars":
        (staged.dir / "group_vars").mkdir()
    if case == "inventory_vars":
        (staged.dir / "inventory.ini").write_text("[CyberController]\ncc ansible_host=127.0.0.1 dp_ip=10.1.1.1\n")
    if case == "confirm_mismatch":
        kw["confirm_targets"] = "dp2"
    if case == "non_interactive":
        kw["confirm_targets"] = None
        kw["interactive"] = False
    report = Report()
    kw.setdefault("confirm_targets", target.name)
    res = run_preflight(repo, env, target, "A", staged, "create_vars.yml", sha, report, Authorization(), **kw)
    assert not res.passed, case
    assert report.errors


def test_interactive_confirmation(repo, known_good):
    staged, sha = _stage(repo, known_good)
    ok, _ = _pf(repo, staged, sha, confirm_targets=None, interactive=True, prompt=lambda _: "dp1")
    assert ok.passed
    staged2 = stage(repo, "t2", "dp1", "A", {"create_vars.yml": dump(known_good)})
    bad, _ = _pf(repo, staged2, sha, confirm_targets=None, interactive=True, prompt=lambda _: "yes")
    assert not bad.passed


def test_staging_never_inherits_a_stale_create_vars(repo, known_good):
    """Plant a stale vars/create_vars.yml with extra IPs and sections; none of it may reach the staged run."""
    stale = copy.deepcopy(known_good)
    stale["dp_ip"] = [LAB_IP, "10.9.9.9"]
    stale["create_dns_profiles"] = [{"name": "STALE"}]
    stale["security_policy_config"]["create_dns_profiles"] = True
    repo.create_vars.write_text(yaml.safe_dump(stale))
    generated = dump(known_good)
    staged = stage(repo, "t3", "dp1", "A", {"create_vars.yml": generated})
    try:
        assert (staged.dir / "vars" / "create_vars.yml").read_text() == generated
        assert sorted(p.name for p in (staged.dir / "vars").iterdir()) == ["cc.yml", "create_vars.yml"]
        assert "STALE" not in (staged.dir / "vars" / "create_vars.yml").read_text()
    finally:
        cleanup(staged)
    assert not staged.dir.exists()


@pytest.mark.skipif(shutil.which("ansible-playbook") is None, reason="ansible not installed")
def test_real_ansible_sees_only_the_generated_values(repo, known_good):
    """Run real Ansible in the staging dir with a probe playbook that loads vars like create_full_config.yml."""
    stale = copy.deepcopy(known_good)
    stale["dp_ip"] = ["10.9.9.9"]
    repo.create_vars.write_text(yaml.safe_dump(stale))
    staged = stage(repo, "t4", "dp1", "A", {"create_vars.yml": dump(known_good)})
    out = staged.dir / "probe.json"
    probe = staged.dir / "playbooks" / "zz_probe.yml"
    probe.write_text(
        "- hosts: cc\n  gather_facts: false\n  vars_files:\n    - ../vars/cc.yml\n    - ../vars/create_vars.yml\n"
        "  tasks:\n    - ansible.builtin.copy:\n        dest: '" + str(out) + "'\n"
        "        content: '{{ {\"dp_ip\": dp_ip, \"dns\": create_dns_profiles, \"spc\": security_policy_config} | to_json }}'\n")
    try:
        env = {"ANSIBLE_CONFIG": str(staged.ansible_cfg), "PATH": __import__("os").environ["PATH"],
               "XL2YAML_RESULTS_FILE": str(staged.dir / "r.json")}
        p = subprocess.run(["ansible-playbook", "playbooks/zz_probe.yml"], cwd=staged.dir, env=env,
                           capture_output=True, text=True)
        assert p.returncode == 0, p.stdout + p.stderr
        got = yaml.safe_load(out.read_text())
        assert got["dp_ip"] == [LAB_IP] and got["dns"] == []
        assert got["spc"]["apply_policies_after_creation"] is False
        # the recorder callback also ran and scrubbed the password
        rec = (staged.dir / "r.json").read_text()
        assert "password" not in rec
    finally:
        cleanup(staged)


@pytest.mark.skipif(shutil.which("ansible-playbook") is None, reason="ansible not installed")
def test_real_syntax_check_of_create_full_config(repo, known_good):
    from xl2yaml.runner import run_playbook
    staged = stage(repo, "t5", "dp1", "S", {"create_vars.yml": dump(known_good)}, dummy=True)
    try:
        r = run_playbook(staged, "create_full_config.yml", repo.runs_dir / "t5", syntax_check=True)
        assert r.returncode == 0
    finally:
        cleanup(staged)
