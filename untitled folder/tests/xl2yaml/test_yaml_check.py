"""YAML-mode checks against what the modules accept (silent defaults become errors)."""

import copy

import yaml

from conftest import ROOT
from xl2yaml.report import Report
from xl2yaml.yaml_check import check_config


def codes(cfg, **kw):
    r = Report()
    check_config(cfg, r, **kw)
    return r


def test_known_good_passes(known_good):
    r = codes(known_good)
    assert r.ok, r.render()


def test_repository_example_is_flagged():
    cfg = yaml.safe_load((ROOT / "vars" / "create_vars.yml.example").read_text())
    r = codes(cfg)
    got = set(r.codes("ERROR"))
    # DNS/HTTPS/SSL on, apply on, oos_profiles missing while OOS toggle on, minimal TF rule without explicit fields
    assert {"UNSUPPORTED_SECTION", "APPLY_IN_PHASE_A", "YAML_SECTION_MISSING", "YAML_MISSING_EXPLICIT"} <= got


def test_typo_in_cl_action_would_silently_become_drop(known_good):
    cfg = copy.deepcopy(known_good)
    cfg["cl_protections"][1]["action"] = "report-only"     # module: ACTION_MAP.get(x, '10') -> drop
    r = codes(cfg)
    assert any(f.code == "YAML_BAD_VALUE" and f.safety for f in r.errors)


def test_unknown_bdos_param_is_an_error(known_good):
    cfg = copy.deepcopy(known_good)
    cfg["bdos_profiles"][0]["params"]["inbound_trafic"] = 5    # module silently ignores unknown keys
    assert "YAML_UNKNOWN_KEY" in codes(cfg).codes("ERROR")


def test_missing_app_port_group_is_an_error(known_good):
    cfg = copy.deepcopy(known_good)
    del cfg["cl_protections"][0]["app_port_group"]             # module: '' = all ports
    assert "YAML_MISSING_EXPLICIT" in codes(cfg).codes("ERROR")


def test_missing_apply_toggle_is_an_error(known_good):
    cfg = copy.deepcopy(known_good)
    del cfg["security_policy_config"]["apply_policies_after_creation"]   # playbook default(true)
    assert "TOGGLE_NOT_EXPLICIT" in codes(cfg).codes("ERROR")


def test_tf_flags_required_for_tcp(known_good):
    cfg = copy.deepcopy(known_good)
    del cfg["create_tf_protections"][0]["tcp_ack"]
    assert "YAML_MISSING_EXPLICIT" in codes(cfg).codes("ERROR")


def test_report_only_keeps_safety_errors(known_good):
    cfg = copy.deepcopy(known_good)
    cfg["unknown_section"] = []                                  # non-safety
    del cfg["cl_protections"][0]["app_port_group"]              # safety
    r = codes(cfg)
    r.downgrade_non_safety_errors()
    assert r.codes("ERROR") == ["YAML_MISSING_EXPLICIT"]
    assert "YAML_UNKNOWN_SECTION" in r.codes("WARNING")


def test_unverified_refs_listed(known_good):
    r = codes(known_good)
    msgs = " ".join(f.message for f in r.of("UNVERIFIED"))
    assert "All-DoS-Shield" in msgs and "web_servers" in msgs and "some_existing_protection" in msgs
