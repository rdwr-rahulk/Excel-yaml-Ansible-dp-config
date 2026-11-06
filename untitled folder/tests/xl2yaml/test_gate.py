"""Acceptance test 11 (unit level): partial failures and warnings fail the gate."""

import copy
import re

from conftest import LAB_IP
from xl2yaml.gate import gate_phase_a, gate_phase_b
from xl2yaml.mapper import expected_counts
from xl2yaml.report import Report
from xl2yaml.runner import PlaybookRun


def item(action, status="changed", result=None, ip=LAB_IP):
    r = dict(result or {})
    return {"status": status, "item_level": True, "task": action, "action": action, "host": "cc", "item": ip,
            "ignore_errors": False, "result": r}


def good_run(cfg):
    e = expected_counts(cfg)
    recs = [item("dp_lock", "ok"),
            item("create_network_class", result={"response": {"errors": [], "summary": {
                "total_groups_attempted": e["network_groups"], "successful_groups": e["network_groups"], "failed_groups": 0}}}),
            item("create_cl_configuration", result={"response": {"created_protections": [{}] * e["cl_protections"],
                                                                  "created_profiles": [{}] * e["cl_profile_links"]}}),
            item("create_oos_profile", result={"response": {"errors": [], "summary": {"successful_profiles": e["oos_profiles"]}}}),
            item("create_bdos_profile", result={"response": {"errors": [], "summary": {"successful_profiles": e["bdos_profiles"]}}}),
            item("create_dns_profile", "skipped"), item("create_ssl_object", "skipped"), item("create_https_profile", "skipped"),
            item("create_traffic_filter", result={"response": {"errors": [], "summary": {
                "successful_profiles": e["tf_profiles"], "successful_protections": e["tf_protections"]}}}),
            item("create_full_config", result={"response": {"errors": [], "summary": {"successful_policies": e["policies"]}}}),
            item("update_policies", "skipped"),
            item("dp_unlock", "ok")]
    return PlaybookRun("create_full_config.yml", 0, recs, {"cc": {"failures": 0, "unreachable": 0}})


def test_good_run_passes(known_good):
    rep = Report()
    assert gate_phase_a(good_run(known_good), known_good, [], rep, "dp1"), rep.render()


def _mutate(run, action, fn):
    for r in run.records:
        if r["action"] == action:
            fn(r)
    return run


def test_network_class_warning_fails(known_good):
    def partial(r):
        r["result"]["warnings"] = ["Failed to create network group 'egor_test_net[3]'"]
        s = r["result"]["response"]["summary"]
        s["successful_groups"] -= 1
        s["failed_groups"] = 1
    rep = Report()
    assert not gate_phase_a(_mutate(good_run(known_good), "create_network_class", partial), known_good, [], rep, "dp1")
    assert {"UNEXPECTED_WARNING", "PARTIAL_FAILURE", "COUNT_MISMATCH"} <= set(rep.codes("ERROR"))


def test_benign_warning_is_allowed_only_if_listed(known_good):
    run = _mutate(good_run(known_good), "create_bdos_profile", lambda r: r["result"].__setitem__("warnings", ["known noise"]))
    assert not gate_phase_a(copy.deepcopy(run), known_good, [], Report(), "dp1")
    assert gate_phase_a(run, known_good, [re.compile("known noise")], Report(), "dp1")


def test_failed_module_fails(known_good):
    run = _mutate(good_run(known_good), "create_bdos_profile", lambda r: r.update(status="failed"))
    run.stats["cc"]["failures"] = 1
    rep = Report()
    assert not gate_phase_a(run, known_good, [], rep, "dp1")
    assert "TASK_FAILED" in rep.codes("ERROR")


def test_apply_in_phase_a_fails(known_good):
    run = _mutate(good_run(known_good), "update_policies", lambda r: r.update(status="changed"))
    rep = Report()
    assert not gate_phase_a(run, known_good, [], rep, "dp1")
    assert "FORBIDDEN_IN_PHASE_A" in rep.codes("ERROR")


def test_module_skipped_when_expected_fails(known_good):
    run = _mutate(good_run(known_good), "create_oos_profile", lambda r: r.update(status="skipped"))
    rep = Report()
    assert not gate_phase_a(run, known_good, [], rep, "dp1")
    assert "MODULE_NOT_RUN" in rep.codes("ERROR")


def test_other_target_fails(known_good):
    run = good_run(known_good)
    run.records.append(item("create_full_config", ip="10.9.9.9", result={"response": {"summary": {}}}))
    rep = Report()
    assert not gate_phase_a(run, known_good, [], rep, "dp1")
    assert "UNEXPECTED_TARGET" in rep.codes("ERROR")


def test_unlock_failure_fails(known_good):
    run = _mutate(good_run(known_good), "dp_unlock", lambda r: r.update(status="failed"))
    rep = Report()
    assert not gate_phase_a(run, known_good, [], rep, "dp1")
    assert "LOCK_STATE" in rep.codes("ERROR")


def test_no_results_fails(known_good):
    rep = Report()
    assert not gate_phase_a(PlaybookRun("x", 0), known_good, [], rep, "dp1")
    assert "NO_RESULTS" in rep.codes("ERROR")


def _phase_b(status="success", warnings=None):
    resp = {"status": status}
    if warnings:
        resp["warnings"] = warnings
    return PlaybookRun("update_policies.yml", 0, [item("dp_lock", "ok"), item("update_policies", result={"response": resp}),
                                                  item("dp_unlock", "ok")], {"cc": {"failures": 0}})


def test_phase_b_success():
    assert gate_phase_b(_phase_b(), LAB_IP, [], Report(), "dp1")


def test_phase_b_unclear_confirmation_fails():
    rep = Report()
    assert not gate_phase_b(_phase_b(warnings=["API response does not provide clear success confirmation"]), LAB_IP, [], rep, "dp1")
    assert "UNEXPECTED_WARNING" in rep.codes("ERROR")


def test_phase_b_wrong_status_fails():
    rep = Report()
    assert not gate_phase_b(_phase_b(status="failed"), LAB_IP, [], rep, "dp1")
