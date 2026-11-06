"""Result gates for Phase A (create) and Phase B (apply).

A run passes only if every expected module ran, every loop item succeeded, the
counts each module reports match what was generated, and no warning appeared
that is not on the reviewed benign list. create_network_class.py reports a
partial failure as warnings (not a failure), so warnings are failures here.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Pattern

import yaml

from .mapper import expected_counts
from .report import Report
from .runner import PlaybookRun

# module action -> (governing toggle, [(response path, expected-count key)])
PHASE_A_MODULES = {
    "create_network_class": ("create_network_classes", [("summary.successful_groups", "network_groups"),
                                                        ("summary.total_groups_attempted", "network_groups")]),
    "create_cl_configuration": ("create_cl_profiles", [("len:created_protections", "cl_protections"),
                                                       ("len:created_profiles", "cl_profile_links")]),
    "create_oos_profile": ("create_out_of_state_profiles", [("summary.successful_profiles", "oos_profiles")]),
    "create_bdos_profile": ("create_bdos_profiles", [("summary.successful_profiles", "bdos_profiles")]),
    "create_traffic_filter": ("create_traffic_filter_profiles", [("summary.successful_profiles", "tf_profiles"),
                                                                 ("summary.successful_protections", "tf_protections")]),
    "create_full_config": ("create_security_policies", [("summary.successful_policies", "policies")]),
}
# These must never run in Phase A.
PHASE_A_FORBIDDEN = ("create_dns_profile", "create_ssl_object", "create_https_profile", "update_policies")


def load_benign(path: Path) -> List[Pattern]:
    if not path.is_file():
        return []
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return [re.compile(p) for p in (raw.get("benign_warnings") or [])]


def _get(resp: Dict, path: str):
    if path.startswith("len:"):
        v = resp.get(path[4:])
        return len(v) if isinstance(v, list) else None
    cur = resp
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _warnings(res: Dict) -> List[str]:
    w = list(res.get("warnings") or [])
    resp = res.get("response")
    if isinstance(resp, dict) and resp.get("warnings"):
        rw = resp["warnings"]
        w += rw if isinstance(rw, list) else [str(rw)]
    return [str(x) for x in w]


def _check_warnings(rec: Dict, benign: Iterable[Pattern], report: Report, device: str, phase: str):
    for w in _warnings(rec["result"]):
        if any(p.search(w) for p in benign):
            report.info("BENIGN_WARNING", f"{rec['task']}: {w} (on reviewed benign list)", device=device)
        else:
            report.error("UNEXPECTED_WARNING", f"{phase}: {rec['task']}: {w}", device=device, safety=True)


def _common(run: PlaybookRun, benign, report: Report, device: str, phase: str):
    if run.returncode != 0:
        report.error("PLAYBOOK_RC", f"{phase}: ansible-playbook exited with {run.returncode}", device=device, safety=True)
    if not run.records:
        report.error("NO_RESULTS", f"{phase}: no structured results recorded - cannot verify the run", device=device, safety=True)
    for host, s in run.stats.items():
        if s.get("failures") or s.get("unreachable"):
            report.error("PLAYBOOK_FAILURES", f"{phase}: host {host} failures={s.get('failures')} "
                         f"unreachable={s.get('unreachable')}", device=device, safety=True)
    for rec in run.records:
        if rec["status"] in ("failed", "unreachable"):
            msg = rec["result"].get("msg") or ""
            ign = " (ignore_errors was set)" if rec.get("ignore_errors") else ""
            report.error("TASK_FAILED", f"{phase}: {rec['task']} {rec['status']}{ign}: {msg}", device=device, safety=True)
        _check_warnings(rec, benign, report, device, phase)
    for action in ("dp_lock", "dp_unlock"):
        items = run.items(action)
        if not items or any(i["status"] not in ("ok", "changed") for i in items):
            report.error("LOCK_STATE", f"{phase}: {action} did not complete for {device}", device=device, safety=True)


def gate_phase_a(run: PlaybookRun, cfg: Dict, benign, report: Report, device: str) -> bool:
    before = len(report.errors)
    _common(run, benign, report, device, "Phase A")
    expected = expected_counts(cfg)
    toggles = cfg.get("security_policy_config", {})
    ip = cfg["dp_ip"][0]
    for action, (toggle, checks) in PHASE_A_MODULES.items():
        items = [i for i in run.items(action) if i.get("item") == ip]
        ran = [i for i in items if i["status"] in ("ok", "changed")]
        if toggles.get(toggle):
            if not ran:
                report.error("MODULE_NOT_RUN", f"Phase A: {action} was expected to run ({toggle} = true) but did not",
                             device=device, safety=True)
                continue
            resp = ran[0]["result"].get("response") or {}
            errs = resp.get("errors") or []
            if errs:
                report.error("MODULE_ERRORS", f"Phase A: {action} reported errors: {errs}", device=device, safety=True)
            summary = resp.get("summary") or {}
            if summary.get("failed_groups"):
                report.error("PARTIAL_FAILURE", f"Phase A: {action} failed_groups={summary['failed_groups']}",
                             device=device, safety=True)
            for path, key in checks:
                got, want = _get(resp, path), expected[key]
                if want == 0 and got is None:
                    continue          # module exits early when its section is empty
                if got != want:
                    report.error("COUNT_MISMATCH", f"Phase A: {action} {path} = {got}, expected {want}",
                                 device=device, safety=True)
        elif ran:
            report.error("MODULE_RAN_WHEN_OFF", f"Phase A: {action} ran although {toggle} = false", device=device, safety=True)
    for action in PHASE_A_FORBIDDEN:
        if any(i["status"] != "skipped" for i in run.items(action)):
            report.error("FORBIDDEN_IN_PHASE_A", f"Phase A: {action} ran - this must never happen in Phase A",
                         device=device, safety=True)
    device_actions = set(PHASE_A_MODULES) | set(PHASE_A_FORBIDDEN) | {"dp_lock", "dp_unlock"}
    others = {i.get("item") for a in device_actions for i in run.items(a) if i.get("item") != ip}
    if others:
        report.error("UNEXPECTED_TARGET", f"Phase A: items for other targets {sorted(map(str, others))}",
                     device=device, safety=True)
    passed = len(report.errors) == before
    if passed:
        report.info("PHASE_A_PASS", "Phase A result gate passed", device=device)
    return passed


def gate_phase_b(run: PlaybookRun, ip: str, benign, report: Report, device: str) -> bool:
    before = len(report.errors)
    _common(run, benign, report, device, "Phase B")
    items = [i for i in run.items("update_policies") if i.get("item") == ip]
    ok = [i for i in items if i["status"] in ("ok", "changed")]
    if not ok:
        report.error("APPLY_NOT_CONFIRMED", "Phase B: update_policies did not complete", device=device, safety=True)
    else:
        status = (ok[0]["result"].get("response") or {}).get("status")
        if status != "success":
            report.error("APPLY_NOT_CONFIRMED", f"Phase B: update_policies status = {status!r}", device=device, safety=True)
    others = {str(i.get("item")) for a in ("dp_lock", "update_policies", "dp_unlock")
              for i in run.items(a) if i.get("item") != ip}
    if others:
        report.error("UNEXPECTED_TARGET", f"Phase B: items for other targets {sorted(others)}", device=device, safety=True)
    passed = len(report.errors) == before
    if passed:
        report.info("PHASE_B_PASS", "Phase B result gate passed", device=device)
    return passed
