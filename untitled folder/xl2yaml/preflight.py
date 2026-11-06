"""Preflight: confirm exactly what will be changed, and where, before Ansible starts.

``--limit`` cannot be used: create_full_config.yml runs against the ``cc`` host
and loops through ``dp_ip``, so limiting hosts does not limit DefensePro IPs.
Targeting is therefore enforced on the data:

  * one DefensePro IP per generated file and per run
  * the IP (and its name) must be on the allowlist of the chosen environment
  * a lab run may not contain an IP from the production allowlist (and vice versa)
  * vars/cc.yml must point to the controller of that environment
  * the staged vars file must be byte-identical to the generated/selected file
  * no other variable source (group_vars, host_vars, inventory vars) may exist
  * a human confirms the device name (or CI passes --confirm-targets)
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

import yaml

from . import logutil
from . import schema as S
from .paths import Repo
from .report import Report
from .staging import StagedRun
from .yaml_check import check_config
from .yamlio import load, sha256_file

ALLOWED_INVENTORY_VARS = {"ansible_host", "ansible_connection", "ansible_python_interpreter"}


@dataclass
class Target:
    name: str
    ip: str


@dataclass
class Authorization:
    authorize_apply: bool = False
    change_ticket: Optional[str] = None
    authorized_by: Optional[str] = None

    def complete(self) -> bool:
        return bool(self.change_ticket and self.authorized_by)


@dataclass
class PreflightResult:
    passed: bool
    checks: List[Dict[str, str]] = field(default_factory=list)


def load_allowlist(path: Path) -> Dict:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    devices = raw.get("devices") or []
    return {"environment": raw.get("environment"), "controller": str(raw.get("controller") or ""),
            "devices": {str(d.get("ip")): str(d.get("name")) for d in devices if isinstance(d, dict)}}


class _Checks:
    def __init__(self, report: Report, device: str):
        self.report, self.device, self.items = report, device, []

    def ok(self, name, detail=""):
        self.items.append({"check": name, "result": "PASS", "detail": detail})

    def fail(self, name, detail):
        self.items.append({"check": name, "result": "FAIL", "detail": detail})
        self.report.error("PREFLIGHT_" + name, detail, device=self.device, safety=True)


def run_preflight(repo: Repo, env: str, target: Target, phase: str, staged: StagedRun, vars_file: str,
                  expected_sha: str, report: Report, auth: Authorization,
                  phase_a_passed: Optional[bool] = None, confirm_targets: Optional[str] = None,
                  interactive: Optional[bool] = None, sections: Optional[List[str]] = None,
                  prompt: Callable[[str], str] = input) -> PreflightResult:
    log = logutil.get()
    c = _Checks(report, target.name)

    # --- environment allowlist ---------------------------------------------
    al_path = repo.allowlist(env)
    allow = None
    if env not in S.ENVIRONMENTS:
        c.fail("ENVIRONMENT", f"environment must be one of {S.ENVIRONMENTS}, got {env!r}")
    elif not al_path.is_file():
        c.fail("ALLOWLIST_MISSING", f"{al_path.relative_to(repo.root)} not found - no device may be targeted")
    else:
        allow = load_allowlist(al_path)
        if allow["environment"] != env:
            c.fail("ALLOWLIST_ENV", f"{al_path.name} declares environment {allow['environment']!r}, expected {env!r}")
        if allow["devices"].get(target.ip) == target.name:
            c.ok("ALLOWLISTED", f"{target.name} {target.ip} is on the {env} allowlist")
        elif target.ip in allow["devices"]:
            c.fail("ALLOWLIST_NAME", f"{target.ip} is allowlisted as {allow['devices'][target.ip]!r}, not {target.name!r}")
        else:
            c.fail("NOT_ALLOWLISTED", f"{target.name} {target.ip} is not on the {env} allowlist")
        other = "production" if env == "lab" else "lab"
        if repo.allowlist(other).is_file() and target.ip in load_allowlist(repo.allowlist(other))["devices"]:
            c.fail("CROSS_ENVIRONMENT", f"{target.ip} is on the {other} allowlist - not allowed in a {env} run")

    # --- controller -----------------------------------------------------------
    try:
        cc = (load(str(staged.vars_path("cc.yml"))) or {}).get("cc") or {}
        cc_ip = str(cc.get("cc_ip") or "")
    except Exception as exc:  # noqa: BLE001
        cc_ip = ""
        c.fail("CONTROLLER", f"cannot read staged vars/cc.yml: {exc}")
    if allow is not None:
        if cc_ip and cc_ip == allow["controller"]:
            c.ok("CONTROLLER", f"vars/cc.yml cc_ip {cc_ip} is the {env} controller")
        else:
            c.fail("CONTROLLER", f"vars/cc.yml cc_ip {cc_ip!r} is not the {env} controller {allow['controller']!r}")

    # --- inventory & variable sources ----------------------------------------
    _check_inventory(staged, c)
    stray = [p for p in staged.dir.rglob("*") if p.is_dir() and p.name in ("group_vars", "host_vars")]
    if stray:
        c.fail("EXTRA_VAR_SOURCES", f"variable directories present in staging: {[str(p) for p in stray]}")
    else:
        c.ok("EXTRA_VAR_SOURCES", "no group_vars/host_vars in staging")
    vars_dir = staged.dir / "vars"
    expected_vars = {"cc.yml", vars_file}
    extra_files = sorted(p.name for p in vars_dir.iterdir() if p.name not in expected_vars)
    if extra_files:
        c.fail("EXTRA_VAR_FILES", f"unexpected files in staged vars/: {extra_files}")

    # --- staged file is exactly the file that was reviewed --------------------
    staged_sha = sha256_file(str(staged.vars_path(vars_file)))
    if staged_sha == expected_sha:
        c.ok("STAGED_FILE_HASH", f"vars/{vars_file} sha256={staged_sha}")
    else:
        c.fail("STAGED_FILE_HASH", f"vars/{vars_file} sha256 {staged_sha} != expected {expected_sha}")

    staged_cfg = load(str(staged.vars_path(vars_file))) or {}
    if phase == "A":
        dp = staged_cfg.get("dp_ip")
        if dp == [target.ip]:
            c.ok("SINGLE_DEVICE", f"dp_ip = [{target.ip}]")
        else:
            c.fail("SINGLE_DEVICE", f"dp_ip must be exactly [{target.ip}], got {dp!r}")
        sub = Report()
        check_config(staged_cfg, sub, source=f"staged vars/{vars_file}", for_run=True, allow_ipv6=True)
        blocking = [f for f in sub.errors if f.safety]
        if blocking:
            for f in blocking:
                c.fail("STAGED_FILE_SAFETY", f.message)
        else:
            c.ok("STAGED_FILE_SAFETY", "toggles explicit, unsupported sections off, apply off")
    else:
        td = staged_cfg.get("target_devices")
        us = staged_cfg.get("update_settings") or {}
        if td == [target.ip]:
            c.ok("SINGLE_DEVICE", f"target_devices = [{target.ip}]")
        else:
            c.fail("SINGLE_DEVICE", f"target_devices must be exactly [{target.ip}], got {td!r}")
        if us.get("continue_on_error") is not False:
            c.fail("CONTINUE_ON_ERROR", "update_settings.continue_on_error must be false (the playbook defaults it to true)")
        if not auth.authorize_apply:
            c.fail("APPLY_NOT_AUTHORIZED", f"{S.rc_label(S.AUTHORIZE_APPLY)} is not Yes")
        if phase_a_passed is not True:
            c.fail("PHASE_A_NOT_PASSED", "Phase B requires a passed Phase A (gate and read-back) for the same file")
        else:
            c.ok("PHASE_A_PASSED", "Phase A gate and read-back passed")

    if env == "production" or phase == "B":
        if auth.complete():
            c.ok("AUTHORIZATION", f"change {auth.change_ticket} approved by {auth.authorized_by}")
        else:
            c.fail("AUTHORIZATION", "change ticket and approver are required for production runs and for Phase B")

    # --- summary + confirmation ----------------------------------------------
    log.info(f"PREFLIGHT  phase={phase} environment={env} controller={cc_ip or '?'} "
             f"change={auth.change_ticket or 'n/a'}")
    log.info(f"  target    {target.name}  {target.ip}")
    if sections is not None:
        log.info(f"  sections  {', '.join(sections) or '(none)'}")
    log.info(f"  apply     {'TRUE (Phase B)' if phase == 'B' else 'FALSE (Phase A)'}")
    log.info(f"  vars      {staged.vars_path(vars_file)} sha256={staged_sha}")
    for item in c.items:
        log.info(f"  [{item['result']}] {item['check']}: {item['detail']}")

    if report.ok:
        _confirm(c, target, phase, confirm_targets, interactive, prompt)
    passed = all(i["result"] == "PASS" for i in c.items) and report.ok
    log.info(f"PREFLIGHT RESULT: {'PASS' if passed else 'FAIL'}")
    return PreflightResult(passed, c.items)


def _check_inventory(staged: StagedRun, c: _Checks):
    inv = staged.dir / "inventory.ini"
    hosts = {}
    section = None
    for line in inv.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith(("#", ";")):
            continue
        if s.startswith("["):
            section = s.strip("[]")
            if ":vars" in section:
                c.fail("INVENTORY_VARS", f"inventory group variables [{section}] are not allowed")
            continue
        parts = s.split()
        host, kv = parts[0], parts[1:]
        hosts[host] = section
        bad = [p.split("=")[0] for p in kv if p.split("=")[0] not in ALLOWED_INVENTORY_VARS]
        if bad:
            c.fail("INVENTORY_VARS", f"inventory host '{host}' sets variables {bad}; only "
                   f"{sorted(ALLOWED_INVENTORY_VARS)} are allowed")
    if "cc" in hosts:
        c.ok("INVENTORY", "inventory defines host 'cc'")
    else:
        c.fail("INVENTORY", "inventory does not define host 'cc'")


def _confirm(c: _Checks, target: Target, phase: str, confirm_targets, interactive, prompt):
    if confirm_targets is not None:
        if confirm_targets == target.name:
            c.ok("CONFIRMATION", f"--confirm-targets {confirm_targets}")
        else:
            c.fail("CONFIRMATION", f"--confirm-targets {confirm_targets!r} does not match {target.name!r}")
        return
    if interactive is None:
        interactive = sys.stdin.isatty()
    if not interactive:
        c.fail("CONFIRMATION", "non-interactive run: pass --confirm-targets <device name>")
        return
    action = "APPLY POLICIES on" if phase == "B" else "create objects on"
    answer = prompt(f"Type the device name to {action} {target.name} ({target.ip}): ").strip()
    if answer == target.name:
        c.ok("CONFIRMATION", "operator typed the device name")
    else:
        c.fail("CONFIRMATION", f"typed {answer!r}, expected {target.name!r}")
