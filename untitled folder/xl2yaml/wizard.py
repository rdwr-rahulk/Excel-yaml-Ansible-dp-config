"""Interactive orchestration wizard: ``python -m xl2yaml wizard``.

    1  Convert Excel to vars only  workbook -> generated/create_vars_<device>.yml (no device access)
    2  Dry run only                read the YAML vars, check values and Ansible syntax (no device access)
    3  Execute                     push the YAML vars to the device(s) (safe run flow) + summary
    4  Full run                    1 -> 2 -> 3, stopping at the first failure

Every step reuses the existing building blocks (convert, check-yaml, run), so the safety
model is unchanged: preflight, allowlist, typed target confirmation, gate and read-back.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from . import logutil
from . import schema as S
from .convert import ConvertResult, convert_workbook, write_outputs
from .input_select import EXCEL, InputError, InputSelection, select_input
from .manifest import Manifest, command_line, new_run_id
from .paths import Repo
from .preflight import load_allowlist
from .report import Report
from .runflow import RunArgs, run as run_flow
from .validator import Options
from .yaml_check import check_config
from .yamlio import load, semantic_diff

CONVERT, DRY_RUN, EXECUTE, FULL = "1", "2", "3", "4"
MENU = (
    (CONVERT, "Convert Excel to vars only", "workbook -> generated/create_vars_<device>.yml (no device access)"),
    (DRY_RUN, "Dry run only", "read the YAML vars, check values and Ansible syntax (no device access)"),
    (EXECUTE, "Execute", "configure: push the YAML vars to the device(s), then show a summary"),
    (FULL, "Full run", "1 convert -> 2 dry run -> 3 execute, stopping at the first failure"),
)
CHOICES = {c for c, _, _ in MENU}

# section key -> human-readable name, in the order create_full_config.yml runs them
SECTION_NAMES = (
    ("netclasses", "Network classes"),
    ("cl_protections", "Connection-limit protections"),
    ("cl_profiles", "Connection-limit profiles"),
    ("oos_profiles", "Out-of-state profiles"),
    ("bdos_profiles", "BDoS profiles"),
    ("create_tf_profiles", "Traffic-filter profiles"),
    ("create_tf_protections", "Traffic-filter rules"),
    ("create_security_policies", "Security policies"),
)


@dataclass
class WizardOptions:
    choice: Optional[str] = None             # 1-4; None = show the menu
    input_mode: str = "auto"
    workbook: Optional[str] = None
    devices: List[str] = field(default_factory=list)
    env: Optional[str] = None                # YAML mode only (Excel mode reads Run_Control)
    allow_ipv6: bool = False
    confirm_targets: Optional[str] = None    # non-interactive target confirmation (CI)
    apply: Optional[bool] = None             # Phase B when authorized: None = ask, True/False = decided
    skip_syntax_check: bool = False


@dataclass
class VarsFile:
    device: Optional[str]
    path: Path


class Wizard:
    def __init__(self, repo: Repo, opts: WizardOptions, ask: Callable[[str], str] = input,
                 out: Callable[[str], None] = print):
        self.repo, self.o, self.ask, self.out = repo, opts, ask, out

    # ------------------------------------------------------------------ menu
    def main(self) -> int:
        choice = self.o.choice
        if choice is None:
            self._banner()
            choice = self._menu()
            if choice is None:
                self.out("Nothing done.")
                return 0
        return {CONVERT: self.convert, DRY_RUN: self.dry_run, EXECUTE: self.execute, FULL: self.full_run}[choice]()

    def _banner(self):
        self.out("=" * 72)
        self.out(" xl2yaml - DefensePro configuration wizard")
        self.out("=" * 72)
        try:
            sel = select_input(self.repo, self.o.input_mode, self.o.workbook)
            self.out(f" Input: {sel.mode} mode - {self._rel(sel.source)}")
        except InputError as exc:
            self.out(f" Input: {exc}")
        self.out("")

    def _menu(self) -> Optional[str]:
        for c, title, help_ in MENU:
            self.out(f"  {c}. {title:<28} {help_}")
        self.out("  q. Quit")
        while True:
            a = self.ask("\nChoose 1-4 (q to quit): ").strip().lower()
            if a in CHOICES:
                return a
            if a in ("q", "quit", "exit", ""):
                return None
            self.out(f"'{a}' is not a menu option.")

    def _step(self, n: str, title: str):
        self.out("")
        self.out(f"---- Step {n}: {title} " + "-" * max(0, 56 - len(title)))

    # ------------------------------------------------------------------ 1. convert
    def convert(self) -> int:
        self._step(CONVERT, "Convert Excel to vars")
        rc, _ = convert_to_vars(self.repo, self.o.input_mode, self.o.workbook, self.o.allow_ipv6,
                                self.o.devices or None, None, self.out)
        return rc

    # ------------------------------------------------------------------ 2. dry run
    def dry_run(self) -> int:
        self._step(DRY_RUN, "Dry run - read YAML vars and check syntax")
        try:
            sel = select_input(self.repo, self.o.input_mode, self.o.workbook)
        except InputError as exc:
            self.out(f"[INPUT] {exc}")
            return 2
        files, rc = self._vars_files(sel)
        if rc:
            return rc
        for vf in files:
            report = Report()
            try:
                cfg = load(str(vf.path))
            except Exception as exc:  # noqa: BLE001
                self.out(f"FAIL  {self._rel(vf.path)}: cannot read YAML: {exc}")
                rc = 1
                continue
            check_config(cfg, report, source=vf.path.name, for_run=True, allow_ipv6=self.o.allow_ipv6)
            self.out(report.render([f"VARS CHECK {self._rel(vf.path)}"]))
            rc = rc or (0 if report.ok else 1)
            if report.ok:
                self._print_contents(cfg)
        if rc:
            self.out("DRY RUN: FAIL - fix the findings above (nothing was sent to any device).")
            return rc
        rc = self._syntax_check([vf.path for vf in files])
        self.out(f"DRY RUN: {'PASS' if rc == 0 else 'FAIL'} (nothing was sent to any device).")
        return rc

    def _vars_files(self, sel: InputSelection) -> Tuple[List[VarsFile], int]:
        """The YAML vars to check / push: generated files (Excel mode) or vars/create_vars.yml (YAML mode)."""
        if sel.mode != EXCEL:
            self.out(f"[INPUT] YAML mode - using {self._rel(sel.source)}")
            return [VarsFile(None, Path(sel.source))], 0
        res = convert_workbook(str(sel.source), sel.sha256, self._options())
        if not res.ok:
            self.out(res.report.render([f"VALIDATION (Excel mode) {sel.source}"]))
            self.out("The workbook does not validate - run option 1 and fix the errors first.")
            return [], 1
        files, rc = [], 0
        for name, o in sorted(res.outputs.items()):
            p = self.repo.generated_dir / f"create_vars_{name}.yml"
            if not p.is_file():
                self.out(f"MISSING {self._rel(p)} - run option 1 (Convert) first.")
                rc = 1
                continue
            diffs = semantic_diff(load(str(p)), o.config)
            if diffs:
                self.out(f"STALE   {self._rel(p)} no longer matches the workbook - run option 1 (Convert) again:")
                for d in diffs[:10]:
                    self.out(f"          {d}")
                rc = 1
                continue
            self.out(f"OK      {self._rel(p)} matches the workbook")
            files.append(VarsFile(name, p))
        return files, rc

    def _syntax_check(self, files: List[Path]) -> int:
        if self.o.skip_syntax_check:
            self.out("ANSIBLE SYNTAX CHECK: skipped (--skip-syntax-check)")
            return 0
        if not shutil.which("ansible-playbook"):
            self.out("ANSIBLE SYNTAX CHECK: skipped - ansible-playbook is not on PATH "
                     "(the vars were still fully checked against the modules)")
            return 0
        from .cli import _syntax_check
        self.out("ANSIBLE SYNTAX CHECK: ansible-playbook --syntax-check create_full_config.yml "
                 "(isolated staging, placeholder connection files)")
        return _syntax_check(self.repo, files)

    def _print_contents(self, cfg: Dict):
        spc = cfg.get("security_policy_config") or {}
        dev = ", ".join(cfg.get("dp_ip") or []) or "-"
        self.out(f"  Will configure dp_ip {dev}:")
        for key, title in SECTION_NAMES:
            toggle = S.SECTION_TOGGLE.get(key)
            n = len(cfg.get(key) or [])
            state = f"{n} item(s)" if spc.get(toggle) else "skipped (Run_Control = No)"
            self.out(f"    {title:<30} {state}")
        apply = spc.get("apply_policies_after_creation")
        self.out(f"    {'Apply policies':<30} {'yes' if apply else 'no (separate authorized step)'}")

    # ------------------------------------------------------------------ 3. execute
    def execute(self) -> int:
        self._step(EXECUTE, "Execute - push YAML vars to the device")
        try:
            sel = select_input(self.repo, self.o.input_mode, self.o.workbook)
        except InputError as exc:
            self.out(f"[INPUT] {exc}")
            return 2
        targets, env, phase, rc = self._plan(sel)
        if rc:
            return rc
        self.out(f"Environment {env or '(from allowlist)'} - phase {'A+B (create, then apply)' if phase == 'AB' else 'A (create, apply off)'}")
        self.out("Each device is confirmed separately: type its name when asked.")
        results = []
        for dev in targets:
            before = set(self._run_ids())
            code = run_flow(RunArgs(env=env, device=dev, input_mode=self.o.input_mode, workbook=self.o.workbook,
                                    phase=phase, confirm_targets=self.o.confirm_targets,
                                    allow_ipv6=self.o.allow_ipv6), self.repo)
            new = sorted(set(self._run_ids()) - before)
            m = Manifest.load(self.repo.runs_dir / new[-1] / "run_manifest.json") if new else None
            results.append((dev, code, m))
            if code != 0:
                break
        self._summary(results, targets)
        return next((c for _, c, _ in results if c != 0), 0)

    def _plan(self, sel: InputSelection) -> Tuple[List[str], Optional[str], str, int]:
        if sel.mode == EXCEL:
            files, rc = self._vars_files(sel)
            if rc:
                self.out("Execute stopped: the YAML vars to push must exist and match the workbook.")
                return [], None, "A", rc
            res = convert_workbook(str(sel.source), sel.sha256, self._options())
            run_control = res.run_control
            env = run_control.get("environment")
            if self.o.env and self.o.env != env:
                self.out(f"--env {self.o.env} does not match Run_Control Environment {env}")
                return [], None, "A", 3
            targets = self._choose([vf.device for vf in files])
            phase = "A"
            if run_control.get(S.AUTHORIZE_APPLY):
                phase = "AB" if self._confirm_apply(run_control) else "A"
            else:
                self.out(f"Run_Control '{S.rc_label(S.AUTHORIZE_APPLY)}' = No: policies are created but not applied.")
            return targets, env, phase, 0 if targets else 1
        env = self.o.env or self._ask_choice("Environment", S.ENVIRONMENTS, "lab")
        al = self.repo.allowlist(env)
        if not al.is_file():
            self.out(f"{self._rel(al)} not found")
            return [], env, "A", 3
        cfg = load(str(sel.source)) or {}
        names = [n for ip, n in load_allowlist(al)["devices"].items() if ip in (cfg.get("dp_ip") or [])]
        if not names:
            self.out(f"No device in dp_ip of {self._rel(sel.source)} is on the {env} allowlist.")
            return [], env, "A", 3
        self.out("YAML mode: policies are created but not applied (use 'run --phase B' with a change ticket).")
        targets = self._choose(names)
        return targets, env, "A", 0 if targets else 1

    def _choose(self, devices: List[str]) -> List[str]:
        if self.o.devices:
            unknown = [d for d in self.o.devices if d not in devices]
            if unknown:
                self.out(f"Not available for this run: {', '.join(unknown)} (available: {', '.join(devices)})")
                return []
            return list(self.o.devices)
        if len(devices) <= 1:
            return devices
        self.out("Devices:")
        for i, d in enumerate(devices, start=1):
            self.out(f"  {i}. {d}")
        a = self.ask("Device number(s), comma separated, or 'all': ").strip().lower()
        if a == "all":
            return devices
        try:
            return [devices[int(x) - 1] for x in a.split(",") if x.strip()]
        except (ValueError, IndexError):
            self.out(f"'{a}' is not a valid selection.")
            return []

    def _confirm_apply(self, rc: Dict) -> bool:
        self.out(f"Run_Control authorizes policy apply: ticket {rc.get('change_ticket')}, "
                 f"approved by {rc.get('authorized_by')}.")
        if self.o.apply is not None:
            return self.o.apply
        a = self.ask("Apply the policies right after a successful create (Phase B)? [y/N]: ").strip().lower()
        return a in ("y", "yes")

    def _ask_choice(self, label: str, values, default: str) -> str:
        a = self.ask(f"{label} ({'/'.join(values)}) [{default}]: ").strip().lower() or default
        while a not in values:
            a = self.ask(f"{label} must be one of {', '.join(values)}: ").strip().lower()
        return a

    def _summary(self, results, targets: List[str]):
        self.out("")
        self.out("=" * 72)
        self.out(" EXECUTION SUMMARY")
        self.out("=" * 72)
        for dev, code, m in results:
            if m is None:
                self.out(f" {dev}: no run record (exit code {code})")
                continue
            d = (m.devices or [{}])[0]
            counts = _finding_counts(m)
            self.out(f" Device       {dev} ({d.get('ip', '?')})   environment {m.environment or '-'}")
            self.out(f" Run id       {m.run_id}")
            self.out(f" Input        {m.input.get('mode', '-')} {m.input.get('source', '')}")
            self.out(f" Preflight    {_res(m.preflight, 'A')}" + (f" / B {_res(m.preflight, 'B')}" if 'B' in m.preflight else ""))
            self.out(f" Create (A)   {_res(m.phases, 'A')}")
            self.out(f" Read-back    {m.readback.get('result', 'not run')}")
            self.out(f" Apply  (B)   {_res(m.phases, 'B')}")
            vars_file = self.repo.runs_dir / m.run_id / f"create_vars_{dev}.yml"
            if vars_file.is_file() and m.phases.get("A", {}).get("result") == "PASS":
                self._print_contents(load(str(vars_file)))
            self.out(f" Findings     {counts['error']} error(s), {counts['warning']} warning(s), "
                     f"{counts['unverified']} unverified reference(s)")
            self.out(f" RESULT       {m.result}")
            self.out(f" Details      {self._rel(self.repo.runs_dir / m.run_id)} (xl2yaml.log, report.txt, run_manifest.json)")
            self.out("-" * 72)
        not_run = targets[len(results):]
        if not_run:
            self.out(f" Not run (stopped after a failure): {', '.join(not_run)}")
        ok = results and all(c == 0 for _, c, _ in results) and not not_run
        self.out(f" OVERALL: {'PASS' if ok else 'FAIL'}")

    # ------------------------------------------------------------------ 4. full run
    def full_run(self) -> int:
        for n, step in ((CONVERT, self.convert), (DRY_RUN, self.dry_run), (EXECUTE, self.execute)):
            rc = step()
            if rc != 0:
                self.out(f"FULL RUN stopped at step {n} (exit code {rc}).")
                return rc
        self.out("FULL RUN: PASS")
        return 0

    # ------------------------------------------------------------------ helpers
    def _options(self) -> Options:
        return Options(allow_ipv6=self.o.allow_ipv6, devices=self.o.devices or None)

    def _run_ids(self) -> List[str]:
        d = self.repo.runs_dir
        return [p.parent.name for p in d.glob("*/run_manifest.json")] if d.is_dir() else []

    def _rel(self, p) -> str:
        try:
            return str(Path(p).resolve().relative_to(self.repo.root))
        except ValueError:
            return str(p)


def _res(d: Dict, k: str) -> str:
    return (d.get(k) or {}).get("result", "not run")


def _finding_counts(m: Manifest) -> Dict[str, int]:
    c = {"error": 0, "warning": 0, "unverified": 0}
    for f in m.validation.get("findings", []):
        sev = str(f.get("level", "")).lower()
        for k in c:
            if sev.startswith(k):
                c[k] += 1
    return c


def convert_to_vars(repo: Repo, input_mode: str, workbook: Optional[str], allow_ipv6: bool,
                    devices: Optional[List[str]], out_dir: Optional[str],
                    out: Callable[[str], None] = print) -> Tuple[int, Optional[ConvertResult]]:
    """Validate the workbook and write generated/create_vars_<device>.yml (shared by `convert` and the wizard)."""
    run_id = new_run_id()
    logutil.setup(repo.runs_dir / run_id / "xl2yaml.log")
    try:
        sel = select_input(repo, input_mode, workbook)
    except InputError as exc:
        out(f"[INPUT] {exc}")
        return 2, None
    if sel.mode != EXCEL:
        out("[INPUT] YAML mode - nothing to convert (vars/create_vars.yml is used as is). "
            "Use 'check-yaml' or the dry run to validate it.")
        return 0, None
    res = convert_workbook(str(sel.source), sel.sha256, Options(allow_ipv6=allow_ipv6, devices=devices))
    out(res.report.render([f"VALIDATION (Excel mode) {sel.source}"]))
    m = Manifest(run_id=run_id, command=command_line(), input=sel.as_dict())
    m.validation = {"result": "PASS" if res.ok else "FAIL", "findings": [f.as_dict() for f in res.report.findings]}
    if not res.ok:
        m.result = "FAILED_VALIDATION"
        m.save(repo.runs_dir)
        out("Nothing was written.")
        return 1, res
    target = Path(out_dir) if out_dir else repo.generated_dir
    for o in write_outputs(res, target):
        out(f"wrote {o.path}  sha256={o.sha256}")
        m.generated.append({"device": o.name, "ip": o.ip, "path": str(o.path), "sha256": o.sha256})
    m.toggles = res.run_control
    m.result = "GENERATED"
    out(f"manifest: {m.save(repo.runs_dir)}")
    return 0, res
