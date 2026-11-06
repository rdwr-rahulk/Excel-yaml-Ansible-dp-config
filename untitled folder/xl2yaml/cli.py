"""Command-line interface: ``python -m xl2yaml <command>`` from the repository root."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__, logutil
from .convert import convert_workbook, load_yaml_input
from .input_select import EXCEL, InputError, select_input
from .manifest import new_run_id
from .paths import Repo
from .report import Report
from .runflow import RunArgs, run as run_flow
from .validator import Options
from .yaml_check import check_config
from .yamlio import load, semantic_diff


def _repo(args) -> Repo:
    return Repo.find(getattr(args, "repo", None))


# --------------------------------------------------------------------------- commands
def cmd_template(args) -> int:
    from .template import build_workbook, default_run_control
    build_workbook(args.output, {}, default_run_control(), None, "Blank template.")
    print(f"wrote {args.output}")
    return 0


def cmd_import(args) -> int:
    from .importer import import_export
    warnings = import_export(args.csv, args.device, args.output)
    for w in warnings:
        print(f"WARNING: {w}")
    print(f"wrote {args.output}  (fill in the blank orange columns, then run: python -m xl2yaml validate)")
    return 0


def _convert_selected(args, repo: Repo):
    sel = select_input(repo, args.input, args.workbook)
    if sel.mode != EXCEL:
        return sel, None
    res = convert_workbook(str(sel.source), sel.sha256, Options(allow_ipv6=args.allow_ipv6, devices=args.device or None))
    return sel, res


def cmd_validate(args) -> int:
    repo = _repo(args)
    logutil.setup()
    try:
        sel, res = _convert_selected(args, repo)
    except InputError as exc:
        print(f"[INPUT] {exc}")
        return 2
    if res is None:
        rep, _ = load_yaml_input(str(sel.source), args.allow_ipv6, args.yaml_report_only)
        print(rep.render([f"VALIDATION (YAML mode) {sel.source}"]))
        return 0 if rep.ok else 1
    print(res.report.render([f"VALIDATION (Excel mode) {sel.source}"]))
    return 0 if res.ok else 1


def cmd_convert(args) -> int:
    from .wizard import convert_to_vars
    rc, _ = convert_to_vars(_repo(args), args.input, args.workbook, args.allow_ipv6, args.device or None, args.out_dir)
    return rc


def cmd_wizard(args) -> int:
    from .wizard import Wizard, WizardOptions
    opts = WizardOptions(choice=args.choice, input_mode=args.input, workbook=args.workbook, devices=args.device or [],
                         env=args.env, allow_ipv6=args.allow_ipv6, confirm_targets=args.confirm_targets,
                         apply={"yes": True, "no": False}.get(args.apply), skip_syntax_check=args.skip_syntax_check)
    logutil.setup()
    try:
        return Wizard(_repo(args), opts).main()
    except (KeyboardInterrupt, EOFError):
        print("\nWizard cancelled.")
        return 130


def cmd_check_yaml(args) -> int:
    rc = 0
    for f in args.files:
        report = Report()
        try:
            cfg = load(f)
        except Exception as exc:  # noqa: BLE001
            print(f"{f}: cannot parse YAML: {exc}")
            rc = 1
            continue
        check_config(cfg, report, source=Path(f).name, for_run=not args.allow_apply, allow_ipv6=args.allow_ipv6)
        if args.report_only:
            report.downgrade_non_safety_errors()
        print(report.render([f"CHECK {f}"]))
        rc = rc or (0 if report.ok else 1)
    return rc


def cmd_compare(args) -> int:
    diffs = semantic_diff(load(args.left), load(args.right))
    if diffs:
        print("NOT semantically equivalent:")
        for d in diffs:
            print(f"  {d}")
        return 1
    print("semantically equivalent (same keys, values, types and order)")
    return 0


def cmd_ci(args) -> int:
    """PR checks: no device access. Validate committed YAML, re-convert the workbook, check determinism."""
    repo = _repo(args)
    logutil.setup()
    gen_dir = Path(args.generated_dir) if args.generated_dir else repo.generated_dir
    files = sorted(gen_dir.glob("create_vars_*.yml")) if gen_dir.is_dir() else []
    rc = 0
    for f in files:
        rep = Report()
        check_config(load(str(f)), rep, source=f.name, for_run=True, allow_ipv6=args.allow_ipv6)
        print(rep.render([f"CHECK {f.name}"]))
        rc = rc or (0 if rep.ok else 1)
    try:
        sel = select_input(repo, "auto", args.workbook)
    except InputError as exc:
        print(f"[INPUT] {exc}")
        return 2
    if sel.mode == EXCEL:
        a = convert_workbook(str(sel.source), sel.sha256, Options(allow_ipv6=args.allow_ipv6))
        b = convert_workbook(str(sel.source), sel.sha256, Options(allow_ipv6=args.allow_ipv6))
        if not a.ok:
            print(a.report.render(["CI: workbook does not convert"]))
            return 1
        for name, o in a.outputs.items():
            if o.text != b.outputs[name].text:
                print(f"CI FAIL: output for {name} is not deterministic")
                rc = 1
            committed = gen_dir / f"create_vars_{name}.yml"
            if not committed.is_file():
                print(f"CI FAIL: {committed} is not committed")
                rc = 1
                continue
            diffs = semantic_diff(load(str(committed)), o.config)
            if diffs:
                print(f"CI FAIL: {committed.name} does not match the workbook:")
                for d in diffs:
                    print(f"  {d}")
                rc = 1
            else:
                print(f"CI OK: {committed.name} matches the workbook and is deterministic")
    if args.syntax_check:
        rc = rc or _syntax_check(repo, files)
    print("CI RESULT:", "PASS" if rc == 0 else "FAIL")
    return rc


def _syntax_check(repo: Repo, files: List[Path]) -> int:
    from .runner import run_playbook
    from .staging import cleanup, stage
    rc = 0
    run_id = new_run_id()
    for f in files or []:
        staged = stage(repo, run_id, f.stem, "S", {"create_vars.yml": f.read_text(encoding="utf-8")}, dummy=True)
        try:
            r = run_playbook(staged, "create_full_config.yml", repo.runs_dir / run_id, syntax_check=True)
            print(f"syntax-check {f.name}: {'OK' if r.returncode == 0 else 'FAIL'}")
            rc = rc or (0 if r.returncode == 0 else 1)
        finally:
            cleanup(staged)
    return rc


def cmd_json_schema(args) -> int:
    from .jsonschema_export import write
    write(args.output)
    print(f"wrote {args.output}")
    return 0


def cmd_run(args) -> int:
    ra = RunArgs(env=args.env, device=args.device, input_mode=args.input, workbook=args.workbook, phase=args.phase.upper(),
                 after_run=args.after_run, preview=args.preview, confirm_targets=args.confirm_targets,
                 allow_ipv6=args.allow_ipv6, yaml_report_only=args.yaml_report_only, keep_staging=args.keep_staging,
                 authorize_apply=args.authorize_apply, change_ticket=args.change_ticket, authorized_by=args.authorized_by)
    return run_flow(ra, _repo(args))


# --------------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="xl2yaml", description="Optional Excel front-end and safe runner for create_full_config.yml")
    p.add_argument("--version", action="version", version=f"xl2yaml {__version__}")
    p.add_argument("--repo", help="repository root (default: auto-detect)")
    sub = p.add_subparsers(dest="command", required=True)

    def input_opts(sp):
        sp.add_argument("--input", default="auto", choices=("auto", "excel", "yaml"), help="force the input mode")
        sp.add_argument("--workbook", help="explicit workbook path (implies Excel mode)")
        sp.add_argument("--allow-ipv6", action="store_true", help="accept IPv6 network groups (confirm module support first)")

    s = sub.add_parser("template", help="write a blank workbook")
    s.add_argument("-o", "--output", required=True)
    s.set_defaults(func=cmd_template)

    s = sub.add_parser("import-export", help="pre-fill a workbook from the device export CSV")
    s.add_argument("csv")
    s.add_argument("--device", action="append", required=True, help="device name (repeatable)")
    s.add_argument("-o", "--output", required=True)
    s.set_defaults(func=cmd_import)

    s = sub.add_parser("validate", help="validate the selected input (no files written)")
    input_opts(s)
    s.add_argument("--device", action="append")
    s.add_argument("--yaml-report-only", action="store_true", help="YAML mode: non-safety findings become warnings")
    s.set_defaults(func=cmd_validate)

    s = sub.add_parser("convert", help="workbook -> generated/create_vars_<device>.yml")
    input_opts(s)
    s.add_argument("--device", action="append")
    s.add_argument("--out-dir")
    s.set_defaults(func=cmd_convert)

    s = sub.add_parser("check-yaml", help="check create_vars YAML files against the modules (PR check)")
    s.add_argument("files", nargs="+")
    s.add_argument("--allow-ipv6", action="store_true")
    s.add_argument("--allow-apply", action="store_true", help="do not flag apply_policies_after_creation: true")
    s.add_argument("--report-only", action="store_true", help="non-safety findings become warnings")
    s.set_defaults(func=cmd_check_yaml)

    s = sub.add_parser("compare", help="semantic equivalence of two YAML files")
    s.add_argument("left")
    s.add_argument("right")
    s.set_defaults(func=cmd_compare)

    s = sub.add_parser("ci", help="PR checks with no device access")
    s.add_argument("--generated-dir")
    s.add_argument("--workbook")
    s.add_argument("--allow-ipv6", action="store_true")
    s.add_argument("--syntax-check", action="store_true", help="also run ansible-playbook --syntax-check in staging")
    s.set_defaults(func=cmd_ci)

    s = sub.add_parser("json-schema", help="write a JSON Schema for editing create_vars.yml directly")
    s.add_argument("-o", "--output", required=True)
    s.set_defaults(func=cmd_json_schema)

    s = sub.add_parser("run", help="preflight + two-phase run on ONE device")
    input_opts(s)
    s.add_argument("--env", choices=("lab", "production"), help="environment (Excel mode: must match Run_Control)")
    s.add_argument("--device", help="device name (required unless exactly one device is included)")
    s.add_argument("--phase", default="A", choices=("A", "B", "AB", "a", "b", "ab"),
                   help="A = create with apply off; B = apply only; AB = both in one run")
    s.add_argument("--after-run", help="Phase B: run id of the passed Phase A")
    s.add_argument("--preview", action="store_true", help="Phase A with --check (planned operations only)")
    s.add_argument("--confirm-targets", help="non-interactive confirmation: the device name")
    s.add_argument("--keep-staging", action="store_true", help="keep the staging directory (debugging only)")
    s.add_argument("--yaml-report-only", action="store_true")
    s.add_argument("--authorize-apply", action="store_true", help="YAML mode: authorize Phase B")
    s.add_argument("--change-ticket", help="YAML mode: change ticket")
    s.add_argument("--authorized-by", help="YAML mode: approver")
    s.set_defaults(func=cmd_run)

    s = sub.add_parser("wizard", help="interactive menu: 1 convert, 2 dry run, 3 execute, 4 full run",
                       description="Orchestration wizard. 1 = convert Excel to vars only; 2 = dry run (read the YAML "
                                   "vars, check values and Ansible syntax); 3 = execute (push the YAML vars + summary); "
                                   "4 = full run (1, 2, 3).")
    input_opts(s)
    s.add_argument("--choice", choices=("1", "2", "3", "4"), help="skip the menu and run this option")
    s.add_argument("--device", action="append", help="limit to this device (repeatable)")
    s.add_argument("--env", choices=("lab", "production"), help="YAML mode: environment")
    s.add_argument("--confirm-targets", help="non-interactive confirmation: the device name")
    s.add_argument("--apply", choices=("ask", "yes", "no"), default="ask",
                   help="when Run_Control authorizes it: apply policies after a successful create (default: ask)")
    s.add_argument("--skip-syntax-check", action="store_true", help="dry run: skip ansible-playbook --syntax-check")
    s.set_defaults(func=cmd_wizard)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
