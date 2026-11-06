"""Validate a create_vars.yml structure against what the modules actually accept.

Used for YAML mode (the existing vars/create_vars.yml), for PR checks on the
generated files, and inside preflight. Most modules map unknown values to a
default silently (``MAP.get(value, default)``) and BDoS/OOS ignore unknown
parameter keys, so unknown keys and values are errors here.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, Optional

from . import schema as S
from .mapper import TF_RULE_ORDER
from .report import Report

SHEET_FOR_SECTION = {
    "cl_protections": S.CL_PROTECTIONS,
    "oos_profiles": S.OOS_PROFILES,
    "bdos_profiles": S.BDOS_PROFILES,
    "create_tf_profiles": S.TF_PROFILES,
    "create_tf_protections": S.TF_RULES,
    "create_security_policies": S.POLICIES,
}
TF_EXTRA_KEYS = {"custom_protocol"}
TCP_FLAG_YAML_KEYS = tuple(k for _, k in S.TCP_FLAG_KEYS)


def _is_int(v) -> bool:
    return (isinstance(v, int) and not isinstance(v, bool)) or (isinstance(v, str) and v.isdigit())


def value_problem(fld: S.Field, v: Any) -> Optional[str]:
    k = fld.kind
    if k == "ref" and v == "" and fld.cls == S.OPTIONAL:
        return None   # empty binding = "do not bind" (create_full_config.py skips empty values)
    if k in ("name", "ref", "text"):
        return None if isinstance(v, str) and v != "" else f"expected a non-empty string, got {v!r}"
    if k == "enum":
        if not isinstance(v, str):
            return f"expected one of {list(fld.module_values)}, got {v!r}"
        ok = v in fld.module_values or (fld.case_insensitive and v.lower() in fld.module_values)
        return None if ok else (f"'{v}' is not accepted by the module {list(fld.module_values)} - "
                                "the module would silently substitute a default")
    if k in ("int", "numeric_string"):
        if not _is_int(v):
            return f"expected a whole number, got {v!r}"
        i = int(v)
        if fld.minimum is not None and i < fld.minimum or fld.maximum is not None and i > fld.maximum:
            return f"{i} is outside {fld.minimum}..{fld.maximum}"
        return None
    if k == "port_group":
        if isinstance(v, str) and (v == "" or v in S.PORT_GROUPS or (v.isdigit() and 1 <= int(v) <= 65535)):
            return None
        return f"app_port_group {v!r} is not '', {', '.join(S.PORT_GROUPS)} or a port number"
    if k in ("ip", "ipv4"):
        try:
            ip = ipaddress.ip_address(str(v))
        except ValueError:
            return f"'{v}' is not an IP address"
        return None if k == "ip" or ip.version == 4 else f"'{v}' must be IPv4"
    return None


def _check_item(item: Any, spec: S.SheetSpec, where: str, report: Report, src: str, extra_keys=frozenset()):
    if not isinstance(item, dict):
        report.error("YAML_BAD_ITEM", f"{where}: expected a mapping, got {type(item).__name__}", sheet=src)
        return
    params_fields = {f.key: f for f in spec.fields if f.in_params}
    top_fields = {f.key: f for f in spec.fields if f.key and not f.in_params and f.cls not in (S.KEY, S.INFO, S.CHECK)}
    if spec is S.TF_RULES:
        top_fields.pop("tcp_flags", None)
    allowed_top = set(top_fields) | set(extra_keys) | ({"params"} if params_fields else set())
    for key in item:
        if key not in allowed_top:
            report.error("YAML_UNKNOWN_KEY", f"{where}: unknown key '{key}' (not read by the module)", sheet=src, field=key)
    targets = [(item, top_fields, where)]
    if params_fields:
        params = item.get("params", {})
        if not isinstance(params, dict):
            report.error("YAML_BAD_ITEM", f"{where}.params: expected a mapping", sheet=src)
            params = {}
        for key in params:
            if key not in params_fields:
                report.error("YAML_UNKNOWN_KEY", f"{where}.params: unknown key '{key}' - the module silently ignores it",
                             sheet=src, field=key, safety=True)
        targets.append((params, params_fields, where + ".params"))
    for container, fields, w in targets:
        for key, fld in fields.items():
            if key not in container:
                if fld.cls == S.REQUIRED:
                    report.error("YAML_MISSING_REQUIRED", f"{w}: '{key}' is required", sheet=src, field=key)
                elif fld.cls == S.EXPLICIT:
                    report.error("YAML_MISSING_EXPLICIT", f"{w}: '{key}' must be set explicitly ({fld.source})",
                                 sheet=src, field=key, safety=True)
                continue
            problem = value_problem(fld, container[key])
            if problem:
                report.error("YAML_BAD_VALUE", f"{w}.{key}: {problem}", sheet=src, field=key,
                             safety=fld.kind == "enum")


def check_config(cfg: Any, report: Report, source: str = "create_vars.yml", for_run: bool = True,
                 allow_ipv6: bool = False) -> None:
    src = source
    if not isinstance(cfg, dict):
        report.error("YAML_NOT_MAPPING", "top level must be a mapping", sheet=src, safety=True)
        return
    for key in cfg:
        if key not in S.YAML_SECTION_ORDER:
            report.error("YAML_UNKNOWN_SECTION", f"unknown top-level key '{key}' - create_full_config.yml never reads it",
                         sheet=src, field=key)

    # dp_ip
    dp = cfg.get("dp_ip")
    if not isinstance(dp, list) or not dp:
        report.error("YAML_DP_IP", "dp_ip must be a non-empty list", sheet=src, safety=True)
    else:
        for ip in dp:
            p = value_problem(S.Field("dp_ip", "dp_ip", "ipv4", S.REQUIRED), ip)
            if p:
                report.error("YAML_DP_IP", f"dp_ip: {p}", sheet=src, safety=True)

    # security_policy_config: every toggle explicit
    spc = cfg.get("security_policy_config")
    if not isinstance(spc, dict):
        report.error("TOGGLE_NOT_EXPLICIT", "security_policy_config is missing", sheet=src, safety=True)
        spc = {}
    for t in S.TOGGLES:
        if t not in spc:
            msg = f"security_policy_config.{t} must be set explicitly"
            if t == "apply_policies_after_creation":
                msg += " (the playbook defaults it to true)"
            report.error("TOGGLE_NOT_EXPLICIT", msg, sheet=src, field=t, safety=True)
        elif not isinstance(spc[t], bool):
            report.error("TOGGLE_NOT_BOOL", f"security_policy_config.{t} must be true or false, got {spc[t]!r}",
                         sheet=src, field=t, safety=True)
    for t in spc:
        if t not in S.TOGGLES:
            report.error("YAML_UNKNOWN_KEY", f"security_policy_config: unknown toggle '{t}'", sheet=src, field=t)
    for t in S.UNSUPPORTED_TOGGLES:
        if spc.get(t) is True:
            report.error("UNSUPPORTED_SECTION", f"{t} = true is not supported by the POC runner", sheet=src, field=t,
                         safety=True)
    if for_run and spc.get("apply_policies_after_creation") is True:
        report.error("APPLY_IN_PHASE_A", "apply_policies_after_creation must be false - policies are applied only in the "
                     "separate, authorized Phase B run", sheet=src, field="apply_policies_after_creation", safety=True)

    for section, toggle in S.SECTION_TOGGLE.items():
        if spc.get(toggle) is True and not isinstance(cfg.get(section), list):
            report.error("YAML_SECTION_MISSING", f"{toggle} = true but '{section}' is missing or not a list", sheet=src,
                         field=section, safety=True)

    # network classes
    nc_names = set()
    for i, nc in enumerate(cfg.get("netclasses") or []):
        w = f"netclasses[{i}]"
        if not isinstance(nc, dict) or not isinstance(nc.get("name"), str):
            report.error("YAML_BAD_ITEM", f"{w}: needs a string 'name'", sheet=src)
            continue
        nc_names.add(nc["name"])
        for key in nc:
            if key not in ("name", "groups"):
                report.error("YAML_UNKNOWN_KEY", f"{w}: unknown key '{key}'", sheet=src, field=key)
        for j, g in enumerate(nc.get("groups") or []):
            gw = f"{w}.groups[{j}]"
            if not isinstance(g, dict) or set(g) - {"address", "mask"} or "address" not in g or "mask" not in g:
                report.error("YAML_BAD_ITEM", f"{gw}: needs exactly 'address' and 'mask'", sheet=src)
                continue
            try:
                ip = ipaddress.ip_address(str(g["address"]))
            except ValueError:
                report.error("YAML_BAD_VALUE", f"{gw}.address: '{g['address']}' is not an IP address", sheet=src)
                continue
            if ip.version == 6 and not allow_ipv6:
                report.error("IPV6_UNCONFIRMED", f"{gw}: IPv6 support is not confirmed (use --allow-ipv6)", sheet=src,
                             safety=True)

    # list sections driven by the schema
    for section, spec in SHEET_FOR_SECTION.items():
        extra = TF_EXTRA_KEYS | set(TCP_FLAG_YAML_KEYS) if section == "create_tf_protections" else frozenset()
        for i, item in enumerate(cfg.get(section) or []):
            _check_item(item, spec, f"{section}[{i}]", report, src, extra)
            if section == "create_tf_protections" and isinstance(item, dict):
                _check_tf_conditionals(item, f"{section}[{i}]", report, src)

    for i, prof in enumerate(cfg.get("cl_profiles") or []):
        w = f"cl_profiles[{i}]"
        if not isinstance(prof, dict) or not isinstance(prof.get("name"), str) or not isinstance(prof.get("protections"), list):
            report.error("YAML_BAD_ITEM", f"{w}: needs 'name' and a 'protections' list", sheet=src)

    _report_unverified_refs(cfg, nc_names, report, src)


def _check_tf_conditionals(item: Dict, where: str, report: Report, src: str):
    proto = str(item.get("protocol", "")).lower()
    if proto in ("tcp", "any"):
        for k in TCP_FLAG_YAML_KEYS:
            if k not in item:
                report.error("YAML_MISSING_EXPLICIT", f"{where}: '{k}' must be set when protocol is {proto} "
                             "(module default: enable)", sheet=src, field=k, safety=True)
            elif item[k] not in ("enable", "disable"):
                report.error("YAML_BAD_VALUE", f"{where}.{k}: must be enable or disable", sheet=src, field=k, safety=True)
    unit = item.get("threshold_unit")
    need = {"pps": "threshold_pps", "kbps": "threshold_kbps"}.get(unit)
    if need and need not in item:
        report.error("YAML_MISSING_EXPLICIT", f"{where}: '{need}' is required when threshold_unit = {unit}", sheet=src,
                     field=need, safety=True)


def _report_unverified_refs(cfg: Dict, nc_names, report: Report, src: str):
    defined = {
        "connection_limit_profile": {p.get("name") for p in cfg.get("cl_profiles") or [] if isinstance(p, dict)},
        "traffic_filters_profile": {p.get("profile_name") for p in cfg.get("create_tf_profiles") or [] if isinstance(p, dict)},
        "bdos_profile": {p.get("name") for p in cfg.get("bdos_profiles") or [] if isinstance(p, dict)},
        "out_of_state_profile": {p.get("name") for p in cfg.get("oos_profiles") or [] if isinstance(p, dict)},
    }
    seen = set()
    for pol in cfg.get("create_security_policies") or []:
        if not isinstance(pol, dict):
            continue
        for k in ("src_network", "dst_network"):
            n = pol.get(k)
            if isinstance(n, str) and n != "any" and n not in nc_names:
                seen.add(("network class", n))
        for k, v in pol.items():
            if k.endswith("_profile") and isinstance(v, str) and v.strip() and v not in defined.get(k, set()):
                seen.add((k, v))
    cl_defined = {p.get("name") for p in cfg.get("cl_protections") or [] if isinstance(p, dict)}
    for prof in cfg.get("cl_profiles") or []:
        for p in (prof.get("protections") or []) if isinstance(prof, dict) else []:
            if p not in cl_defined:
                seen.add(("cl protection", p))
    tf_defined = defined["traffic_filters_profile"]
    for prot in cfg.get("create_tf_protections") or []:
        if isinstance(prot, dict) and prot.get("profile_name") not in tf_defined:
            seen.add(("traffic filter profile", prot.get("profile_name")))
    for kind, name in sorted(seen, key=str):
        report.unverified("EXTERNAL_REF", f"{kind} '{name}' is not created by this file - must already exist on the device",
                          sheet=src)
