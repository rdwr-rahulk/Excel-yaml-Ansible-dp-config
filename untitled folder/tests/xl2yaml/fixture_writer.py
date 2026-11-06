"""TEST-ONLY: turn a create_vars.yml structure into workbook rows.

This is not a user feature (YAML -> Excel export is deferred to Phase 2). It
exists so the fidelity tests can prove that known-good YAML survives the
Excel path unchanged.
"""

from __future__ import annotations

from typing import Dict, List

from xl2yaml import schema as S
from xl2yaml.template import build_workbook

POLICY_REF_TYPE = {f.key: f.ref for f in S.POLICIES.fields if f.kind == "ref"}


def _label(fld: S.Field, value):
    if fld.kind == "enum":
        for label, v in fld.labels:
            if v == value:
                return label
        raise ValueError(f"no label for {fld.key}={value!r}")
    if fld.kind == "port_group":
        return S.ALL_PORTS_TOKEN if value == "" else value
    if fld.kind in ("int", "numeric_string"):
        return int(value)
    return value


def _row(spec: S.SheetSpec, device: str, values: Dict) -> Dict:
    row = {"DefensePro Name": device}
    for f in spec.fields:
        if f.key in values and f.cls not in (S.KEY, S.CHECK, S.INFO):
            row[f.header] = _label(f, values[f.key])
    return row


def rows_from_config(cfg: Dict, device: str = "dp1") -> Dict[str, List[Dict]]:
    ip = cfg["dp_ip"][0]
    rows: Dict[str, List[Dict]] = {s.name: [] for s in S.DATA_SHEETS}
    rows["Devices"] = [{"DefensePro Name": device, "DefensePro IP": ip, "Include in this run?": "Yes"}]
    ext = []
    for nc in cfg.get("netclasses", []):
        for i, g in enumerate(nc["groups"]):
            rows["Network_Classes"].append({"DefensePro Name": device, "Network Class": nc["name"], "Group Index": i,
                                            "Address": g["address"], "Mask": g["mask"]})
    for p in cfg.get("cl_protections", []):
        rows["CL_Protections"].append(_row(S.CL_PROTECTIONS, device, p))
    defined_cl = {p["name"] for p in cfg.get("cl_protections", [])}
    for prof in cfg.get("cl_profiles", []):
        for prot in prof["protections"]:
            rows["CL_Profile_Members"].append({"DefensePro Name": device, "Profile Name": prof["name"], "Protection Name": prot})
            if prot not in defined_cl:
                ext.append(("Connection Limit Protection", prot))
    for p in cfg.get("create_tf_profiles", []):
        rows["TF_Profiles"].append(_row(S.TF_PROFILES, device, p))
    for p in cfg.get("create_tf_protections", []):
        r = _row(S.TF_RULES, device, p)
        flags = [label for label, key in S.TCP_FLAG_KEYS if p.get(key) == "enable"]
        if all(k in p for _, k in S.TCP_FLAG_KEYS):
            r["TCP Flags"] = S.ALL_FLAGS_TOKEN if len(flags) == 6 else ",".join(flags)
        rows["TF_Rules"].append(r)
    for p in cfg.get("oos_profiles", []):
        rows["OOS_Profiles"].append(_row(S.OOS_PROFILES, device, {"name": p["name"], **p["params"]}))
    for p in cfg.get("bdos_profiles", []):
        rows["BDoS_Profiles"].append(_row(S.BDOS_PROFILES, device, {"name": p["name"], **p["params"]}))
    nc_names = {nc["name"] for nc in cfg.get("netclasses", [])}
    internal = {
        "Connection Limit Profile": {p["name"] for p in cfg.get("cl_profiles", [])},
        "Traffic Filter Profile": {p["profile_name"] for p in cfg.get("create_tf_profiles", [])},
        "BDoS Profile": {p["name"] for p in cfg.get("bdos_profiles", [])},
        "Out of State Profile": {p["name"] for p in cfg.get("oos_profiles", [])},
        "Network Class": nc_names | {"any"},
    }
    for pol in cfg.get("create_security_policies", []):
        rows["Policies"].append(_row(S.POLICIES, device, pol))
        for k, v in pol.items():
            t = POLICY_REF_TYPE.get(k)
            if t and v and v not in internal.get(t, set()):
                ext.append((t, v))
    for t, n in dict.fromkeys(ext):
        rows["External_References"].append({"DefensePro Name": device, "Type": t, "Name": n, "Reason": "test fixture"})
    return rows


def run_control_from_config(cfg: Dict, **overrides) -> Dict:
    spc = cfg["security_policy_config"]
    rc = {t: spc[t] for t in S.RUN_CONTROL_TOGGLES}
    rc[S.AUTHORIZE_APPLY] = False
    rc["environment"] = "lab"
    rc.update(overrides)
    return rc


def workbook_from_config(path: str, cfg: Dict, device: str = "dp1", **rc_overrides) -> None:
    build_workbook(path, rows_from_config(cfg, device), run_control_from_config(cfg, **rc_overrides), None, "test fixture")
