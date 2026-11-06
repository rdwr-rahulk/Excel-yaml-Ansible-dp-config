"""Import the existing device export ("Policy list with source, destination and Profile attached" CSV).

The export packs lists into multi-line cells (blocks separated by ``------``).
The importer splits them into one row per item. Fields the export does not
contain (priority, direction, App Port Group, TCP flags, TF status/match,
BDoS outbound traffic) are left blank on purpose: they are explicit fields and
must be filled in by an engineer before the workbook converts.
"""

from __future__ import annotations

import csv
import re
from collections import OrderedDict
from typing import Dict, List, Optional, Tuple

from . import schema as S
from .template import build_workbook, default_run_control


def _blocks(v: str) -> List[Dict[str, str]]:
    out = []
    for b in (v or "").split("------"):
        d = OrderedDict()
        for line in b.strip().splitlines():
            if ":" in line:
                k, val = line.split(":", 1)
                d[k.strip()] = val.strip()
        if d:
            out.append(d)
    return out


def _num(v) -> Optional[int]:
    v = (v or "").strip()
    return int(v) if re.fullmatch(r"\d+", v) else None


def _s(v) -> Optional[str]:
    v = (v or "").strip()
    return v or None


def _split_cidr(entry: str) -> Tuple[str, str]:
    if "/" in entry:
        a, m = entry.split("/", 1)
        return a.strip(), m.strip()
    return entry.strip(), ("128" if ":" in entry else "32")


def import_export(csv_path: str, devices: List[str], out_path: str) -> List[str]:
    """Write a workbook for ``devices`` from the export. Returns importer warnings."""
    with open(csv_path, encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.DictReader(fh))
    warnings: List[str] = []
    all_devices = OrderedDict()
    for r in rows:
        all_devices.setdefault(r["DefensePro Name"], r["DefensePro IP"])
    unknown = [d for d in devices if d not in all_devices]
    if unknown:
        raise ValueError(f"devices not in the export: {unknown}")

    data: Dict[str, List[Dict]] = {s.name: [] for s in S.DATA_SHEETS}
    data["Devices"] = [{"DefensePro Name": n, "DefensePro IP": ip, "Include in this run?": "Yes" if n in devices else "No"}
                       for n, ip in all_devices.items()]
    dns_hdr = [h for h in rows[0].keys() if h.startswith("DNS ")]
    ref = {"DNS_Profiles": (["DefensePro Name"] + dns_hdr, []),
           "SYN_Profiles": (["DefensePro Name", "Profile Name", "Action", "Network Authentication Method", "HTTP Authentication"], []),
           "SYN_Protections": (["DefensePro Name", "Profile Name", "Protection Name", "Protection ID", "Application Port Group",
                                "Activation Threshold", "Termination Threshold"], [])}

    for dev in devices:
        drows = [r for r in rows if r["DefensePro Name"] == dev]
        seen = {k: {} for k in ("nc", "cl", "clm", "tf", "oos", "bdos", "ext", "dns", "syn")}

        def once(kind, key, payload, what):
            """Add ``key`` once; warn if the export repeats it with different settings."""
            prev = seen[kind].get(key)
            if prev is None:
                seen[kind][key] = payload
                return True
            if prev != payload:
                warnings.append(f"{dev}: {what} '{key}' appears with different settings in the export - first kept")
            return False

        for r in drows:
            pol = {"DefensePro Name": dev, "Policy Name": _s(r["Policy Name"]), "Policy State": _s(r["Policy State"]),
                   "Priority": None, "Direction": None, "Policy Block/Report": _s(r["Policy Block/Report"]),
                   "Policy Packet Reporting": _s(r["Policy Packet Reporting"]),
                   "SRC Network": _s(r["SRC Network Profile Name"]), "DST Network": _s(r["DST Network Profile Name"]),
                   "Signature Profile": _s(r["Signature Profile Name"]),
                   "Out of State Profile": _s(r["Out of State Profile Name"]), "EAAF Profile": _s(r["EAAF Profile Name"]),
                   "Geolocation Profile": _s(r["Geolocaation Profile"]),
                   "Connection Limit Profile": _s(r["Connection Limit Profile Name"]),
                   "SYN Flood Profile": _s(r["SYN Flood Protection Profile"]),
                   "Traffic Filter Profile": _s(r["Traffic Filter Profile Name"]), "BDoS Profile": _s(r["BDOS Profile Name"]),
                   "DNS Profile": _s(r["DNS Profile Name"]), "HTTPS Flood Profile": None}
            data["Policies"].append(pol)

            for name_col, addr_col in (("SRC Network Profile Name", "SRC Network Addresses"),
                                       ("DST Network Profile Name", "DST Network Addresses")):
                name = _s(r[name_col])
                if not name or name == "any":
                    continue
                addrs = [a.strip() for a in (r[addr_col] or "").splitlines() if a.strip()]
                if once("nc", name, tuple(addrs), "network class"):
                    for i, a in enumerate(addrs):
                        addr, mask = _split_cidr(a)
                        data["Network_Classes"].append({"DefensePro Name": dev, "Network Class": name, "Group Index": i,
                                                        "Address": addr, "Mask": mask})

            prof = _s(r["Connection Limit Profile Name"])
            if prof:
                for b in _blocks(r["Connection Limit Profile Protections and settings"]):
                    pname = b.get("Protection Name")
                    settings = {k: v for k, v in b.items() if k != "Protection ID"}
                    if once("cl", pname, tuple(sorted(settings.items())), "connection-limit protection"):
                        data["CL_Protections"].append({
                            "DefensePro Name": dev, "Protection Name": pname, "Protection ID": _num(b.get("Protection ID")),
                            "Protection Type": b.get("Protection Type"), "Protocol": b.get("Protocol"), "App Port Group": None,
                            "Threshold": _num(b.get("Threshold")), "Tracking Type": b.get("Tracking Type"),
                            "Action": b.get("Action"), "Packet Reporting": b.get("Packet Reporting")})
                    if once("clm", (prof, pname), True, "profile member"):
                        data["CL_Profile_Members"].append({"DefensePro Name": dev, "Profile Name": prof, "Protection Name": pname})

            tf = _s(r["Traffic Filter Profile Name"])
            if tf:
                rules = _blocks(r["Traffic Filter Rules"])
                payload = (r["Traffic Filter Block/Report"], tuple(tuple(sorted((k, v) for k, v in b.items() if k != "Protection ID")) for b in rules))
                if once("tf", tf, payload, "traffic-filter profile"):
                    data["TF_Profiles"].append({"DefensePro Name": dev, "Profile Name": tf, "Action": _s(r["Traffic Filter Block/Report"])})
                    for b in rules:
                        pps, kbps = _num(b.get("Threhold(PPS)")), _num(b.get("Threhold(Kbps)"))
                        data["TF_Rules"].append({
                            "DefensePro Name": dev, "Profile Name": tf, "Rule Name": b.get("Rule Name"),
                            "Protection ID": _num(b.get("Protection ID")), "Status": None, "Match Criteria": None,
                            "Protocol": b.get("Protocol"), "TCP Flags": None,
                            "Threshold Unit": "Kbps" if kbps is not None and pps is None else ("PPS" if pps is not None else None),
                            "Threshold (PPS)": pps, "Threshold (Kbps)": kbps, "Tracking Mode": b.get("Tracking Mode"),
                            "Packet Reporting": b.get("Packet Reporting")})

            oos = _s(r["Out of State Profile Name"])
            if oos:
                payload = tuple(r[k] for k in ("Out of State Block/Report", "Out of State Activation Threshold",
                                               "Out of State Termination Threshold", "Out of State Enable SYN-ACK"))
                if once("oos", oos, payload, "out-of-state profile"):
                    data["OOS_Profiles"].append({"DefensePro Name": dev, "Profile Name": oos,
                                                 "Action": _s(r["Out of State Block/Report"]),
                                                 "Activation Threshold": _num(r["Out of State Activation Threshold"]),
                                                 "Termination Threshold": _num(r["Out of State Termination Threshold"]),
                                                 "SYN-ACK Allow": _s(r["Out of State Enable SYN-ACK"])})

            bd = _s(r["BDOS Profile Name"])
            if bd:
                cols = [h for h in r if h.startswith("BDOS ") and h != "BDOS Profile Name"]
                if once("bdos", bd, tuple(r[h] for h in cols), "BDoS profile"):
                    data["BDoS_Profiles"].append({
                        "DefensePro Name": dev, "Profile Name": bd, "Action": _s(r["BDOS Profile Block/Report"]),
                        "Inbound Traffic (kbps)": _num(r["BDOS Profile Bandwidth"]), "Outbound Traffic (kbps)": None,
                        "TCP In Quota %": _num(r["BDOS TCP Quota"]), "UDP In Quota %": _num(r["BDOS UDP Quota"]),
                        "ICMP In Quota %": _num(r["BDOS ICMP Quota"]),
                        "Transparent Optimization": _s(r["BDOS Transparent Optimization"]),
                        "Packet Reporting": _s(r["BDOS Packet Reporting"]),
                        "Learning Suppression": _num(r["BDOS Learning Suppression"]),
                        "Footprint Strictness": _s(r["BDOS Footprint Strictness"]),
                        "UDP Packet Rate Sensitivity": _s(r["BDOS UDP Packet Rate Detection Sensitivity"]),
                        "Burst-Attack Protection": _s(r["BDOS Burst-Attack Protection"])})

            for typ, col in (("Signature Profile", "Signature Profile Name"), ("EAAF Profile", "EAAF Profile Name"),
                             ("Geolocation Profile", "Geolocaation Profile"), ("SYN Flood Profile", "SYN Flood Protection Profile"),
                             ("DNS Profile", "DNS Profile Name")):
                n = _s(r[col])
                if n and once("ext", (typ, n), True, "external reference"):
                    data["External_References"].append({"DefensePro Name": dev, "Type": typ, "Name": n,
                                                        "Reason": "imported: exists on the device per export; not created by the POC"})

            dns = _s(r["DNS Profile Name"])
            if dns and once("dns", dns, True, "DNS profile"):
                ref["DNS_Profiles"][1].append([dev] + [r[h] for h in dns_hdr])
            syn = _s(r["SYN Flood Protection Profile"])
            if syn and once("syn", syn, True, "SYN profile"):
                ref["SYN_Profiles"][1].append([dev, syn, r["SYN Flood Profile Action"], r["SYN Flood Network Authentication Method"],
                                               r["SYN Flood HTTP Authentication"]])
                for b in _blocks(r["SYN Flood Protection Settings"]):
                    ref["SYN_Protections"][1].append([dev, syn, b.get("Protection Name"), _num(b.get("Protection ID")),
                                                      b.get("Application Port Group"), _num(b.get("Activation Threshold")),
                                                      _num(b.get("Termination Threshold"))])

    note = (f"Imported from {csv_path.split('/')[-1]} for {', '.join(devices)}. Fields not in the export are blank "
            "and must be filled in: Priority, Direction, App Port Group, TCP Flags, TF Status / Match Criteria, "
            "BDoS Outbound Traffic.")
    build_workbook(out_path, data, default_run_control(), ref, note)
    return warnings
