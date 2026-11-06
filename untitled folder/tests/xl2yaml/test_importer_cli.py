"""Importer (device export CSV -> workbook) and CLI smoke tests. Synthetic data only."""

import csv
import json

import yaml
from openpyxl import load_workbook

from conftest import LAB_IP
from xl2yaml import schema as S
from xl2yaml.cli import main
from xl2yaml.convert import convert_workbook
from xl2yaml.importer import import_export
from xl2yaml.yamlio import sha256_file

HEADERS = ['DefensePro Name', 'DefensePro IP', 'DefensePro Version', 'Policy Name', 'Policy State', 'Policy Block/Report',
           'Policy Packet Reporting', 'SRC Network Profile Name', 'SRC Network Addresses', 'DST Network Profile Name',
           'DST Network Addresses', 'Signature Profile Name', 'Out of State Profile Name', 'Out of State Block/Report',
           'Out of State Activation Threshold', 'Out of State Termination Threshold', 'Out of State Enable SYN-ACK',
           'Anti-Scanning Profile Name', 'EAAF Profile Name', 'Geolocaation Profile', 'Connection Limit Profile Name',
           'Connection Limit Profile Protections and settings', 'SYN Flood Protection Profile', 'SYN Flood Profile Action',
           'SYN Flood Network Authentication Method', 'SYN Flood HTTP Authentication', 'SYN Flood Protection Settings',
           'Traffic Filter Profile Name', 'Traffic Filter Block/Report', 'Traffic Filter Rules', 'BDOS Profile Name',
           'BDOS Profile Block/Report', 'BDOS Profile Bandwidth', 'BDOS TCP Quota', 'BDOS UDP Quota', 'BDOS ICMP Quota',
           'BDOS Transparent Optimization', 'BDOS Packet Reporting', 'BDOS Learning Suppression', 'BDOS Footprint Strictness',
           'BDOS UDP Packet Rate Detection Sensitivity', 'BDOS Burst-Attack Protection', 'DNS Profile Name']


def _export(path):
    row = {h: "" for h in HEADERS}
    row.update({
        "DefensePro Name": "dp1", "DefensePro IP": LAB_IP, "DefensePro Version": "8.34.2.0", "Policy Name": "POL-A",
        "Policy State": "Enabled", "Policy Block/Report": "Report", "Policy Packet Reporting": "Enabled",
        "SRC Network Profile Name": "any", "SRC Network Addresses": "any IPv4/IPv6",
        "DST Network Profile Name": "NET-A", "DST Network Addresses": "192.0.2.0/24\n198.51.100.0/23\n",
        "Signature Profile Name": "DoS-All", "Out of State Profile Name": "OOS-A", "Out of State Block/Report": "Block and Report",
        "Out of State Activation Threshold": "5000", "Out of State Termination Threshold": "2000",
        "Out of State Enable SYN-ACK": "Enabled", "Connection Limit Profile Name": "CL-A",
        "Connection Limit Profile Protections and settings":
            "Protection Name: TCP_A\nProtection ID: 450005\nProtection Type: Connections per Second\nProtocol: TCP\n"
            "Threshold: 1500\nTracking Type: Source Count\nAction: Drop\nPacket Reporting: Enabled\n------\n",
        "Traffic Filter Profile Name": "TF-A", "Traffic Filter Block/Report": "Block and Report",
        "Traffic Filter Rules": "Rule Name: R1\nProtection ID: 700064\nProtocol: TCP\nThrehold(PPS): 6000000\n"
                                "Tracking Mode: All\nPacket Reporting: Enabled\n------\n"
                                "Rule Name: R2\nProtection ID: 700065\nProtocol: UDP\nThrehold(Kbps): 2000\n"
                                "Tracking Mode: Per Destination\nPacket Reporting: Enabled\n------\n",
        "BDOS Profile Name": "BD-A", "BDOS Profile Block/Report": "Block and Report", "BDOS Profile Bandwidth": "350000",
        "BDOS TCP Quota": "90", "BDOS UDP Quota": "50", "BDOS ICMP Quota": "20", "BDOS Transparent Optimization": "Disabled",
        "BDOS Packet Reporting": "Enabled", "BDOS Learning Suppression": "50", "BDOS Footprint Strictness": "Medium",
        "BDOS UDP Packet Rate Detection Sensitivity": "Medium", "BDOS Burst-Attack Protection": "Disabled"})
    other = dict(row, **{"DefensePro Name": "dp2", "DefensePro IP": "10.105.192.33"})
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=HEADERS)
        w.writeheader()
        w.writerow(row)
        w.writerow(other)


def _fill(ws, header, value, sheet):
    c = S.SHEETS[sheet].headers.index(header) + 1
    for r in range(S.FIRST_DATA_ROW, ws.max_row + 1):
        if ws.cell(row=r, column=1).value == "dp1":
            ws.cell(row=r, column=c).value = value


def test_import_then_fill_explicit_fields_then_convert(tmp_path):
    csv_path, wb_path = tmp_path / "export.csv", tmp_path / "wb.xlsx"
    _export(csv_path)
    import_export(str(csv_path), ["dp1"], str(wb_path))
    res = convert_workbook(str(wb_path), sha256_file(str(wb_path)))
    blank = {(f.sheet, f.field) for f in res.report.errors if f.code in ("BLANK_EXPLICIT", "BLANK_REQUIRED")}
    assert ("CL_Protections", "app_port_group") in blank            # not in the export -> must be chosen
    assert ("Policies", "direction") in blank and ("Policies", "priority") in blank
    assert ("BDoS_Profiles", "outbound_traffic") in blank
    wb = load_workbook(wb_path)
    _fill(wb["Policies"], "Priority", 100, "Policies")
    _fill(wb["Policies"], "Direction", "One Way", "Policies")
    _fill(wb["CL_Protections"], "App Port Group", "https", "CL_Protections")
    _fill(wb["BDoS_Profiles"], "Outbound Traffic (kbps)", 350000, "BDoS_Profiles")
    ws = wb["TF_Rules"]
    _fill(ws, "Status", "Enabled", "TF_Rules")
    _fill(ws, "Match Criteria", "Match", "TF_Rules")
    ws.cell(row=S.FIRST_DATA_ROW, column=S.TF_RULES.headers.index("TCP Flags") + 1).value = "(all flags)"
    wb.save(wb_path)
    res = convert_workbook(str(wb_path), sha256_file(str(wb_path)))
    assert res.ok, res.report.render()
    cfg = res.outputs["dp1"].config
    assert cfg["dp_ip"] == [LAB_IP]
    assert cfg["netclasses"] == [{"name": "NET-A", "groups": [{"address": "192.0.2.0", "mask": "24"},
                                                               {"address": "198.51.100.0", "mask": "23"}]}]
    assert cfg["cl_protections"][0] == {"name": "TCP_A", "protection_type": "cps", "protocol": "tcp", "threshold": "1500",
                                        "app_port_group": "https", "tracking_type": "src_ip", "action": "drop",
                                        "packet_report": "enable", "index": 450005}
    rules = cfg["create_tf_protections"]
    assert rules[0]["threshold_unit"] == "pps" and rules[0]["tcp_syn"] == "enable"
    assert rules[1]["threshold_unit"] == "kbps" and "tcp_syn" not in rules[1]
    assert cfg["oos_profiles"][0] == {"name": "OOS-A", "params": {"action": "block_and_report", "act_threshold": 5000,
                                                                   "term_threshold": 2000, "syn_ack_allow": "enable"}}
    assert cfg["create_security_policies"][0]["action"] == "report_only"
    assert any("TF_Rules" == f.sheet for f in res.report.of("WARNING"))          # Protection ID is not converted


def test_cli_template_json_schema_check_compare(tmp_path, known_good, capsys):
    assert main(["template", "-o", str(tmp_path / "blank.xlsx")]) == 0
    assert set(S.SHEET_ORDER) - {"DNS_Profiles", "SYN_Profiles", "SYN_Protections"} <= set(load_workbook(tmp_path / "blank.xlsx").sheetnames)
    assert main(["json-schema", "-o", str(tmp_path / "s.json")]) == 0
    assert "security_policy_config" in json.loads((tmp_path / "s.json").read_text())["properties"]
    good = tmp_path / "good.yml"
    good.write_text(yaml.safe_dump(known_good))
    assert main(["check-yaml", str(good)]) == 0
    other = tmp_path / "other.yml"
    changed = json.loads(json.dumps(known_good))
    changed["cl_protections"][0]["threshold"] = 100                       # int instead of "100"
    other.write_text(yaml.safe_dump(changed))
    assert main(["compare", str(good), str(other)]) == 1
    assert "type str != int" in capsys.readouterr().out


def test_cli_convert_and_ci(repo, known_good, monkeypatch, capsys):
    from fixture_writer import workbook_from_config
    repo.input_dir.mkdir()
    workbook_from_config(str(repo.default_workbook), known_good)
    monkeypatch.chdir(repo.root)
    assert main(["convert"]) == 0
    gen = repo.generated_dir / "create_vars_dp1.yml"
    assert gen.is_file()
    assert main(["ci"]) == 0
    gen.write_text(gen.read_text().replace('"700"', '"701"'))            # hand edit drifts from the workbook
    assert main(["ci"]) == 1
    assert "does not match the workbook" in capsys.readouterr().out
