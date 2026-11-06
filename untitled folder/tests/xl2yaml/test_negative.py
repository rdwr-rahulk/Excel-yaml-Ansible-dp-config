"""Acceptance tests 3, 4 and 5: precise cell-level errors; nothing passes silently.

Each case starts from the known-good workbook, breaks exactly one thing, and
asserts the expected rule fires at the expected location.
"""

import datetime

import pytest
from openpyxl import load_workbook

from fixture_writer import workbook_from_config
from xl2yaml import schema as S
from xl2yaml.convert import convert_workbook
from xl2yaml.validator import Options
from xl2yaml.yamlio import sha256_file


R0 = S.FIRST_DATA_ROW   # first data row; old tests were written for row 2


def col(sheet, header):
    return S.SHEETS[sheet].headers.index(header) + 1


def at(sheet, header, row):
    from openpyxl.utils import get_column_letter
    return f"{sheet}!{get_column_letter(col(sheet, header))}{row}"


def setc(sheet, header, row, value):
    def f(wb):
        wb[sheet].cell(row=row, column=col(sheet, header)).value = value   # cell(value=None) would be a no-op
    return f


def rc(key, value):
    label = S.rc_label(key)
    value = {True: S.YES, False: S.NO}.get(value, value) if isinstance(value, bool) else value

    def f(wb):
        ws = wb["Run_Control"]
        for r in range(1, ws.max_row + 1):
            if ws.cell(row=r, column=1).value == label:
                ws.cell(row=r, column=2).value = value
    return f


def find_row(sheet, header, value):
    def f(wb):
        ws = wb[sheet]
        c = col(sheet, header)
        for r in range(S.FIRST_DATA_ROW, ws.max_row + 1):
            if ws.cell(row=r, column=c).value == value:
                return r
        raise AssertionError(value)
    return f


def _formula(wb):
    wb["CL_Protections"].cell(row=R0, column=col("CL_Protections", "Threshold"), value="=50*2")


def _date(wb):
    c = wb["CL_Protections"].cell(row=R0, column=col("CL_Protections", "Threshold"), value=datetime.datetime(2026, 1, 10))
    c.number_format = "yyyy-mm-dd"


def _merge(wb):
    wb["Policies"].merge_cells(f"B{R0}:C{R0}")


def _hide_row(wb):
    wb["Policies"].row_dimensions[R0].hidden = True


def _extra_sheet(wb):
    wb.create_sheet("My_Notes")


def _extra_col(wb):
    wb["TF_Profiles"].cell(row=S.HEADER_ROW, column=4, value="Comment")


def _version(wb):
    wb["_Meta"]["B1"] = "0.2"


def _outside(wb):
    wb["TF_Profiles"].cell(row=R0, column=6, value="stray")


def _ext_conflict(wb):
    ws = wb["External_References"]
    r = ws.max_row + 1
    for h, v in (("DefensePro Name", "dp1"), ("Type", "BDoS Profile"), ("Name", "BDOS_Profile_50")):
        ws.cell(row=r, column=col("External_References", h), value=v)


def _remove_ext(name):
    def f(wb):
        ws = wb["External_References"]
        for r in range(ws.max_row, S.HEADER_ROW, -1):
            if ws.cell(row=r, column=col("External_References", "Name")).value == name:
                ws.delete_rows(r)
    return f


def _ipv6(wb):
    setc("Network_Classes", "Address", 3, "2001:db8::")(wb)
    setc("Network_Classes", "Mask", 3, "64")(wb)


def _unknown_device(wb):
    setc("TF_Profiles", "DefensePro Name", 3, "dp9")(wb)


def _group_gap(wb):
    setc("Network_Classes", "Group Index", 4, 5)(wb)


def _group_dup(wb):
    setc("Network_Classes", "Group Index", 4, 0)(wb)


def _dup_policy(wb):
    setc("Policies", "Policy Name", 4, "example_security_policy_1")(wb)


def _bdos_user_defined(wb):
    setc("BDoS_Profiles", "User Defined Rate Limit", 3, None)(wb)


CASES = [
    # (id, mutation, expected code, expected location prefix)
    ("blank App Port Group", setc("CL_Protections", "App Port Group", 3, None), "BLANK_EXPLICIT", at("CL_Protections", "App Port Group", 3)),
    ("blank CL action", setc("CL_Protections", "Action", 3, None), "BLANK_EXPLICIT", at("CL_Protections", "Action", 3)),
    ("blank policy direction", setc("Policies", "Direction", 3, None), "BLANK_EXPLICIT", "Policies!E3"),
    ("blank TF profile action", setc("TF_Profiles", "Action", 3, None), "BLANK_EXPLICIT", "TF_Profiles!C3"),
    ("blank BDoS outbound", setc("BDoS_Profiles", "Outbound Traffic (kbps)", 3, None), "BLANK_EXPLICIT", at("BDoS_Profiles", "Outbound Traffic (kbps)", 3)),
    ("formula in input cell", _formula, "FORMULA", at("CL_Protections", "Threshold", 3)),
    ("date-typed cell", _date, "DATE_CELL", at("CL_Protections", "Threshold", 3)),
    ("trailing space", setc("Policies", "Policy Name", 3, "example_security_policy_1 "), "WHITESPACE", "Policies!B3"),
    ("non-breaking space", setc("Network_Classes", "Network Class", 3, "egor\xa0test"), "WHITESPACE", "Network_Classes!B3"),
    ("wrong letter case", setc("Policies", "Policy State", 3, "enabled"), "BAD_ENUM", "Policies!C3"),
    ("pasted unknown value", setc("CL_Protections", "Action", 3, "Block"), "BAD_ENUM", at("CL_Protections", "Action", 3)),
    ("decimal in whole number", setc("CL_Protections", "Threshold", 3, 100.5), "BAD_NUMBER", at("CL_Protections", "Threshold", 3)),
    ("percentage stored as fraction", setc("BDoS_Profiles", "TCP In Quota %", 3, 0.8), "BAD_NUMBER", at("BDoS_Profiles", "TCP In Quota %", 3)),
    ("out of range quota", setc("BDoS_Profiles", "TCP In Quota %", 3, 180), "OUT_OF_RANGE", at("BDoS_Profiles", "TCP In Quota %", 3)),
    ("bad port group", setc("CL_Protections", "App Port Group", 3, "smtp"), "BAD_PORT_GROUP", at("CL_Protections", "App Port Group", 3)),
    ("bad mask", setc("Network_Classes", "Mask", 3, "255.0.255.0"), "BAD_MASK", "Network_Classes!E3"),
    ("group index gap", _group_gap, "GROUP_INDEX_GAP", "Network_Classes"),
    ("duplicate group index", _group_dup, "DUPLICATE_KEY", "Network_Classes"),
    ("duplicate policy", _dup_policy, "DUPLICATE_KEY", "Policies"),
    ("undeclared reference", _remove_ext("All-DoS-Shield"), "UNRESOLVED_REF", "Policies!J3"),
    ("toggle off but referenced", rc("create_bdos_profiles", False), "REF_TOGGLE_OFF", "Policies!Q3"),
    ("unsupported toggle on", rc("create_dns_profiles", True), "UNSUPPORTED_SECTION", "Run_Control"),
    ("blank toggle", rc("create_cl_profiles", None), "TOGGLE_NOT_EXPLICIT", "Run_Control"),
    ("non-boolean toggle", rc("create_cl_profiles", "TRUE"), "TOGGLE_NOT_BOOL", "Run_Control"),
    ("apply authorized without ticket", rc("authorize_policy_apply", True), "AUTHORIZATION_MISSING", "Run_Control"),
    ("production without ticket", rc("environment", "production"), "AUTHORIZATION_MISSING", "Run_Control"),
    ("bad environment", rc("environment", "staging"), "BAD_ENVIRONMENT", "Run_Control"),
    ("TCP flags blank for TCP", setc("TF_Rules", "TCP Flags", 3, None), "BLANK_EXPLICIT", at("TF_Rules", "TCP Flags", 3)),
    ("TCP flags set for UDP", setc("TF_Rules", "TCP Flags", 5, "(all flags)"), "TCP_FLAGS_NOT_APPLICABLE", at("TF_Rules", "TCP Flags", 5)),
    ("bad TCP flag token", setc("TF_Rules", "TCP Flags", 3, "SYN,URG"), "BAD_TCP_FLAGS", at("TF_Rules", "TCP Flags", 3)),
    ("PPS unit without PPS", setc("TF_Rules", "Threshold (PPS)", 3, None), "BLANK_EXPLICIT", at("TF_Rules", "Threshold (PPS)", 3)),
    ("BDoS user defined without rate", _bdos_user_defined, "BLANK_REQUIRED", "BDoS_Profiles"),
    ("declared external and created", _ext_conflict, "EXT_CONFLICT", "Policies"),
    ("IPv6 not confirmed", _ipv6, "IPV6_UNCONFIRMED", "Network_Classes!D3"),
    ("row for unknown device", _unknown_device, "UNKNOWN_DEVICE", "TF_Profiles"),
    ("unknown sheet", _extra_sheet, "UNKNOWN_SHEET", "My_Notes"),
    ("extra column", _extra_col, "HEADER_MISMATCH", "TF_Profiles!A2"),
    ("value outside template", _outside, "OUTSIDE_TEMPLATE", "TF_Profiles!F3"),
    ("old template version", _version, "TEMPLATE_VERSION", "_Meta!B1"),
    ("merged cells", _merge, "MERGED_CELLS", "Policies!B3"),
    ("hidden row with data", _hide_row, "HIDDEN_ROW", "Policies!A3"),
]


@pytest.mark.parametrize("name,mutate,code,where", CASES, ids=[c[0] for c in CASES])
def test_bad_input_is_rejected_at_the_cell(tmp_path, known_good, name, mutate, code, where):
    p = tmp_path / "wb.xlsx"
    workbook_from_config(str(p), known_good)
    wb = load_workbook(p)
    mutate(wb)
    wb.save(p)
    res = convert_workbook(str(p), sha256_file(str(p)))
    assert not res.ok, f"{name}: expected failure"
    hits = [f for f in res.report.errors if f.code == code]
    assert hits, f"{name}: expected {code}, got {[(f.code, f.location, f.message) for f in res.report.errors]}"
    assert any(f.location.startswith(where) for f in hits), \
        f"{name}: {code} not at {where}: {[f.location for f in hits]}"
    assert not res.outputs, "nothing may be generated when there are errors"


def test_at_least_25_negative_cases():
    assert len(CASES) >= 25


def test_ipv6_allowed_with_flag(tmp_path, known_good):
    p = tmp_path / "wb.xlsx"
    workbook_from_config(str(p), known_good)
    wb = load_workbook(p)
    _ipv6(wb)
    wb.save(p)
    res = convert_workbook(str(p), sha256_file(str(p)), Options(allow_ipv6=True))
    assert res.ok, res.report.render()


def test_declared_external_refs_are_reported_unverified(tmp_path, known_good):
    p = tmp_path / "wb.xlsx"
    workbook_from_config(str(p), known_good)
    res = convert_workbook(str(p), sha256_file(str(p)))
    unverified = [f.message for f in res.report.of("UNVERIFIED")]
    assert any("All-DoS-Shield" in m for m in unverified)
    assert any("some_existing_protection" in m for m in unverified)
    assert any("web_servers" in m for m in unverified)
