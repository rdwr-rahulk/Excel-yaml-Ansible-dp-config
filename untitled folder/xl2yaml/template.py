"""Build the workbook (blank template or pre-filled) from the schema.

The template is generated, never hand-maintained, so headers, dropdowns and the
reader can never drift apart.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from openpyxl import Workbook
from openpyxl.comments import Comment
from openpyxl.formatting.rule import FormulaRule
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter as L
from openpyxl.worksheet.datavalidation import DataValidation

from . import __version__
from . import schema as S

FONT = "Arial"
COLORS = {S.KEY: "003087", S.REQUIRED: "003087", S.EXPLICIT: "C55A11", S.OPTIONAL: "4A6FA5", S.INFO: "7F7F7F",
          S.CHECK: "2E7D32"}
CLASS_TEXT = {
    S.REQUIRED: "REQUIRED - blank is an error.",
    S.EXPLICIT: "EXPLICIT - must be chosen; if omitted the module would apply a default that can widen protection "
                "or change enforcement. Blank is an error.",
    S.OPTIONAL: "OPTIONAL - blank leaves the key out; the module/device default applies (listed in the report).",
    S.INFO: "INFO - copied from the device export; not converted (no module parameter).",
    S.KEY: "Device this row belongs to.",
    S.CHECK: "Automatic check - formula, do not edit. Ignored by the converter.",
}
_thin = Side(style="thin", color="C9D3E0")
BOX = Border(top=_thin, bottom=_thin, left=_thin, right=_thin)
HDR_FONT = Font(name=FONT, bold=True, color="FFFFFF", size=10)
BODY = Font(name=FONT, size=10)
RED = PatternFill("solid", fgColor="F4B6B6")
ROWS_WITH_RULES = 1000
HDR, FIRST = S.HEADER_ROW, S.FIRST_DATA_ROW
DESC_FILL = "EAF1FB"


def _fill(hex_):
    return PatternFill("solid", fgColor=hex_)


def _describe(ws, text: str, ncols: int, height: float = 75):
    """Row 1: what the sheet is for and how to fill it (merged across the sheet's columns)."""
    c = ws.cell(row=S.DESCRIPTION_ROW, column=1, value=text)
    c.font = Font(name=FONT, size=10, italic=True, color="1F3864")
    c.fill = _fill(DESC_FILL)
    c.alignment = Alignment(wrap_text=True, vertical="top", horizontal="left")
    ncols = max(ncols, 6)
    ws.merge_cells(start_row=S.DESCRIPTION_ROW, start_column=1, end_row=S.DESCRIPTION_ROW, end_column=ncols)
    ws.row_dimensions[S.DESCRIPTION_ROW].height = height


class _Lists:
    def __init__(self, wb):
        self.ws = wb.create_sheet("_Lists")
        self.col = 0
        self.refs: Dict[Tuple, str] = {}

    def ref(self, values: Sequence[str]) -> str:
        key = tuple(values)
        if key not in self.refs:
            self.col += 1
            for i, v in enumerate(values, start=1):
                self.ws.cell(row=i, column=self.col, value=v)
            c = L(self.col)
            self.refs[key] = f"_Lists!${c}$1:${c}${len(values)}"
        return self.refs[key]


def _dropdown(ws, col: int, ref: str, warn=False, msg="Pick a value from the list."):
    dv = DataValidation(type="list", formula1=ref, allow_blank=True, showErrorMessage=True,
                        errorStyle="warning" if warn else "stop", errorTitle="Check value", error=msg)
    ws.add_data_validation(dv)
    dv.add(f"{L(col)}{FIRST}:{L(col)}{ROWS_WITH_RULES}")


def _whole(ws, col: int, lo, hi):
    dv = DataValidation(type="whole", operator="between", formula1=str(lo if lo is not None else -2147483648),
                        formula2=str(hi if hi is not None else 2147483647), allow_blank=True, showErrorMessage=True,
                        errorTitle="Out of range", error=f"Whole number {lo}..{hi}")
    ws.add_data_validation(dv)
    dv.add(f"{L(col)}{FIRST}:{L(col)}{ROWS_WITH_RULES}")


def _data_sheet(wb, spec: S.SheetSpec, rows: List[Dict], lists: _Lists):
    ws = wb.create_sheet(spec.name)
    ws.sheet_properties.tabColor = spec.tab
    _describe(ws, spec.description, len(spec.fields))
    for i, f in enumerate(spec.fields, start=1):
        c = ws.cell(row=HDR, column=i, value=f.header)
        c.font, c.border = HDR_FONT, BOX
        c.fill = _fill(COLORS[f.cls])
        c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        text = CLASS_TEXT[f.cls] + (f"\n{f.note}" if f.note else "") + (f"\nSource: {f.source}" if f.source else "")
        c.comment = Comment(text, "xl2yaml")
        c.comment.width, c.comment.height = 320, 160
        ws.column_dimensions[L(i)].width = max(f.width, min(len(f.header) + 2, 30))
        if f.kind == "enum":
            _dropdown(ws, i, lists.ref([l for l, _ in f.labels]))
        elif f.kind == "yesno":
            _dropdown(ws, i, lists.ref(["Yes", "No"]))
        elif f.kind == "port_group":
            _dropdown(ws, i, lists.ref([S.ALL_PORTS_TOKEN, *S.PORT_GROUPS]), warn=True,
                      msg="Not in the list. Port numbers are allowed - the converter checks the value.")
        elif f.kind == "tcp_flags":
            _dropdown(ws, i, lists.ref([S.ALL_FLAGS_TOKEN, "SYN", "ACK", "RST", "SYN-ACK", "FIN-ACK", "PSH-ACK"]),
                      warn=True, msg="A comma list like SYN,ACK is allowed - the converter checks the value.")
        elif f.kind in ("int", "numeric_string"):
            _whole(ws, i, f.minimum, f.maximum)
    ws.row_dimensions[HDR].height = 42
    ws.freeze_panes = f"C{FIRST}" if len(spec.fields) > 6 else f"B{FIRST}"
    for r_i, row in enumerate(rows, start=FIRST):
        for c_i, f in enumerate(spec.fields, start=1):
            if f.cls == S.CHECK:
                continue
            v = row.get(f.header)
            cell = ws.cell(row=r_i, column=c_i, value=v)
            cell.font, cell.border = BODY, BOX
            cell.alignment = Alignment(vertical="top", wrap_text=False)
            if isinstance(v, str) and v.isdigit() and f.kind in ("name", "ref", "text", "ip"):
                cell.number_format = "@"
    # highlight blank required/explicit cells on rows that have data
    anchor = L(2)
    for c_i, f in enumerate(spec.fields, start=1):
        if f.cls in (S.REQUIRED, S.EXPLICIT) and f.kind != "tcp_flags" and c_i > 1:
            col = L(c_i)
            ws.conditional_formatting.add(f"{col}{FIRST}:{col}{ROWS_WITH_RULES}",
                                          FormulaRule(formula=[f'AND(${anchor}{FIRST}<>"",{col}{FIRST}="")'], fill=RED))
    ws.auto_filter.ref = f"A{HDR}:{L(len(spec.fields))}{max(len(rows) + HDR, FIRST)}"
    return ws


def _reference_check(ws, n_rows: int):
    """Excel-side convenience check on Policies (the converter does the real check)."""
    fields = list(S.POLICIES.fields)
    col = {f.key: L(i) for i, f in enumerate(fields, start=1) if f.key}
    check_col = len(fields)
    ext = "External_References"
    internal = {"Network Class": ("Network_Classes", "B"), "Out of State Profile": ("OOS_Profiles", "B"),
                "Connection Limit Profile": ("CL_Profile_Members", "B"), "Traffic Filter Profile": ("TF_Profiles", "B"),
                "BDoS Profile": ("BDoS_Profiles", "B")}
    for r in range(FIRST, max(n_rows + FIRST, 200)):
        parts = []
        for f in fields:
            if f.kind != "ref":
                continue
            c = f"{col[f.key]}{r}"
            ext_cnt = f'COUNTIFS({ext}!$A:$A,$A{r},{ext}!$C:$C,{c})'
            if f.ref in internal:
                sh, kc = internal[f.ref]
                cnt = f"COUNTIFS({sh}!$A:$A,$A{r},{sh}!${kc}:${kc},{c})+{ext_cnt}"
            else:
                cnt = ext_cnt
            any_ok = f'{c}="any",' if f.ref == "Network Class" else ""
            parts.append(f'IF(OR({c}="",{any_ok}{cnt}>0),"","{f.header}: "&{c}&"; ")')
        miss = "&".join(parts)
        cell = ws.cell(row=r, column=check_col, value=f'=IF(B{r}="","",IF(({miss})="","OK","Missing - "&{miss}))')
        cell.font = BODY
    letter = L(check_col)
    ws.conditional_formatting.add(f"{letter}{FIRST}:{letter}200",
                                  FormulaRule(formula=[f'LEFT({letter}{FIRST},7)="Missing"'],
                                              font=Font(name=FONT, color="C00000", bold=True)))
    ws.conditional_formatting.add(f"{letter}{FIRST}:{letter}200", FormulaRule(formula=[f'{letter}{FIRST}="OK"'],
                                  font=Font(name=FONT, color="2E7D32", bold=True)))


RUN_CONTROL_HELP = {
    "create_network_classes": "Yes = create the network classes listed on Network_Classes.",
    "create_cl_profiles": "Yes = create the connection-limit protections (CL_Protections) and profiles (CL_Profile_Members).",
    "create_out_of_state_profiles": "Yes = create the out-of-state profiles listed on OOS_Profiles.",
    "create_bdos_profiles": "Yes = create the BDoS profiles listed on BDoS_Profiles.",
    "create_dns_profiles": "Must be No in the POC (DNS profiles are not generated).",
    "create_https_profiles": "Must be No in the POC (HTTPS Flood profiles are not generated).",
    "create_traffic_filter_profiles": "Yes = create the traffic-filter profiles (TF_Profiles) and rules (TF_Rules).",
    "create_ssl_objects": "Must be No in the POC (SSL objects are not generated).",
    "create_security_policies": "Yes = create the security policies listed on Policies with their profile bindings.",
    S.AUTHORIZE_APPLY: "Authorizes the separate apply step (Phase B, update_policies.yml) that activates the policies. "
                       "The generated YAML never applies policies by itself. Yes requires Change Ticket and Authorized By.",
    "environment": "lab or production. The run checks the target device against this environment's allowlist.",
    "change_ticket": "Change ticket number. Required for production and whenever Authorize Policy Apply = Yes.",
    "authorized_by": "Name of the approver. Required together with a change ticket.",
}


def _yes_no(v):
    if v is True:
        return S.YES
    if v is False:
        return S.NO
    return v


def _run_control(wb, values: Dict, lists: _Lists):
    ws = wb.create_sheet("Run_Control")
    ws.sheet_properties.tabColor = "C55A11"
    _describe(ws, S.RUN_CONTROL.description, 3, height=60)
    for i, h in enumerate(("Setting", "Value", "What it controls"), start=1):
        c = ws.cell(row=HDR, column=i, value=h)
        c.font, c.fill, c.border = HDR_FONT, _fill("003087"), BOX
    keys = list(S.RUN_CONTROL_TOGGLES) + [S.AUTHORIZE_APPLY] + list(S.RUN_CONTROL_SETTINGS)
    yellow = _fill("FFF2CC")
    for r, k in enumerate(keys, start=FIRST):
        ws.cell(row=r, column=1, value=S.rc_label(k)).font = Font(name=FONT, size=10, bold=True)
        v = ws.cell(row=r, column=2, value=_yes_no(values.get(k)))
        v.font, v.fill, v.border = BODY, yellow, BOX
        v.alignment = Alignment(horizontal="center")
        ws.cell(row=r, column=3, value=RUN_CONTROL_HELP.get(k, "")).font = BODY
    n_bool = len(S.RUN_CONTROL_TOGGLES) + 1
    last_bool = FIRST + n_bool - 1
    dv = DataValidation(type="list", formula1=f'"{S.YES},{S.NO}"', allow_blank=True, showErrorMessage=True,
                        errorTitle="Yes or No", error="Choose Yes or No.")
    ws.add_data_validation(dv)
    dv.add(f"B{FIRST}:B{last_bool}")
    env_row = last_bool + 1
    _dv = DataValidation(type="list", formula1=lists.ref(list(S.ENVIRONMENTS)), allow_blank=True)
    ws.add_data_validation(_dv)
    _dv.add(f"B{env_row}")
    row_of = {k: r for r, k in enumerate(keys, start=FIRST)}
    chk_row = env_row + 4
    ws.cell(row=chk_row, column=1, value="Run_Control check").font = Font(name=FONT, size=10, bold=True)
    uns = ",".join(f'B{row_of[t]}="{S.YES}"' for t in S.UNSUPPORTED_TOGGLES)
    f = (f'=IF(OR({uns}),"ERROR - DNS, HTTPS Flood and SSL must be No in the POC",'
         f'IF(AND(OR(B{row_of[S.AUTHORIZE_APPLY]}="{S.YES}",B{env_row}="production"),'
         f'OR(B{row_of["change_ticket"]}="",B{row_of["authorized_by"]}="")),"ERROR - change ticket and approver required",'
         f'IF(COUNTBLANK(B{FIRST}:B{last_bool})>0,"ERROR - every Create/Authorize setting must be Yes or No","OK")))')
    c = ws.cell(row=chk_row, column=2, value=f)
    c.font = Font(name=FONT, size=10, bold=True)
    ws.conditional_formatting.add(f"B{chk_row}", FormulaRule(formula=[f'LEFT(B{chk_row},5)="ERROR"'],
                                  font=Font(name=FONT, color="C00000", bold=True)))
    for col, w in zip("ABC", (34, 14, 100)):
        ws.column_dimensions[col].width = w


README = [
    ("DefensePro Configuration Workbook", None, "title"),
    ("Template version", f"v{S.TEMPLATE_VERSION} (xl2yaml {__version__})", None),
    ("WHAT THIS TOOL DOES", None, "h"),
    ("Purpose", "The DefensePro Ansible automation (playbooks/create_full_config.yml) creates network classes, protection "
                "profiles and security policies on DefensePro devices. It reads vars/create_vars.yml. This workbook is an "
                "OPTIONAL, easier way to write that configuration: fill in tables instead of YAML.", None),
    ("How it works", "xl2yaml reads this workbook, checks every value against what the modules accept, and writes one "
                     "create_vars_<device>.yml per included device in exactly the format the playbook already uses. "
                     "The playbooks and modules do not change.", None),
    ("Flow", "Workbook -> xl2yaml convert -> generated/create_vars_<device>.yml -> Git review -> xl2yaml run "
             "(preflight -> Phase A create -> gate -> read-back -> Phase B apply)", None),
    ("Why strict", "Most modules silently replace an unknown value with a default (e.g. a typo in a CL action becomes "
                   "'drop', an unknown TF protocol becomes 'any'). The converter therefore rejects every unknown value, "
                   "and fields whose default would widen protection must be chosen explicitly.", None),
    ("EXCEL OR YAML? (the workbook is optional)", None, "h"),
    ("No workbook", "If input/defensepro_config.xlsx does not exist, xl2yaml uses vars/create_vars.yml (YAML mode).", None),
    ("Workbook present", "The YAML is generated from the workbook (Excel mode). vars/create_vars.yml is IGNORED, never merged.", None),
    ("Workbook has errors", "The run stops. It never falls back to the YAML file.", None),
    ("Force a mode", "--input excel | --input yaml   (default: auto)", None),
    ("Logged on every run", "[INPUT] mode=EXCEL source=input/defensepro_config.xlsx sha256=...  and the same in "
                            "runs/<run id>/run_manifest.json", None),
    ("HOW TO USE", None, "h"),
    ("1. Devices", "Set 'Include in this run?' = Yes for the device(s) to generate.", None),
    ("2. Run_Control", "Set every Create ... row to Yes or No. DNS / HTTPS Flood / SSL stay No. Keep Authorize Policy "
                       "Apply = No until the change is approved.", None),
    ("3. Policies", "One row per policy per device. Fill Priority and Direction (not in the export).", None),
    ("4. Profile sheets", "One item per row. Orange headers must be filled (e.g. App Port Group, TCP Flags, Status, "
                          "Match Criteria, Outbound Traffic).", None),
    ("5. External_References", "Only if a policy or profile uses an object that ALREADY EXISTS on the device (e.g. a "
                               "Signature, EAAF, Geolocation, SYN or DNS profile this tool cannot create). Declaring it "
                               "tells the validator the name is intentional, so typos in names are still caught. "
                               "Declared objects are reported as UNVERIFIED. Leave empty if not needed.", None),
    ("6. Run the wizard", "python -m xl2yaml wizard   - menu: 1 convert Excel to vars only, 2 dry run (read YAML vars, "
                          "check syntax), 3 execute (push YAML vars + summary), 4 full run (1+2+3).", None),
    ("Or step by step", "python -m xl2yaml validate | convert | run --device <name> --phase A, then after approval "
                        "--phase B --after-run <run id>.", None),
    ("COLOUR LEGEND", None, "h"),
    ("Navy header", "Required.", "navy"),
    ("Orange header", "Explicit: must be chosen; the module default could widen protection or change enforcement.", "orange"),
    ("Blue header", "Optional: blank = module/device default (listed in the report).", "blue"),
    ("Grey header / tab", "Not converted (export information or reference-only sheet).", "grey"),
    ("Green header", "Automatic Excel check - do not edit.", "green"),
    ("RULES", None, "h"),
    ("Blank cells", "Blank = not set. Required and explicit fields may not be blank.", None),
    ("Row 1 / row 2", "Row 1 of each sheet is the description, row 2 the headers. Do not delete or move them.", None),
    ("Group Index", "Sets the order and index of network groups (0, 1, 2 ... per class). Sorting the sheet is safe.", None),
    ("Mask", "Prefix length (24) or dotted mask (255.255.255.0) - written exactly as entered.", None),
    ("App Port Group", "(all ports) writes \"\" = all ports. Choose it only if you mean all ports.", None),
    ("Dropdowns", "Pasted values bypass dropdowns - the converter re-checks everything.", None),
    ("Do not", "Rename sheets or headers, add columns, merge cells, type formulas in input cells, or type credentials.", None),
]


README_DESCRIPTION = ("PURPOSE: explains what this workbook is for, the order to fill the sheets in and how to run the "
                      "tool. HOW TO USE: read top to bottom. Every other sheet also starts with a blue line like this one "
                      "(row 1) describing its purpose and what to fill; headers are on row 2, data from row 3 down.")


def _readme(wb, note: Optional[str]):
    ws = wb.create_sheet("README", 0)
    ws.sheet_properties.tabColor = "C00000"
    ws.sheet_view.showGridLines = False
    ws.column_dimensions["A"].width = 3
    ws.column_dimensions["B"].width = 34
    ws.column_dimensions["C"].width = 110
    fills = {"navy": "003087", "orange": "C55A11", "blue": "4A6FA5", "grey": "7F7F7F", "green": "2E7D32"}
    _describe(ws, README_DESCRIPTION, 3, height=45)
    r = 2
    items = list(README)
    if note:
        items.insert(2, ("This copy", note, None))
    for a, b, style in items:
        if style == "h":
            r += 1
        ca = ws.cell(row=r, column=2, value=a)
        cb = ws.cell(row=r, column=3, value=b)
        cb.font = Font(name=FONT, size=10)
        cb.alignment = Alignment(wrap_text=True, vertical="top")
        ca.alignment = Alignment(vertical="top")
        if style == "title":
            ca.font = Font(name=FONT, size=16, bold=True, color="003087")
        elif style == "h":
            ca.font = Font(name=FONT, size=12, bold=True, color="003087")
        elif style in fills:
            ca.font = Font(name=FONT, size=10, bold=True, color="FFFFFF")
            ca.fill = _fill(fills[style])
        else:
            ca.font = Font(name=FONT, size=10, bold=True)
        r += 1


def _value_map(wb):
    ws = wb.create_sheet("Value_Map")
    ws.sheet_properties.tabColor = "7F7F7F"
    _describe(ws, S.VALUE_MAP_DESCRIPTION, 5, height=35)
    for i, h in enumerate(("Sheet", "Column", "Excel value", "YAML value written", "Source"), start=1):
        c = ws.cell(row=HDR, column=i, value=h)
        c.font, c.fill = HDR_FONT, _fill("003087")
    r = FIRST
    for label, val in ((S.YES, "true"), (S.NO, "false")):
        for i, v in enumerate(("Run_Control", "Create ... / Authorize Policy Apply", label, val,
                               "security_policy_config / authorize_policy_apply"), start=1):
            ws.cell(row=r, column=i, value=v).font = BODY
        r += 1
    for spec in S.DATA_SHEETS:
        for f in spec.fields:
            pairs = list(f.labels)
            if f.kind == "port_group":
                pairs = [(S.ALL_PORTS_TOKEN, '""  (all ports)')] + [(p, p) for p in S.PORT_GROUPS] + [("<port number>", "\"<port number>\"")]
            if f.kind == "tcp_flags":
                pairs = [(S.ALL_FLAGS_TOKEN, "all six tcp_* = enable"), ("SYN,ACK", "tcp_syn/tcp_ack = enable, others disable")]
            for label, val in pairs:
                for i, v in enumerate((spec.name, f.header, label, val, f.source), start=1):
                    ws.cell(row=r, column=i, value=v).font = BODY
                r += 1
    for col, w in zip("ABCDE", (22, 30, 30, 36, 70)):
        ws.column_dimensions[col].width = w


def build_workbook(path: str, rows: Optional[Dict[str, List[Dict]]] = None, run_control: Optional[Dict] = None,
                   reference: Optional[Dict[str, Tuple[List[str], List[List]]]] = None, note: Optional[str] = None):
    rows = rows or {}
    wb = Workbook()
    wb.remove(wb.active)
    lists = _Lists(wb)
    _readme(wb, note)
    for name in S.SHEET_ORDER:
        if name == "README" or name in ("Value_Map", "_Lists", "_Meta"):
            continue
        if name == "Run_Control":
            _run_control(wb, run_control or {}, lists)
            continue
        if name in S.REFERENCE_SHEETS:
            if reference and name in reference:
                headers, data = reference[name]
                ws = wb.create_sheet(name)
                ws.sheet_properties.tabColor = "7F7F7F"
                _describe(ws, S.REFERENCE_SHEET_DESCRIPTION, len(headers), height=35)
                for i, h in enumerate(headers, start=1):
                    c = ws.cell(row=HDR, column=i, value=h)
                    c.font, c.fill = HDR_FONT, _fill("7F7F7F")
                    ws.column_dimensions[L(i)].width = 16
                for r_i, row in enumerate(data, start=FIRST):
                    for c_i, v in enumerate(row, start=1):
                        ws.cell(row=r_i, column=c_i, value=v).font = BODY
            continue
        spec = S.SHEETS[name]
        ws = _data_sheet(wb, spec, rows.get(name, []), lists)
        if name == "Policies":
            _reference_check(ws, len(rows.get(name, [])))
    _value_map(wb)
    meta = wb.create_sheet("_Meta")
    meta["A1"], meta["B1"] = "template_version", S.TEMPLATE_VERSION
    meta["A2"], meta["B2"] = "generated_by", f"xl2yaml {__version__}"
    meta.sheet_state = "hidden"
    lists.ws.sheet_state = "hidden"
    # move _Lists to the end
    wb._sheets.remove(lists.ws)
    wb._sheets.insert(len(wb._sheets) - 1, lists.ws)
    wb.save(path)


def default_run_control() -> Dict:
    rc = {t: True for t in S.RUN_CONTROL_TOGGLES}
    for t in S.UNSUPPORTED_TOGGLES:
        rc[t] = False
    rc[S.AUTHORIZE_APPLY] = False
    rc["environment"] = "lab"
    return rc
