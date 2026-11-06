"""Turn raw cell values into typed YAML values, one field at a time.

Every value is checked here regardless of any Excel data validation, because
pasted values bypass dropdowns.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import schema as S
from .reader import RowData, WorkbookData
from .report import Report

_MISSING = object()


@dataclass
class NRow:
    sheet: str
    row: int
    device: Optional[str]
    values: Dict[str, Any] = field(default_factory=dict)   # yaml key -> typed value (absent = blank)
    cells: Dict[str, str] = field(default_factory=dict)    # yaml key -> cell ref
    ok: bool = True

    def get(self, key, default=None):
        return self.values.get(key, default)

    def cell(self, key):
        return self.cells.get(key)


@dataclass
class NormalizedData:
    devices: List[NRow] = field(default_factory=list)
    sheets: Dict[str, List[NRow]] = field(default_factory=dict)
    run_control: Dict[str, Any] = field(default_factory=dict)
    run_control_cells: Dict[str, str] = field(default_factory=dict)
    reference_rows: Dict[str, int] = field(default_factory=dict)
    defaults: Dict[tuple, int] = field(default_factory=dict)     # (device, sheet, header) -> blank count


def _as_int(v) -> Any:
    if isinstance(v, bool):
        return _MISSING
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        return int(v) if v.is_integer() else _MISSING
    if isinstance(v, str) and v.isdigit():
        return int(v)
    return _MISSING


def _as_name(v) -> Any:
    if isinstance(v, bool):
        return _MISSING
    if isinstance(v, str):
        return v
    i = _as_int(v)
    return str(i) if i is not _MISSING else _MISSING


def convert(fld: S.Field, v, report: Report, sheet: str, cell: str, device: Optional[str]) -> Any:
    """Return the typed YAML value, or _MISSING after recording an error."""
    kw = dict(sheet=sheet, cell=cell, field=fld.key or fld.header, device=device)
    k = fld.kind

    if k in ("name", "ref"):
        s = _as_name(v)
        if s is _MISSING:
            report.error("BAD_NAME", f"expected a name, got {v!r}", **kw)
        return s

    if k == "text":
        return str(v)

    if k == "enum":
        if not isinstance(v, str):
            report.error("BAD_ENUM", f"{v!r} is not one of {[l for l, _ in fld.labels]}", **kw)
            return _MISSING
        lm = fld.label_map()
        if v in lm:
            return lm[v]
        suggestion = [l for l in lm if l.lower() == v.lower()]
        hint = f" - did you mean '{suggestion[0]}'? (letter case must match)" if suggestion else ""
        report.error("BAD_ENUM", f"'{v}' is not an allowed value {list(lm)}{hint}", **kw)
        return _MISSING

    if k in ("int", "numeric_string"):
        i = _as_int(v)
        if i is _MISSING:
            report.error("BAD_NUMBER", f"expected a whole number, got {v!r}", **kw)
            return _MISSING
        if fld.minimum is not None and i < fld.minimum or fld.maximum is not None and i > fld.maximum:
            report.error("OUT_OF_RANGE", f"{i} is outside {fld.minimum}..{fld.maximum}", **kw)
            return _MISSING
        return i if k == "int" else str(i)

    if k in ("ip", "ipv4"):
        if not isinstance(v, str):
            report.error("BAD_IP", f"expected an IP address as text, got {v!r}", **kw)
            return _MISSING
        try:
            ip = ipaddress.ip_address(v)
        except ValueError:
            report.error("BAD_IP", f"'{v}' is not a valid IP address", **kw)
            return _MISSING
        if k == "ipv4" and ip.version != 4:
            report.error("BAD_IP", f"'{v}' must be an IPv4 address", **kw)
            return _MISSING
        return v

    if k == "mask":
        i = _as_int(v)
        if i is not _MISSING:
            return str(i)          # family-specific range checked in the validator
        if isinstance(v, str):
            try:
                ipaddress.IPv4Network(f"0.0.0.0/{v}")
                return v           # dotted mask, written exactly as entered
            except ValueError:
                pass
        report.error("BAD_MASK", f"'{v}' is not a prefix length or dotted netmask", **kw)
        return _MISSING

    if k == "yesno":
        if v in ("Yes", "No"):
            return v == "Yes"
        report.error("BAD_ENUM", f"expected Yes or No, got {v!r}", **kw)
        return _MISSING

    if k == "port_group":
        if v == S.ALL_PORTS_TOKEN:
            return ""
        if isinstance(v, str) and v in S.PORT_GROUPS:
            return v
        i = _as_int(v)
        if i is not _MISSING and 1 <= i <= 65535:
            return str(i)
        report.error("BAD_PORT_GROUP", f"{v!r} is not {S.ALL_PORTS_TOKEN}, {', '.join(S.PORT_GROUPS)} or a port number", **kw)
        return _MISSING

    if k == "tcp_flags":
        names = dict(S.TCP_FLAG_KEYS)
        if v == S.ALL_FLAGS_TOKEN:
            return {key: "enable" for _, key in S.TCP_FLAG_KEYS}
        if not isinstance(v, str):
            report.error("BAD_TCP_FLAGS", f"expected {S.ALL_FLAGS_TOKEN} or a comma list, got {v!r}", **kw)
            return _MISSING
        tokens = [t.strip() for t in v.split(",")]
        bad = [t for t in tokens if t not in names]
        if bad or len(set(tokens)) != len(tokens) or not tokens:
            report.error("BAD_TCP_FLAGS", f"'{v}' must be {S.ALL_FLAGS_TOKEN} or a comma list of "
                         f"{', '.join(names)} without duplicates", **kw)
            return _MISSING
        return {key: ("enable" if label in tokens else "disable") for label, key in S.TCP_FLAG_KEYS}

    raise ValueError(f"unknown field kind {k}")


def _normalize_row(raw: RowData, spec: S.SheetSpec, report: Report, data: NormalizedData) -> NRow:
    device = None
    nrow = NRow(raw.sheet, raw.row, None)
    for fld in spec.fields:
        if fld.cls == S.CHECK:
            continue
        v = raw.value(fld.header)
        ref = raw.ref(fld.header)
        if fld.cls == S.KEY:
            if v is None:
                report.error("BLANK_REQUIRED", "device name is required", sheet=raw.sheet, cell=ref, safety=True)
                nrow.ok = False
            else:
                device = _as_name(v)
                nrow.device = device if device is not _MISSING else None
            continue
        if v is None:
            if fld.cls == S.REQUIRED:
                report.error("BLANK_REQUIRED", f"'{fld.header}' is required", sheet=raw.sheet, cell=ref,
                             field=fld.key, device=nrow.device)
                nrow.ok = False
            elif fld.cls == S.EXPLICIT and fld.kind != "tcp_flags":   # tcp_flags is conditional (validator)
                report.error("BLANK_EXPLICIT", f"'{fld.header}' must be chosen explicitly - if omitted the module "
                             f"applies a default ({fld.source})", sheet=raw.sheet, cell=ref, field=fld.key,
                             device=nrow.device, safety=True)
                nrow.ok = False
            elif fld.cls == S.OPTIONAL:
                key = (nrow.device, raw.sheet, fld.header)
                data.defaults[key] = data.defaults.get(key, 0) + 1
            nrow.cells[fld.key or fld.header] = ref
            continue
        if fld.cls == S.INFO:
            key = (nrow.device, raw.sheet, "INFO:" + fld.header)
            data.defaults[key] = data.defaults.get(key, 0) + 1
            continue
        typed = convert(fld, v, report, raw.sheet, ref, nrow.device)
        nrow.cells[fld.key] = ref
        if typed is _MISSING:
            nrow.ok = False
        else:
            nrow.values[fld.key] = typed
    return nrow


def normalize(wb: WorkbookData, report: Report) -> NormalizedData:
    data = NormalizedData(reference_rows=dict(wb.reference_rows))
    for spec in S.DATA_SHEETS:
        rows = [_normalize_row(r, spec, report, data) for r in wb.sheets.get(spec.name, [])]
        if spec.name == "Devices":
            data.devices = rows
        else:
            data.sheets[spec.name] = rows
    _normalize_run_control(wb, report, data)
    return data


def _normalize_run_control(wb: WorkbookData, report: Report, data: NormalizedData):
    rc = wb.run_control
    for key in S.RUN_CONTROL_TOGGLES + (S.AUTHORIZE_APPLY,):
        cv = rc.get(key)
        ref = cv.ref if cv else None
        if cv is None or cv.value is None:
            report.error("TOGGLE_NOT_EXPLICIT", f"'{S.rc_label(key)}' must be set to Yes or No", sheet="Run_Control",
                         cell=ref, field=key, safety=True)
            continue
        v = cv.value
        if isinstance(v, str) and v in (S.YES, S.NO):
            v = v == S.YES
        if not isinstance(v, bool):
            report.error("TOGGLE_NOT_BOOL", f"'{S.rc_label(key)}' must be Yes or No, got {cv.value!r}", sheet="Run_Control",
                         cell=ref, field=key, safety=True)
            continue
        data.run_control[key] = v
        data.run_control_cells[key] = ref
    for key in S.RUN_CONTROL_SETTINGS:
        cv = rc.get(key)
        data.run_control_cells[key] = cv.ref if cv else None
        if cv is not None and cv.value is not None:
            data.run_control[key] = str(cv.value)
    env = data.run_control.get("environment")
    if env not in S.ENVIRONMENTS:
        report.error("BAD_ENVIRONMENT", f"environment must be one of {S.ENVIRONMENTS}, got {env!r}",
                     sheet="Run_Control", cell=data.run_control_cells.get("environment"), safety=True)
