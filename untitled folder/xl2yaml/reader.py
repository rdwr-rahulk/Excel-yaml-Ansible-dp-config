"""Strict workbook reader.

The reader trusts nothing in Excel: dropdowns and data validation can be bypassed
by pasting, so every value is re-checked later by the normalizer. Here we only
make sure the workbook has exactly the expected structure and that no cell in an
input area contains something Excel produced on its own (formulas, dates, errors,
invisible whitespace, merged or hidden cells).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from openpyxl import load_workbook
from openpyxl.utils import get_column_letter

from . import schema as S
from .report import Report


@dataclass
class CellValue:
    value: Any
    ref: str


@dataclass
class RowData:
    sheet: str
    row: int
    cells: Dict[str, CellValue]

    def value(self, header):
        c = self.cells.get(header)
        return None if c is None else c.value

    def ref(self, header):
        c = self.cells.get(header)
        return c.ref if c else None


@dataclass
class WorkbookData:
    path: str
    version: Optional[str]
    sheets: Dict[str, List[RowData]] = field(default_factory=dict)
    run_control: Dict[str, CellValue] = field(default_factory=dict)
    reference_rows: Dict[str, int] = field(default_factory=dict)


_BAD_WS = ("\xa0", "\n", "\r", "\t", "​")


def _check_cell(cell, sheet: str, report: Report) -> Tuple[bool, Any]:
    """Return (ok, value). Blank strings become None."""
    ref = cell.coordinate
    v = cell.value
    if v is None:
        return True, None
    if cell.data_type == "f" or (isinstance(v, str) and v.startswith("=")):
        report.error("FORMULA", "formulas are not allowed in input cells; type the value", sheet=sheet, cell=ref, safety=True)
        return False, None
    if cell.data_type == "e":
        report.error("CELL_ERROR", f"cell contains an Excel error value {v!r}", sheet=sheet, cell=ref)
        return False, None
    if getattr(cell, "is_date", False):
        report.error("DATE_CELL", "cell is stored as a date (Excel auto-conversion?); format it as text or number",
                     sheet=sheet, cell=ref)
        return False, None
    if isinstance(v, str):
        if v == "":
            return True, None
        if v != v.strip() or any(ch in v for ch in _BAD_WS):
            report.error("WHITESPACE", f"leading/trailing or invisible whitespace in {v!r}", sheet=sheet, cell=ref)
            return False, None
    return True, v


def read_workbook(path: str, report: Report) -> Optional[WorkbookData]:
    try:
        wb = load_workbook(path, data_only=False)
    except Exception as exc:  # noqa: BLE001 - surface any openpyxl problem as a finding
        report.error("WORKBOOK_UNREADABLE", f"cannot open workbook: {exc}", sheet=path, safety=True)
        return None

    names = list(wb.sheetnames)
    known = set(S.SHEET_ORDER)
    for n in names:
        if n not in known:
            report.error("UNKNOWN_SHEET", f"sheet '{n}' is not part of template v{S.TEMPLATE_VERSION}", sheet=n, safety=True)
    required = [s.name for s in S.DATA_SHEETS] + ["Run_Control", "_Meta"]
    for n in required:
        if n not in names:
            report.error("MISSING_SHEET", f"required sheet '{n}' is missing", sheet=n, safety=True)
    if not report.ok:
        return None

    meta = wb["_Meta"]
    version = None
    if str(meta["A1"].value or "").strip() == "template_version":
        version = str(meta["B1"].value or "").strip()
    if version != S.TEMPLATE_VERSION:
        report.error("TEMPLATE_VERSION", f"template version is {version!r}, expected {S.TEMPLATE_VERSION!r}",
                     sheet="_Meta", cell="B1", safety=True)
        return None

    data = WorkbookData(path=path, version=version)

    for spec in S.DATA_SHEETS:
        data.sheets[spec.name] = _read_data_sheet(wb[spec.name], spec, report)

    data.run_control = _read_run_control(wb["Run_Control"], report)

    for n in S.REFERENCE_SHEETS:
        if n in names:
            ws = wb[n]
            count = sum(1 for row in ws.iter_rows(min_row=S.FIRST_DATA_ROW, values_only=True)
                        if any(v not in (None, "") for v in row))
            data.reference_rows[n] = count
    return data


def _read_data_sheet(ws, spec: S.SheetSpec, report: Report) -> List[RowData]:
    sheet = spec.name
    expected = spec.headers
    found = [ws.cell(row=S.HEADER_ROW, column=i + 1).value for i in range(max(ws.max_column, len(expected)))]
    while found and found[-1] in (None, ""):
        found.pop()
    if found != expected:
        report.error("HEADER_MISMATCH", f"header row {S.HEADER_ROW} does not match template v{S.TEMPLATE_VERSION}. "
                     f"Expected {expected}, found {found}", sheet=sheet, cell=f"A{S.HEADER_ROW}", safety=True)
        return []

    for rng in ws.merged_cells.ranges:
        if rng.min_row == rng.max_row == S.DESCRIPTION_ROW:
            continue   # the sheet description banner
        report.error("MERGED_CELLS", f"merged cells {rng} are not allowed on data sheets", sheet=sheet, cell=str(rng).split(":")[0])

    ncols = len(expected)
    hidden_cols = {i for i in range(1, ncols + 1)
                   if ws.column_dimensions[get_column_letter(i)].hidden}
    for i in hidden_cols:
        report.error("HIDDEN_COLUMN", f"column '{expected[i - 1]}' is hidden", sheet=sheet,
                     cell=f"{get_column_letter(i)}{S.HEADER_ROW}")

    rows: List[RowData] = []
    for r in range(S.FIRST_DATA_ROW, ws.max_row + 1):
        cells: Dict[str, CellValue] = {}
        has_data = False
        for i, fld in enumerate(spec.fields, start=1):
            cell = ws.cell(row=r, column=i)
            if fld.cls == S.CHECK:
                continue
            ok, v = _check_cell(cell, sheet, report)
            if v is not None or not ok:
                has_data = True
            cells[fld.header] = CellValue(v, cell.coordinate)
        # anything typed to the right of the template columns
        for c in range(ncols + 1, ws.max_column + 1):
            extra = ws.cell(row=r, column=c)
            if extra.value not in (None, ""):
                report.error("OUTSIDE_TEMPLATE", "value outside the template columns", sheet=sheet, cell=extra.coordinate)
        if not has_data:
            continue
        if ws.row_dimensions[r].hidden:
            report.error("HIDDEN_ROW", "row with data is hidden", sheet=sheet, cell=f"A{r}")
        rows.append(RowData(sheet, r, cells))
    return rows


_RC_KEYS = set(S.RUN_CONTROL_TOGGLES) | {S.AUTHORIZE_APPLY} | set(S.RUN_CONTROL_SETTINGS)
_RC_IGNORED = {"setting", "run_control check"}


def _read_run_control(ws, report: Report) -> Dict[str, CellValue]:
    """Column A holds human-readable labels (e.g. 'Create Network Classes'); they map to internal keys."""
    out: Dict[str, CellValue] = {}
    for r in range(S.HEADER_ROW, ws.max_row + 1):
        key = ws.cell(row=r, column=1).value
        if key in (None, ""):
            continue
        label = str(key).strip()
        if label.lower() in _RC_IGNORED:
            continue
        k = S.RUN_CONTROL_KEYS_BY_LABEL.get(label)
        if k is None:
            report.error("RUN_CONTROL_UNKNOWN", f"unknown Run_Control setting '{label}'", sheet="Run_Control",
                         cell=f"A{r}", safety=True)
            continue
        cell = ws.cell(row=r, column=2)
        ok, v = _check_cell(cell, "Run_Control", report)
        if k in out:
            report.error("RUN_CONTROL_DUPLICATE", f"setting '{label}' appears twice", sheet="Run_Control", cell=f"A{r}", safety=True)
        out[k] = CellValue(v if ok else None, cell.coordinate)
    return out
