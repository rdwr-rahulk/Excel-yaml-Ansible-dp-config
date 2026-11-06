"""Findings collected during reading, validation and preflight."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

ERROR = "ERROR"
WARNING = "WARNING"
UNVERIFIED = "UNVERIFIED"
DEFAULT = "DEFAULT"   # field left out; module/device default applies
INFO = "INFO"

_ORDER = (ERROR, WARNING, UNVERIFIED, DEFAULT, INFO)
_TITLES = {
    ERROR: "ERRORS",
    WARNING: "WARNINGS",
    UNVERIFIED: "UNVERIFIED EXTERNAL REFERENCES",
    DEFAULT: "LEFT TO MODULE / DEVICE DEFAULT",
    INFO: "INFO",
}


@dataclass
class Finding:
    level: str
    code: str
    message: str
    sheet: Optional[str] = None
    cell: Optional[str] = None
    field: Optional[str] = None
    device: Optional[str] = None
    safety: bool = False   # safety findings can never be downgraded

    @property
    def location(self) -> str:
        if self.sheet and self.cell:
            return f"{self.sheet}!{self.cell}"
        return self.sheet or (self.device or "")

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v not in (None, False)}


@dataclass
class Report:
    findings: List[Finding] = field(default_factory=list)

    def add(self, level, code, message, sheet=None, cell=None, field=None, device=None, safety=False) -> Finding:
        f = Finding(level, code, message, sheet, cell, field, device, safety)
        self.findings.append(f)
        return f

    def error(self, code, message, **kw):
        return self.add(ERROR, code, message, **kw)

    def warning(self, code, message, **kw):
        return self.add(WARNING, code, message, **kw)

    def unverified(self, code, message, **kw):
        return self.add(UNVERIFIED, code, message, **kw)

    def default(self, code, message, **kw):
        return self.add(DEFAULT, code, message, **kw)

    def info(self, code, message, **kw):
        return self.add(INFO, code, message, **kw)

    def extend(self, other: "Report"):
        self.findings.extend(other.findings)

    def of(self, level) -> List[Finding]:
        return [f for f in self.findings if f.level == level]

    @property
    def errors(self) -> List[Finding]:
        return self.of(ERROR)

    @property
    def ok(self) -> bool:
        return not self.errors

    def codes(self, level=None) -> List[str]:
        return [f.code for f in self.findings if level is None or f.level == level]

    def downgrade_non_safety_errors(self):
        """Used by --yaml-report-only: field-level YAML findings become warnings; safety ones stay errors."""
        for f in self.findings:
            if f.level == ERROR and not f.safety:
                f.level = WARNING
                f.message += " (reported only: --yaml-report-only)"

    def render(self, header_lines: Optional[List[str]] = None, max_per_level: int = 500) -> str:
        out = list(header_lines or [])
        for level in _ORDER:
            items = self.of(level)
            if not items:
                continue
            out.append(f"{_TITLES[level]} ({len(items)})")
            for f in items[:max_per_level]:
                loc = f.location
                fld = f" {f.field}" if f.field else ""
                out.append(f"  {loc:<28}{fld:<26} [{f.code}] {f.message}".rstrip())
            if len(items) > max_per_level:
                out.append(f"  ... {len(items) - max_per_level} more")
        if not self.findings:
            out.append("No findings.")
        out.append(f"RESULT: {'PASS' if self.ok else 'FAIL'} "
                   f"({len(self.errors)} error(s), {len(self.of(WARNING))} warning(s), "
                   f"{len(self.of(UNVERIFIED))} unverified reference(s))")
        return "\n".join(out)
