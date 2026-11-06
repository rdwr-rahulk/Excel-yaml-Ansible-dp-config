"""Decide whether this run uses the Excel workbook or the existing YAML, and log it.

Rules (README "Excel or YAML?"):
  * no workbook at input/defensepro_config.xlsx  -> YAML mode (vars/create_vars.yml, as today)
  * workbook present                             -> Excel mode; vars/create_vars.yml is IGNORED, never merged
  * workbook present but invalid                 -> the run stops; there is NO fallback to YAML
  * more than one workbook in input/             -> the run stops (ambiguous)
  * --input excel | --input yaml                 -> forces the mode
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from . import logutil
from .paths import Repo
from .yamlio import sha256_file

EXCEL, YAML = "EXCEL", "YAML"


class InputError(Exception):
    """The input cannot be determined unambiguously. The run must stop."""


@dataclass
class InputSelection:
    mode: str
    source: Path
    sha256: str
    forced: bool = False
    ignored: List[str] = field(default_factory=list)
    reason: str = ""

    def as_dict(self) -> dict:
        return {"mode": self.mode, "source": str(self.source), "sha256": self.sha256, "forced": self.forced,
                "ignored": self.ignored, "reason": self.reason}


def _workbooks(repo: Repo) -> List[Path]:
    if not repo.input_dir.is_dir():
        return []
    return sorted(p for p in repo.input_dir.iterdir()
                  if p.suffix.lower() in (".xlsx", ".xlsm") and not p.name.startswith("~$"))


def select_input(repo: Repo, mode: str = "auto", workbook: Optional[str] = None) -> InputSelection:
    log = logutil.get()
    mode = (mode or "auto").lower()
    if mode not in ("auto", "excel", "yaml"):
        raise InputError(f"--input must be auto, excel or yaml (got {mode!r})")

    if workbook:                                   # explicit path always means Excel mode
        p = Path(workbook)
        if not p.is_file():
            raise InputError(f"workbook not found: {p}")
        sel = InputSelection(EXCEL, p, sha256_file(str(p)), forced=True, reason="--workbook given")
    elif mode == "excel":
        if not repo.default_workbook.is_file():
            raise InputError(f"--input excel but {repo.default_workbook} does not exist")
        sel = InputSelection(EXCEL, repo.default_workbook, sha256_file(str(repo.default_workbook)), forced=True,
                             reason="--input excel")
    elif mode == "yaml":
        if not repo.create_vars.is_file():
            raise InputError(f"--input yaml but {repo.create_vars} does not exist")
        sel = InputSelection(YAML, repo.create_vars, sha256_file(str(repo.create_vars)), forced=True, reason="--input yaml")
        books = _workbooks(repo)
        if books:
            sel.ignored += [str(b) for b in books]
    else:
        books = _workbooks(repo)
        if len(books) > 1:
            raise InputError("input is AMBIGUOUS: more than one workbook in input/: " + ", ".join(b.name for b in books))
        if len(books) == 1 and books[0].name != repo.default_workbook.name:
            raise InputError(f"input is AMBIGUOUS: found {books[0].name}; the workbook must be named "
                             f"{repo.default_workbook.name}")
        if books:
            sel = InputSelection(EXCEL, books[0], sha256_file(str(books[0])), reason="workbook found")
        elif repo.create_vars.is_file():
            sel = InputSelection(YAML, repo.create_vars, sha256_file(str(repo.create_vars)),
                                 reason=f"no workbook at {repo.default_workbook.relative_to(repo.root)}")
        else:
            raise InputError(f"no input: neither {repo.default_workbook} nor {repo.create_vars} exists")

    if sel.mode == EXCEL and repo.create_vars.is_file():
        sel.ignored.append(str(repo.create_vars))

    forced = " (forced)" if sel.forced else ""
    log.info(f"[INPUT] mode={sel.mode}{forced} source={_rel(repo, sel.source)} sha256={sel.sha256}"
             + (f" ({sel.reason})" if sel.reason and not sel.forced else ""))
    for ig in sel.ignored:
        log.info(f"[INPUT] {_rel(repo, Path(ig))} present but IGNORED ({sel.mode} mode)")
    return sel


def _rel(repo: Repo, p: Path) -> str:
    try:
        return str(Path(p).resolve().relative_to(repo.root))
    except ValueError:
        return str(p)
