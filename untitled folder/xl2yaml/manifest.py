"""run_manifest.json - the auditable record of one run."""

from __future__ import annotations

import datetime as _dt
import getpass
import json
import os
import secrets
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import __version__


def new_run_id() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3)


@dataclass
class Manifest:
    run_id: str
    command: str
    created_utc: str = field(default_factory=lambda: _dt.datetime.now(_dt.timezone.utc).isoformat())
    tool_version: str = __version__
    operator: str = field(default_factory=lambda: _user())
    input: Dict[str, Any] = field(default_factory=dict)
    environment: Optional[str] = None
    devices: List[Dict[str, str]] = field(default_factory=list)
    generated: List[Dict[str, str]] = field(default_factory=list)
    toggles: Dict[str, Any] = field(default_factory=dict)
    authorization: Dict[str, Any] = field(default_factory=dict)
    validation: Dict[str, Any] = field(default_factory=dict)
    preflight: Dict[str, Any] = field(default_factory=dict)
    phases: Dict[str, Any] = field(default_factory=dict)
    readback: Dict[str, Any] = field(default_factory=dict)
    result: str = "IN_PROGRESS"
    notes: List[str] = field(default_factory=list)

    def save(self, runs_dir: Path) -> Path:
        d = runs_dir / self.run_id
        d.mkdir(parents=True, exist_ok=True)
        p = d / "run_manifest.json"
        p.write_text(json.dumps(self.__dict__, indent=2, sort_keys=False, default=str), encoding="utf-8")
        return p

    @classmethod
    def load(cls, path: Path) -> "Manifest":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        m = cls(run_id=raw["run_id"], command=raw["command"])
        m.__dict__.update(raw)
        return m


def _user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001
        return os.environ.get("USER", "unknown")


def command_line() -> str:
    return " ".join(["xl2yaml"] + sys.argv[1:])
