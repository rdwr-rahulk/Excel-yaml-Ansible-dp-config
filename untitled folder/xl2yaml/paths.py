"""Well-known locations inside the dp_config_builder repository."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class Repo:
    root: Path

    @classmethod
    def find(cls, start: Optional[str] = None) -> "Repo":
        """The repo root is the first directory (from ``start`` upwards) that has playbooks/create_full_config.yml."""
        p = Path(start or os.getcwd()).resolve()
        for cand in (p, *p.parents):
            if (cand / "playbooks" / "create_full_config.yml").is_file():
                return cls(cand)
        here = Path(__file__).resolve().parent.parent
        if (here / "playbooks" / "create_full_config.yml").is_file():
            return cls(here)
        raise FileNotFoundError("cannot find the repository root (playbooks/create_full_config.yml)")

    # inputs
    @property
    def input_dir(self) -> Path: return self.root / "input"
    @property
    def default_workbook(self) -> Path: return self.input_dir / "defensepro_config.xlsx"
    @property
    def vars_dir(self) -> Path: return self.root / "vars"
    @property
    def create_vars(self) -> Path: return self.vars_dir / "create_vars.yml"
    @property
    def cc_vars(self) -> Path: return self.vars_dir / "cc.yml"
    @property
    def inventory(self) -> Path: return self.root / "inventory.ini"
    @property
    def ansible_cfg(self) -> Path: return self.root / "ansible.cfg"
    @property
    def ansible_cfg_example(self) -> Path: return self.root / "ansible_example.cfg"
    @property
    def playbooks(self) -> Path: return self.root / "playbooks"
    @property
    def plugins(self) -> Path: return self.root / "plugins"
    @property
    def targets_dir(self) -> Path: return self.root / "targets"

    def allowlist(self, env: str) -> Path:
        return self.targets_dir / f"allowlist_{env}.yml"

    @property
    def benign_warnings(self) -> Path: return self.targets_dir / "benign_warnings.yml"

    # outputs
    @property
    def generated_dir(self) -> Path: return self.root / "generated"
    @property
    def runs_dir(self) -> Path: return self.root / "runs"
    @property
    def staging_root(self) -> Path: return self.root / ".xl2yaml_staging"
