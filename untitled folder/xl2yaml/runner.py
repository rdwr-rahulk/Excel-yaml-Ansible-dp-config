"""Run a playbook inside a staging directory and collect structured results."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from . import logutil
from .staging import StagedRun


class RunnerError(Exception):
    pass


@dataclass
class PlaybookRun:
    playbook: str
    returncode: int
    records: List[Dict] = field(default_factory=list)
    stats: Dict[str, Dict] = field(default_factory=dict)
    log_path: Optional[Path] = None
    check_mode: bool = False

    def items(self, action: str) -> List[Dict]:
        return [r for r in self.records if r["item_level"] and _short(r["action"]) == action]

    def tasks(self, action: str) -> List[Dict]:
        return [r for r in self.records if not r["item_level"] and _short(r["action"]) == action]


def _short(action: str) -> str:
    return (action or "").split(".")[-1]


def _clean_env(staged: StagedRun, results_file: Path) -> Dict[str, str]:
    # Drop every inherited ANSIBLE_* variable so nothing outside the staging
    # directory (config files, extra var plugins, other callbacks) can change the run.
    env = {k: v for k, v in os.environ.items() if not k.startswith("ANSIBLE_")}
    env.update({
        "ANSIBLE_CONFIG": str(staged.ansible_cfg),
        "ANSIBLE_NOCOLOR": "1",
        "ANSIBLE_FORCE_COLOR": "0",
        "ANSIBLE_RETRY_FILES_ENABLED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
        "XL2YAML_RESULTS_FILE": str(results_file),
    })
    return env


def ansible_playbook_bin() -> str:
    exe = shutil.which("ansible-playbook")
    if not exe:
        raise RunnerError("ansible-playbook not found on PATH")
    return exe


def run_playbook(staged: StagedRun, playbook: str, log_dir: Path, check: bool = False,
                 syntax_check: bool = False) -> PlaybookRun:
    """Run playbooks/<playbook> from the staging directory. No -e, no --limit, ever."""
    log = logutil.get()
    log_dir.mkdir(parents=True, exist_ok=True)
    tag = Path(playbook).stem + ("_check" if check else "") + ("_syntax" if syntax_check else "")
    results_file = log_dir / f"results_{tag}.json"
    log_path = log_dir / f"ansible_{tag}.log"
    cmd = [ansible_playbook_bin(), str(Path("playbooks") / playbook)]
    if check:
        cmd.append("--check")
    if syntax_check:
        cmd.append("--syntax-check")
    log.info(f"[RUN] {' '.join(cmd)}  (cwd={staged.dir})")
    with open(log_path, "w", encoding="utf-8") as out:
        proc = subprocess.Popen(cmd, cwd=staged.dir, env=_clean_env(staged, results_file), stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        assert proc.stdout is not None
        for line in proc.stdout:
            out.write(line)
            log.info(line.rstrip("\n"))
        rc = proc.wait()
    run = PlaybookRun(playbook, rc, log_path=log_path, check_mode=check)
    if results_file.is_file():
        raw = json.loads(results_file.read_text(encoding="utf-8"))
        run.records, run.stats = raw.get("records", []), raw.get("stats", {})
    elif not syntax_check:
        log.warning("[RUN] no results file was written - the result gate will fail")
    return run
