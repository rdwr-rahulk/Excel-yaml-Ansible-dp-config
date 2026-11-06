import json
import os
import shutil
import stat
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from xl2yaml import logutil  # noqa: E402
from xl2yaml.paths import Repo  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
LAB_IP = "10.105.192.32"


@pytest.fixture
def known_good():
    return yaml.safe_load((FIXTURES / "known_good_poc.yml").read_text())


@pytest.fixture
def repo(tmp_path) -> Repo:
    """A throw-away copy of the repository layout with lab/production allowlists."""
    r = tmp_path / "repo"
    shutil.copytree(ROOT / "playbooks", r / "playbooks")
    shutil.copytree(ROOT / "plugins", r / "plugins", ignore=shutil.ignore_patterns("__pycache__"))
    (r / "vars").mkdir()
    shutil.copy(ROOT / "vars" / "create_vars.yml.example", r / "vars" / "create_vars.yml.example")
    (r / "vars" / "cc.yml").write_text('cc:\n  cc_ip: "10.0.0.5"\n  username: "u"\n  password: "p"\n  verify_ssl: false\n')
    (r / "inventory.ini").write_text("[CyberController]\ncc ansible_host=127.0.0.1 ansible_connection=local\n")
    (r / "targets").mkdir()
    (r / "targets" / "allowlist_lab.yml").write_text(yaml.safe_dump(
        {"environment": "lab", "controller": "10.0.0.5", "devices": [{"name": "dp1", "ip": LAB_IP}]}))
    (r / "targets" / "allowlist_production.yml").write_text(yaml.safe_dump(
        {"environment": "production", "controller": "10.0.0.9", "devices": [{"name": "prod1", "ip": "10.9.9.9"}]}))
    logutil.setup()
    import logging
    logging.getLogger("xl2yaml").propagate = True     # let pytest's caplog see the log lines
    return Repo(r.resolve())


@pytest.fixture
def fake_ansible(tmp_path, monkeypatch):
    """Put a fake ansible-playbook first on PATH. Returns a helper to read the call log."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    script = Path(__file__).resolve().parent / "fake_ansible_playbook.py"
    if os.name == "nt":
        (bin_dir / "ansible-playbook.cmd").write_text(f'@"{sys.executable}" "{script}" %*\r\n')
    else:
        exe = bin_dir / "ansible-playbook"
        exe.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n')
        exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    calls = tmp_path / "calls.jsonl"
    monkeypatch.setenv("FAKE_CALLS", str(calls))
    monkeypatch.setenv("FAKE_STATE", str(tmp_path / "state.json"))
    monkeypatch.setenv("FAKE_MODE", "ok")

    class Calls:
        def read(self):
            if not calls.exists():
                return []
            return [json.loads(l) for l in calls.read_text().splitlines()]

        def playbooks(self):
            return [c["playbook"] for c in self.read()]

    return Calls()
