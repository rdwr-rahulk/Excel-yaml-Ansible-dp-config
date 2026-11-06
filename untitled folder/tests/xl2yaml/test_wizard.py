"""Workbook usability (readable Run_Control, description rows) and the orchestration wizard."""

import yaml
from openpyxl import load_workbook

from fixture_writer import workbook_from_config
from xl2yaml import schema as S
from xl2yaml.template import build_workbook, default_run_control
from xl2yaml.wizard import CONVERT, DRY_RUN, EXECUTE, FULL, Wizard, WizardOptions


# --------------------------------------------------------------------------- workbook
def _template(tmp_path):
    p = tmp_path / "t.xlsx"
    build_workbook(str(p), {}, default_run_control(), None, "test")
    return load_workbook(p)


def test_run_control_uses_readable_labels_and_yes_no(tmp_path):
    ws = _template(tmp_path)["Run_Control"]
    labels = [ws.cell(row=r, column=1).value for r in range(S.FIRST_DATA_ROW, ws.max_row + 1)]
    assert "Create Network Classes" in labels and "Authorize Policy Apply" in labels
    assert not any(isinstance(l, str) and "_" in l and l != "Run_Control check" for l in labels), labels
    n_bool = len(S.RUN_CONTROL_TOGGLES) + 1
    values = {ws.cell(row=r, column=2).value for r in range(S.FIRST_DATA_ROW, S.FIRST_DATA_ROW + n_bool)}
    assert values == {"Yes", "No"}


def test_every_visible_sheet_starts_with_a_description(tmp_path):
    wb = _template(tmp_path)
    for ws in wb.worksheets:
        if ws.sheet_state == "hidden":
            continue
        text = ws.cell(row=1, column=1).value or ws.cell(row=1, column=2).value
        assert text and "PURPOSE" in text, ws.title
        if ws.title not in ("README", "Run_Control", "Value_Map"):
            assert "HOW TO FILL" in text or "HOW TO USE" in text, ws.title


def test_external_references_description_explains_why(tmp_path):
    text = _template(tmp_path)["External_References"]["A1"].value
    assert "WHY IT IS NEEDED" in text and "ALREADY EXIST" in text


# --------------------------------------------------------------------------- wizard
class Console:
    def __init__(self, answers=()):
        self.answers, self.lines = list(answers), []

    def ask(self, prompt):
        self.lines.append(prompt)
        return self.answers.pop(0)

    def out(self, line=""):
        self.lines.append(str(line))

    @property
    def text(self):
        return "\n".join(self.lines)


def _wizard(repo, console, **kw):
    kw.setdefault("skip_syntax_check", True)
    return Wizard(repo, WizardOptions(**kw), ask=console.ask, out=console.out)


def _wb(repo, cfg, **rc):
    repo.input_dir.mkdir(exist_ok=True)
    workbook_from_config(str(repo.default_workbook), cfg, **rc)


def test_menu_quit_does_nothing(repo, known_good):
    _wb(repo, known_good)
    c = Console(["9", "q"])
    assert _wizard(repo, c).main() == 0
    assert "not a menu option" in c.text
    assert not repo.generated_dir.exists()


def test_menu_option_1_converts_only(repo, known_good):
    _wb(repo, known_good)
    c = Console(["1"])
    assert _wizard(repo, c).main() == 0
    out = repo.generated_dir / "create_vars_dp1.yml"
    assert out.is_file()
    assert yaml.safe_load(out.read_text())["dp_ip"] == known_good["dp_ip"]
    assert "Execute" not in c.text.split("Step 1")[-1]


def test_dry_run_needs_converted_vars(repo, known_good):
    _wb(repo, known_good)
    c = Console()
    assert _wizard(repo, c, choice=DRY_RUN).main() != 0
    assert "run option 1" in c.text


def test_dry_run_reads_and_checks_the_vars(repo, known_good):
    _wb(repo, known_good)
    assert _wizard(repo, Console(), choice=CONVERT).main() == 0
    c = Console()
    assert _wizard(repo, c, choice=DRY_RUN).main() == 0, c.text
    assert "DRY RUN: PASS" in c.text and "Network classes" in c.text


def test_dry_run_detects_stale_vars(repo, known_good):
    _wb(repo, known_good)
    assert _wizard(repo, Console(), choice=CONVERT).main() == 0
    changed = yaml.safe_load(yaml.safe_dump(known_good))
    changed["create_security_policies"][0]["priority"] = "702"
    _wb(repo, changed)
    c = Console()
    assert _wizard(repo, c, choice=DRY_RUN).main() != 0
    assert "STALE" in c.text


def test_dry_run_rejects_a_hand_broken_yaml(repo, known_good):
    bad = yaml.safe_load(yaml.safe_dump(known_good))
    bad["cl_protections"][0]["action"] = "Block"
    repo.create_vars.write_text(yaml.safe_dump(bad))
    c = Console()
    assert _wizard(repo, c, choice=DRY_RUN, input_mode="yaml").main() != 0
    assert "DRY RUN: FAIL" in c.text


def test_execute_refuses_unconverted_vars(repo, known_good, fake_ansible):
    _wb(repo, known_good)
    c = Console()
    assert _wizard(repo, c, choice=EXECUTE, confirm_targets="dp1").main() != 0
    assert fake_ansible.playbooks() == []


def test_full_run_stops_on_invalid_workbook(repo, known_good, fake_ansible):
    bad = yaml.safe_load(yaml.safe_dump(known_good))
    del bad["cl_protections"][0]["app_port_group"]
    _wb(repo, bad)
    c = Console()
    assert _wizard(repo, c, choice=FULL, confirm_targets="dp1").main() != 0
    assert "stopped at step 1" in c.text
    assert fake_ansible.playbooks() == []


def test_full_run_creates_then_prints_summary(repo, known_good, fake_ansible):
    _wb(repo, known_good)
    c = Console()
    rc = _wizard(repo, c, choice=FULL, confirm_targets="dp1").main()
    assert rc == 0, c.text
    assert fake_ansible.playbooks() == ["create_full_config.yml", "get_network_class.yml"]
    assert "EXECUTION SUMMARY" in c.text and "OVERALL: PASS" in c.text


def test_execute_applies_only_when_authorized_and_confirmed(repo, known_good, fake_ansible):
    _wb(repo, known_good, authorize_policy_apply=True, change_ticket="CHG9", authorized_by="Lead")
    assert _wizard(repo, Console(), choice=CONVERT).main() == 0
    c = Console(["n"])
    assert _wizard(repo, c, choice=EXECUTE, confirm_targets="dp1").main() == 0, c.text
    assert "update_policies.yml" not in fake_ansible.playbooks()
    c = Console(["y"])
    assert _wizard(repo, c, choice=EXECUTE, confirm_targets="dp1").main() == 0, c.text
    assert fake_ansible.playbooks()[-1] == "update_policies.yml"
