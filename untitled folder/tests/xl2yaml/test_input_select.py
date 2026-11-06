"""Acceptance test 7: Excel is optional and the input used is always logged."""

import logging

import pytest
import yaml

from fixture_writer import workbook_from_config
from xl2yaml.input_select import EXCEL, YAML, InputError, select_input


def _yaml(repo, cfg):
    repo.create_vars.write_text(yaml.safe_dump(cfg))


def test_no_workbook_uses_yaml(repo, known_good, caplog):
    _yaml(repo, known_good)
    with caplog.at_level(logging.INFO, logger="xl2yaml"):
        sel = select_input(repo)
    assert sel.mode == YAML and sel.source == repo.create_vars
    assert "[INPUT] mode=YAML" in caplog.text and sel.sha256 in caplog.text


def test_workbook_wins_and_yaml_is_ignored(repo, known_good, caplog):
    _yaml(repo, known_good)
    repo.input_dir.mkdir()
    workbook_from_config(str(repo.default_workbook), known_good)
    with caplog.at_level(logging.INFO, logger="xl2yaml"):
        sel = select_input(repo)
    assert sel.mode == EXCEL
    assert str(repo.create_vars) in sel.ignored
    assert "[INPUT] mode=EXCEL" in caplog.text and "IGNORED" in caplog.text


def test_lock_files_are_not_workbooks(repo, known_good):
    _yaml(repo, known_good)
    repo.input_dir.mkdir()
    (repo.input_dir / "~$defensepro_config.xlsx").write_bytes(b"lock")
    assert select_input(repo).mode == YAML


def test_two_workbooks_are_ambiguous(repo, known_good):
    repo.input_dir.mkdir()
    workbook_from_config(str(repo.default_workbook), known_good)
    workbook_from_config(str(repo.input_dir / "copy.xlsx"), known_good)
    with pytest.raises(InputError, match="AMBIGUOUS"):
        select_input(repo)


def test_misnamed_workbook_is_ambiguous(repo, known_good):
    repo.input_dir.mkdir()
    workbook_from_config(str(repo.input_dir / "config_v2.xlsx"), known_good)
    with pytest.raises(InputError, match="AMBIGUOUS"):
        select_input(repo)


def test_forced_yaml_ignores_workbook(repo, known_good):
    _yaml(repo, known_good)
    repo.input_dir.mkdir()
    workbook_from_config(str(repo.default_workbook), known_good)
    sel = select_input(repo, "yaml")
    assert sel.mode == YAML and sel.forced and str(repo.default_workbook) in sel.ignored


def test_forced_excel_without_workbook_fails(repo, known_good):
    _yaml(repo, known_good)
    with pytest.raises(InputError):
        select_input(repo, "excel")


def test_no_input_at_all_fails(repo):
    with pytest.raises(InputError, match="no input"):
        select_input(repo)
