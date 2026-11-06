"""Acceptance tests 1, 2 and 6: fidelity, determinism, mapping from the modules."""

import yaml

from fixture_writer import workbook_from_config
from xl2yaml import schema as S
from xl2yaml.convert import convert_workbook
from xl2yaml.report import Report
from xl2yaml.yaml_check import check_config
from xl2yaml.yamlio import semantic_diff, sha256_file


def _convert(tmp_path, cfg, **kw):
    p = tmp_path / "wb.xlsx"
    workbook_from_config(str(p), cfg, **kw)
    return convert_workbook(str(p), sha256_file(str(p)))


def test_known_good_survives_excel_path(tmp_path, known_good):
    res = _convert(tmp_path, known_good)
    assert res.ok, res.report.render()
    out = res.outputs["dp1"]
    # semantic equivalence: same keys, values, types and list order
    assert semantic_diff(known_good, out.config) == []
    assert semantic_diff(known_good, yaml.safe_load(out.text)) == []


def test_types_are_preserved(tmp_path, known_good):
    cfg = _convert(tmp_path, known_good).outputs["dp1"].config
    cl = cfg["cl_protections"]
    assert cl[0]["threshold"] == "100" and isinstance(cl[0]["threshold"], str)
    assert cl[0]["index"] == 0 and isinstance(cl[0]["index"], int)
    assert "index" not in cl[1]                                  # blank Protection ID -> key omitted
    assert cl[1]["app_port_group"] == ""                         # only from the explicit "(all ports)" token
    assert cfg["netclasses"][0]["groups"][0]["mask"] == "255.255.255.0"   # dotted mask written as entered
    assert cfg["netclasses"][1]["groups"][0]["mask"] == "24"
    assert cfg["create_security_policies"][0]["priority"] == "700"
    assert cfg["bdos_profiles"][0]["params"]["inbound_traffic"] == 1000000


def test_output_is_deterministic(tmp_path, known_good):
    """The same workbook file always gives byte-identical YAML (the header carries the workbook's sha256)."""
    p = tmp_path / "wb.xlsx"
    workbook_from_config(str(p), known_good)
    a = convert_workbook(str(p), sha256_file(str(p))).outputs["dp1"].text
    b = convert_workbook(str(p), sha256_file(str(p))).outputs["dp1"].text
    assert a == b


def test_data_is_identical_for_rebuilt_workbooks(tmp_path, known_good):
    """Two separately saved workbooks with the same content differ only in the header comment."""
    a = _convert(tmp_path, known_good).outputs["dp1"]
    b = _convert(tmp_path, known_good).outputs["dp1"]
    assert a.config == b.config
    strip = lambda t: "\n".join(l for l in t.splitlines() if not l.startswith("# source sha256"))
    assert strip(a.text) == strip(b.text)


def test_group_order_and_indices_preserved_when_sheet_is_sorted(tmp_path, known_good):
    from openpyxl import load_workbook
    p = tmp_path / "wb.xlsx"
    workbook_from_config(str(p), known_good)
    wb = load_workbook(p)
    ws = wb["Network_Classes"]
    rows = [[c.value for c in r] for r in ws.iter_rows(min_row=S.FIRST_DATA_ROW, max_row=ws.max_row)]
    rows.reverse()                                               # user sorts the sheet
    for i, r in enumerate(rows, start=S.FIRST_DATA_ROW):
        for j, v in enumerate(r, start=1):
            ws.cell(row=i, column=j, value=v)
    wb.save(p)
    res = convert_workbook(str(p), sha256_file(str(p)))
    assert res.ok, res.report.render()
    for nc in res.outputs["dp1"].config["netclasses"]:
        want = next(k for k in known_good["netclasses"] if k["name"] == nc["name"])
        assert nc["groups"] == want["groups"]                    # group order (= device index) unchanged


def test_every_section_and_toggle_is_written(tmp_path, known_good):
    cfg = _convert(tmp_path, known_good).outputs["dp1"].config
    assert set(cfg) >= {"oos_profiles", "create_dns_profiles", "create_ssl_objects", "create_https_profiles"}
    assert len(cfg["security_policy_config"]) == 10
    assert cfg["security_policy_config"]["apply_policies_after_creation"] is False


def test_apply_is_false_even_when_phase_b_is_authorized(tmp_path, known_good):
    res = _convert(tmp_path, known_good, authorize_policy_apply=True, change_ticket="CHG1", authorized_by="Lead")
    assert res.ok, res.report.render()
    assert res.outputs["dp1"].config["security_policy_config"]["apply_policies_after_creation"] is False
    assert res.run_control["authorize_policy_apply"] is True


def test_generated_file_passes_yaml_check(tmp_path, known_good):
    res = _convert(tmp_path, known_good)
    rep = Report()
    check_config(yaml.safe_load(res.outputs["dp1"].text), rep)
    assert rep.ok, rep.render()


def test_oos_is_created_via_oos_profiles_key(tmp_path, known_good):
    cfg = _convert(tmp_path, known_good).outputs["dp1"].config
    assert cfg["oos_profiles"][0]["name"] == "OOS_Profile_1"
    assert cfg["oos_profiles"][0]["params"]["action"] == "block_and_report"
    assert cfg["security_policy_config"]["create_out_of_state_profiles"] is True
