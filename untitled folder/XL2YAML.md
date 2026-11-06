# xl2yaml – optional Excel input and safe runner for `create_full_config.yml`

`xl2yaml` lets engineers write the DefensePro configuration in an Excel workbook
instead of `vars/create_vars.yml`. It converts the workbook into one YAML file per
device, in exactly the format `playbooks/create_full_config.yml` already reads, and
wraps the run in preflight checks, an isolated staging directory and a two-phase
run with a partial-failure gate.

**Nothing in `playbooks/` or `plugins/` was changed.** Engineers who prefer YAML can
keep working exactly as before.

---

## 1. Install

```bash
pip install -r requirements-xl2yaml.txt        # openpyxl, PyYAML, pytest
cp targets/allowlist_lab.yml.example targets/allowlist_lab.yml          # then edit + commit
cp targets/allowlist_production.yml.example targets/allowlist_production.yml
```

All commands run from the repository root: `python -m xl2yaml <command>`.

## 2. Quick start

### The wizard (recommended)

```bash
python -m xl2yaml wizard
```

```
  1. Convert Excel to vars only   workbook -> generated/create_vars_<device>.yml (no device access)
  2. Dry run only                 read the YAML vars, check values and Ansible syntax (no device access)
  3. Execute                      configure: push the YAML vars to the device(s), then show a summary
  4. Full run                     1 convert -> 2 dry run -> 3 execute, stopping at the first failure
```

| Option | What it does |
|---|---|
| 1 Convert | Validates the workbook and writes `generated/create_vars_<device>.yml` + a run manifest. Nothing else. |
| 2 Dry run | Reads the YAML vars (the generated files, or `vars/create_vars.yml` in YAML mode), confirms generated files still match the workbook (`STALE` otherwise), checks every value against the modules, lists what would be configured, and runs `ansible-playbook --syntax-check` in an isolated staging copy (skipped with a note when Ansible is not installed). No device access. |
| 3 Execute | Pushes the YAML vars with the normal safe run flow (preflight, allowlist, typed device-name confirmation, Phase A, gate, read-back). If Run_Control has *Authorize Policy Apply = Yes* it asks whether to apply the policies too (Phase B). Ends with an **execution summary** per device: preflight, create, read-back and apply results, what was configured, findings and the `runs/<id>/` folder. Refuses to start if the generated files are missing or stale. |
| 4 Full run | 1 → 2 → 3, stopping at the first step that fails. |

Non-interactive use (CI, scripts): `python -m xl2yaml wizard --choice 4 --device lab-dp-01 --confirm-targets lab-dp-01 --apply no`.
Other options: `--input`, `--workbook`, `--env` (YAML mode), `--allow-ipv6`, `--skip-syntax-check`.

### Step by step

```bash
# 1. Start a workbook from the device export (or: python -m xl2yaml template -o input/defensepro_config.xlsx)
python -m xl2yaml import-export "Policy list with source, destination and Profile attached.csv" \
       --device syd1ddos04 -o input/defensepro_config.xlsx

# 2. Fill in the orange (explicit) columns the export does not contain, then:
python -m xl2yaml validate          # every error names sheet, cell and rule
python -m xl2yaml convert           # -> generated/create_vars_<device>.yml + runs/<id>/run_manifest.json

# 3. Commit generated/*.yml, open a PR. CI runs (no device access):
python -m xl2yaml ci --syntax-check

# 4. Lab: create objects with apply OFF, gate, read-back
python -m xl2yaml run --device lab-dp-01 --phase A
# 5. After approval (Run_Control: Authorize Policy Apply = Yes + Change Ticket + Authorized By)
python -m xl2yaml run --device lab-dp-01 --phase B --after-run <run id from step 4>
```

## 3. Excel or YAML?

| Situation | Behaviour | Log line |
|---|---|---|
| No workbook at `input/defensepro_config.xlsx` | **YAML mode**: `vars/create_vars.yml` is used as today | `[INPUT] mode=YAML source=vars/create_vars.yml sha256=…` |
| Workbook present | **Excel mode**: YAML generated from the workbook; `vars/create_vars.yml` is ignored, never merged | `[INPUT] mode=EXCEL …` and `[INPUT] vars/create_vars.yml present but IGNORED` |
| Workbook present but invalid | Run stops. **No fallback to YAML.** | `RESULT: FAILED_VALIDATION` |
| Two workbooks, or a differently named one | Run stops (ambiguous) | `[INPUT] input is AMBIGUOUS …` |
| `--input excel` / `--input yaml` | Forces the mode | `mode=… (forced)` |

Every run writes `runs/<run id>/run_manifest.json` (input mode, path, SHA-256,
template version, generated file hashes, target, toggles, authorization,
preflight checks, gate results) and `runs/<run id>/xl2yaml.log`.

YAML mode still goes through the same safety layer when you use `xl2yaml run`.
Pass `--env` and `--device`; the IP comes from the allowlist and the staged copy
is limited to that one device (the file on disk is not changed).

## 4. What the code review of the modules found

These behaviours drove the validation rules. The converter therefore rejects every
unknown value and requires explicit values where a default could widen protection.

| Module | Behaviour if a value is omitted or unknown |
|---|---|
| `create_cl_configuration.py` | omitted `app_port_group` → `""` (**all ports**); unknown `action` → `drop`; unknown `tracking_type` → `dst_ip`; omitted `threshold` → `50` |
| `create_traffic_filter.py` | unknown `protocol` → `any`; unknown profile `action` → `block_and_report`; omitted TCP flags → `enable`; omitted `status` → `enable` |
| `create_full_config.py` | unknown policy `action` → block; unknown `state` → enable; unknown `direction` → oneway |
| `create_bdos_profile.py`, `create_oos_profile.py` | unknown parameter keys are **silently ignored** |
| `create_network_class.py` | partial failure returns **warnings**, not a failure; group index = list position |
| `create_full_config.yml` | `apply_policies_after_creation \| default(true)`; OOS reads `oos_profiles` (missing from the example YAML) |
| `update_policies.yml` | `continue_on_error \| default(true)` → `ignore_errors` |

## 5. The workbook (template v0.4)

Every sheet starts with a **description row (row 1)** that says what the sheet is
for and how to fill it. Column headers are on row 2; data starts on row 3. Do not
delete or move rows 1–2. Workbooks from template v0.3 must be regenerated.

| Sheet | One row per | YAML |
|---|---|---|
| Devices | device | `dp_ip` (one IP per generated file) |
| Run_Control | setting | `security_policy_config` (all toggles written), environment, change ticket, approver, authorization for Phase B |
| Policies | policy per device | `create_security_policies` |
| Network_Classes | group (Group Index, Address, Mask) | `netclasses` (groups ordered by Group Index) |
| CL_Protections / CL_Profile_Members | protection / profile link | `cl_protections` / `cl_profiles` |
| TF_Profiles / TF_Rules | profile / rule | `create_tf_profiles` / `create_tf_protections` |
| OOS_Profiles | profile | `oos_profiles` |
| BDoS_Profiles | profile | `bdos_profiles` |
| External_References | object already on the device | nothing; reported as UNVERIFIED |
| DNS_Profiles, SYN_* (grey) | – | reference only, never converted |

**Run_Control** uses readable names and Yes/No values:

| Setting (column A) | Value (column B) | YAML / internal key |
|---|---|---|
| Create Network Classes | Yes / No | `create_network_classes` |
| Create Connection Limit Profiles | Yes / No | `create_cl_profiles` |
| Create Out of State Profiles | Yes / No | `create_out_of_state_profiles` |
| Create BDoS Profiles | Yes / No | `create_bdos_profiles` |
| Create DNS Profiles | must be No | `create_dns_profiles` |
| Create HTTPS Flood Profiles | must be No | `create_https_profiles` |
| Create Traffic Filter Profiles | Yes / No | `create_traffic_filter_profiles` |
| Create SSL Objects | must be No | `create_ssl_objects` |
| Create Security Policies | Yes / No | `create_security_policies` |
| Authorize Policy Apply | Yes / No | `authorize_policy_apply` (authorizes Phase B, never written to the YAML) |
| Environment | lab / production | `environment` |
| Change Ticket / Authorized By | text | `change_ticket` / `authorized_by` |

Yes/No are written to the YAML as `true`/`false`. Any other value (including the
old `TRUE`/`FALSE`) is rejected with `TOGGLE_NOT_BOOL`.

**Why External_References exists.** A policy (or CL profile / TF rule) can refer
to an object that this workbook does not create: Signature, EAAF, Geolocation, SYN
Flood, DNS and HTTPS Flood profiles (no creation module in the POC), or objects
created earlier. Without this sheet the converter could not tell an intentional
reference to an existing object from a typo, and a typo would only surface when the
device rejects the policy halfway through a run. So every referenced name must be
either defined on its own sheet or declared here (`UNRESOLVED_REF` otherwise).
Declared objects are listed as UNVERIFIED in the report; nothing is created from
this sheet. Leave it empty when every referenced object is created by the workbook.

Header colours: **navy** required · **orange** explicit (default would widen
protection or change enforcement) · **blue** optional (blank → module/device
default, listed in the report) · **grey** not converted · **green** Excel check.

Rules worth knowing:
* Blank always means "not set". To write `app_port_group: ""` choose `(all ports)`.
* `Mask` is written exactly as typed (`24` or `255.255.255.0`).
* Dropdowns can be bypassed by pasting – everything is re-checked.
* Formulas, dates, decimals in whole-number fields, invisible spaces, merged or
  hidden cells, unknown sheets/columns, and old template versions are rejected.
* IPv6 network groups are rejected unless `--allow-ipv6` (support not confirmed).
* The generated YAML always has `apply_policies_after_creation: false`.
  *Authorize Policy Apply* in Run_Control authorizes the separate Phase B run.

## 6. Safety model of `xl2yaml run`

1. **Input selection and validation** (section 3). Errors stop the run.
2. **Staging** – `.xl2yaml_staging/<run>_<device>_<phase>/` (mode 0700) with a
   read-only copy of `playbooks/` and `plugins/`, a generated `ansible.cfg`, the
   inventory, `vars/cc.yml`, and only the vars file for this phase. Whole-file
   replacement – never merged with an old `create_vars.yml`. Inherited `ANSIBLE_*`
   environment variables are dropped. The directory (including cached CC session
   cookies) is deleted after the run.
3. **Preflight** (blocks before Ansible starts):
   one IP in `dp_ip`; IP and name on `targets/allowlist_<env>.yml`; IP not on the
   other environment's allowlist; `vars/cc.yml` points to that environment's
   controller; inventory defines `cc` and sets no other variables; no
   `group_vars`/`host_vars`; staged file hash equals the reviewed file; toggles
   explicit, unsupported sections off, apply off; change ticket + approver for
   production and Phase B; the operator types the device name (or CI passes
   `--confirm-targets`).
4. **Phase A** – `create_full_config.yml` with apply off. A recorder callback
   (`xl2yaml/ansible_plugins/xl2yaml_recorder.py`) captures every task and loop
   item (password scrubbed).
5. **Gate** – fails on any failed task, any warning not on
   `targets/benign_warnings.yml`, any module error list, `failed_groups > 0`,
   any count different from what was generated, a module that should have run but
   did not (or the reverse), any item for another device, `update_policies`
   running in Phase A, or lock/unlock not completing.
6. **Read-back** – `get_network_class.yml` and a group-by-group comparison
   (index, address, prefix). Other sections: verify with the `get_*` playbooks.
7. **Phase B** – only with authorization and a passed Phase A for the *same
   configuration data*: `update_policies.yml` with `target_devices: [ip]`,
   `continue_on_error: false`. Gate requires `status: success` and no warnings.

`--preview` runs Phase A with `--check` (modules report planned operations). It
is not used as safety evidence. The real device test is the isolated lab.

## 7. Commands

| Command | Purpose |
|---|---|
| `wizard [--choice 1-4]` | menu: 1 convert only, 2 dry run, 3 execute + summary, 4 full run |
| `template -o FILE` | blank workbook generated from the schema |
| `import-export CSV --device NAME -o FILE` | workbook pre-filled from the device export |
| `validate` | validate the selected input, write nothing |
| `convert [--device NAME] [--out-dir DIR]` | write `generated/create_vars_<device>.yml` |
| `check-yaml FILE…` | check any create_vars YAML against the modules (PR check) |
| `compare A B` | semantic equivalence (keys, values, types, order) |
| `ci [--syntax-check]` | PR checks: YAML checks, re-convert + compare, determinism, `--syntax-check` with placeholder connection files |
| `json-schema -o FILE` | JSON Schema for editing YAML directly in VS Code |
| `run --device NAME --phase A\|B\|AB` | preflight + two-phase run on one device |

## 8. Tests

```bash
python -m pytest tests/xl2yaml -q
```

123 tests, no device or network needed (a fake `ansible-playbook` simulates
results – a `.cmd` shim on Windows; two tests use real Ansible for staging isolation and `--syntax-check`
when it is installed).

| POC acceptance test (architecture doc §14) | Tests |
|---|---|
| 1 Fields preserved | `test_fidelity.py::test_known_good_survives_excel_path`, `test_types_are_preserved` |
| 2 Deterministic, compatible | `test_output_is_deterministic`, `ci --syntax-check` test |
| 3 Cell-level errors | `test_negative.py` (41 cases) |
| 4 Nothing passes silently | `test_negative.py`, `test_yaml_check.py` |
| 5 Explicit scope-widening fields | `test_negative.py` blank App Port Group / CL action / TCP flags … |
| 6 Mapping matches modules | `test_oos_is_created_via_oos_profiles_key`, `test_group_order_and_indices_preserved_when_sheet_is_sorted` |
| 7 Excel optional, input logged | `test_input_select.py`, `test_runflow.py::test_invalid_workbook_never_falls_back_to_yaml` |
| 8 Only intended devices | `test_preflight_staging.py::test_preflight_blocks[*]`, `test_runflow.py::test_target_not_on_allowlist_never_runs` |
| 9 Orchestration explicit | `test_every_section_and_toggle_is_written`, `test_runflow.py::test_phase_b_refused_without_authorization` |
| 10 No stale variables | `test_staging_never_inherits_a_stale_create_vars`, `test_real_ansible_sees_only_the_generated_values` |
| 11 Partial failure stops the run | `test_gate.py`, `test_runflow.py::test_partial_failure_stops_before_apply` |
| 12 Lab changes match intent | read-back in `test_runflow.py`; real lab run in POC week 4 |

## 9. Known limitations (POC)

* DNS, HTTPS and SSL sections are not generated; their toggles must be false.
* No SYN-profile creation module exists in the repository; SYN profiles are external references.
* Read-back is implemented for network classes only.
* External references are declared, not verified against the device (reported as UNVERIFIED).
* `benign_warnings.yml` is empty: any module warning fails the gate until reviewed.
* IPv6 network groups need `--allow-ipv6` once module support is confirmed.
* The workbook → YAML direction only; YAML → Excel export is Phase 2.
