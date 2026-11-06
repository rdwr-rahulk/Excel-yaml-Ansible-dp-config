#!/usr/bin/env python3
"""TEST-ONLY stand-in for ansible-playbook.

Reads the staged vars exactly like the real playbooks do and writes results in the
format of xl2yaml's recorder callback. FAKE_MODE selects a scenario:
  ok | partial_nc | fail_bdos | apply_unclear | apply_ran_in_a
Every call is appended to FAKE_CALLS so tests can prove what did (not) run.
"""

import json
import os
import sys

import yaml

MODULES = [
    ("create_network_class", "create_network_classes"),
    ("create_cl_configuration", "create_cl_profiles"),
    ("create_oos_profile", "create_out_of_state_profiles"),
    ("create_bdos_profile", "create_bdos_profiles"),
    ("create_dns_profile", "create_dns_profiles"),
    ("create_ssl_object", "create_ssl_objects"),
    ("create_https_profile", "create_https_profiles"),
    ("create_traffic_filter", "create_traffic_filter_profiles"),
    ("create_full_config", "create_security_policies"),
]


def item(action, ip, status="ok", result=None, task=None):
    r = dict(result or {})
    r["item"] = ip
    return {"status": status, "item_level": True, "task": task or action, "action": action, "host": "cc",
            "item": ip, "ignore_errors": False, "result": r}


def main():
    args = sys.argv[1:]
    playbook = os.path.basename(args[0])
    mode = os.environ.get("FAKE_MODE", "ok")
    state_path = os.environ["FAKE_STATE"]
    state = json.load(open(state_path)) if os.path.exists(state_path) else {}
    with open(os.environ["FAKE_CALLS"], "a") as fh:
        fh.write(json.dumps({"playbook": playbook, "args": args, "cwd": os.getcwd(),
                             "vars": sorted(os.listdir("vars"))}) + "\n")
    if "--syntax-check" in args:
        print("playbook: " + args[0])
        return 0
    records, failures = [], 0

    if playbook == "create_full_config.yml":
        cfg = yaml.safe_load(open("vars/create_vars.yml"))
        spc = cfg["security_policy_config"]
        for ip in cfg["dp_ip"]:
            records.append(item("dp_lock", ip))
            for action, toggle in MODULES:
                if not spc.get(toggle):
                    records.append(item(action, ip, "skipped"))
                    continue
                if action == "create_network_class":
                    groups = [(nc["name"], i, g["address"], g["mask"]) for nc in cfg["netclasses"]
                              for i, g in enumerate(nc["groups"])]
                    ok = groups[:-1] if mode == "partial_nc" and groups else groups
                    res = {"changed": True, "response": {"created_groups": [], "errors": [],
                           "summary": {"total_groups_attempted": len(groups), "successful_groups": len(ok),
                                       "failed_groups": len(groups) - len(ok)}}}
                    if mode == "partial_nc":
                        res["warnings"] = ["Failed to create network group 'x[9]': HTTP 500"]
                        res["response"]["errors"] = res["warnings"]
                    state.setdefault(ip, [])
                    state[ip] += [list(g) for g in ok]
                elif action == "create_cl_configuration":
                    res = {"response": {"created_protections": [{}] * len(cfg["cl_protections"]),
                                        "created_profiles": [{}] * sum(len(p["protections"]) for p in cfg["cl_profiles"])}}
                elif action == "create_oos_profile":
                    res = {"response": {"errors": [], "summary": {"successful_profiles": len(cfg["oos_profiles"])}}}
                elif action == "create_bdos_profile":
                    if mode == "fail_bdos":
                        records.append(item(action, ip, "failed", {"msg": "BDoS profile creation completed with 1 error(s)."}))
                        failures += 1
                        break
                    res = {"response": {"errors": [], "summary": {"successful_profiles": len(cfg["bdos_profiles"])}}}
                elif action == "create_traffic_filter":
                    res = {"response": {"errors": [], "summary": {"successful_profiles": len(cfg["create_tf_profiles"]),
                                                                  "successful_protections": len(cfg["create_tf_protections"])}}}
                elif action == "create_full_config":
                    res = {"response": {"errors": [], "summary": {"successful_policies": len(cfg["create_security_policies"])}}}
                else:
                    res = {}
                records.append(item(action, ip, "changed", res))
            apply = spc.get("create_security_policies") and spc.get("apply_policies_after_creation", True)
            if mode == "apply_ran_in_a":
                apply = True
            records.append(item("update_policies", ip, "changed" if apply else "skipped",
                                {"response": {"status": "success"}} if apply else {}))
            records.append(item("dp_unlock", ip))
    elif playbook == "update_policies.yml":
        uv = yaml.safe_load(open("vars/update_vars.yml"))
        if uv["update_settings"].get("continue_on_error") is not False:
            print("FAKE: continue_on_error must be false")
            return 9
        for ip in uv["target_devices"]:
            records.append(item("dp_lock", ip))
            resp = {"status": "success", "message": "ok"}
            if mode == "apply_unclear":
                resp["warnings"] = ["API response does not provide clear success confirmation - verify policy status manually"]
            records.append(item("update_policies", ip, "changed", {"response": resp}))
            records.append(item("dp_unlock", ip))
    elif playbook == "get_network_class.yml":
        gv = yaml.safe_load(open("vars/get_vars.yml"))
        for ip in gv["dp_ip"]:
            table = [{"rsBWMNetworkName": n, "rsBWMNetworkSubIndex": str(i), "rsBWMNetworkAddress": a,
                      "rsBWMNetworkMask": m} for n, i, a, m in state.get(ip, []) if n in gv["filter_class_names"]]
            records.append(item("get_network_class", ip, "ok", {"response": {"rsBWMNetworkTable": table}}))
    json.dump(state, open(state_path, "w"))
    with open(os.environ["XL2YAML_RESULTS_FILE"], "w") as fh:
        json.dump({"records": records, "stats": {"cc": {"ok": len(records), "failures": failures, "unreachable": 0}}}, fh)
    return 2 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
