"""Emit a JSON Schema for create_vars.yml from the same schema (the "edit YAML directly" path).

Use it with the VS Code YAML extension, e.g. in .vscode/settings.json:
    "yaml.schemas": {"./create_vars.schema.json": ["vars/create_vars.yml", "generated/*.yml"]}
Cross-object rules (references, Group Index, explicit TCP flags) still need
``python -m xl2yaml check-yaml``; JSON Schema cannot express them.
"""

from __future__ import annotations

import json
from typing import Dict

from . import schema as S
from .yaml_check import SHEET_FOR_SECTION, TCP_FLAG_YAML_KEYS, TF_EXTRA_KEYS


def _prop(f: S.Field) -> Dict:
    d: Dict = {"description": (f.note + " " if f.note else "") + (f"[{f.cls}] " if f.cls else "") + f.source}
    if f.kind == "enum":
        d["enum"] = sorted(set(f.module_values) | ({v.upper() for v in f.module_values} if f.case_insensitive else set()))
    elif f.kind in ("int",):
        d["type"] = ["integer", "string"]
    elif f.kind == "numeric_string":
        d["type"] = ["string", "integer"]
    else:
        d["type"] = "string"
    if f.minimum is not None and f.kind in ("int", "numeric_string"):
        d["x-minimum"] = f.minimum
    if f.maximum is not None and f.kind in ("int", "numeric_string"):
        d["x-maximum"] = f.maximum
    return d


def _item(spec: S.SheetSpec, section: str) -> Dict:
    top = {f.key: f for f in spec.fields if f.key and not f.in_params and f.cls not in (S.KEY, S.INFO, S.CHECK)}
    top.pop("tcp_flags", None)
    params = {f.key: f for f in spec.fields if f.in_params}
    props = {k: _prop(f) for k, f in top.items()}
    required = [k for k, f in top.items() if f.cls in (S.REQUIRED, S.EXPLICIT)]
    if section == "create_tf_protections":
        for k in TCP_FLAG_YAML_KEYS:
            props[k] = {"enum": ["enable", "disable"]}
        for k in TF_EXTRA_KEYS:
            props[k] = {"type": "string"}
    if params:
        props["params"] = {"type": "object", "additionalProperties": False,
                           "properties": {k: _prop(f) for k, f in params.items()},
                           "required": [k for k, f in params.items() if f.cls in (S.REQUIRED, S.EXPLICIT)]}
        required.append("params")
    return {"type": "object", "additionalProperties": False, "properties": props, "required": required}


def build() -> Dict:
    props: Dict = {
        "dp_ip": {"type": "array", "minItems": 1, "items": {"type": "string"}},
        "netclasses": {"type": "array", "items": {
            "type": "object", "additionalProperties": False, "required": ["name", "groups"],
            "properties": {"name": {"type": "string"}, "groups": {"type": "array", "items": {
                "type": "object", "additionalProperties": False, "required": ["address", "mask"],
                "properties": {"address": {"type": "string"}, "mask": {"type": ["string", "integer"]}}}}}}},
        "cl_profiles": {"type": "array", "items": {
            "type": "object", "additionalProperties": False, "required": ["name", "protections"],
            "properties": {"name": {"type": "string"}, "protections": {"type": "array", "items": {"type": "string"}}}}},
        "security_policy_config": {"type": "object", "additionalProperties": False, "required": list(S.TOGGLES),
                                   "properties": {t: {"type": "boolean"} for t in S.TOGGLES}},
    }
    for section, spec in SHEET_FOR_SECTION.items():
        props[section] = {"type": "array", "items": _item(spec, section)}
    for section in ("create_dns_profiles", "create_ssl_objects", "create_https_profiles"):
        props[section] = {"type": "array", "description": "Not generated or validated by the POC"}
    return {"$schema": "http://json-schema.org/draft-07/schema#", "title": "create_vars.yml (create_full_config.yml)",
            "type": "object", "additionalProperties": False, "required": ["dp_ip", "security_policy_config"],
            "properties": props}


def write(path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(build(), fh, indent=2)
