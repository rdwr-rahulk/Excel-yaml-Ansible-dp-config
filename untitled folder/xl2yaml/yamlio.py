"""Deterministic YAML writing, loading, hashing and semantic comparison."""

from __future__ import annotations

import hashlib
from typing import Any, Iterable, List, Optional

import yaml


class _Dumper(yaml.SafeDumper):
    """Strings always double-quoted (so "100" can never turn into 100), lists indented."""

    def increase_indent(self, flow=False, indentless=False):  # noqa: D401 - PyYAML hook
        return super().increase_indent(flow, False)


def _str(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style='"')


def _dict(dumper, data):
    """Plain keys, quoted string values (keys are always simple identifiers here)."""
    pairs = []
    for k, v in data.items():
        key = yaml.ScalarNode("tag:yaml.org,2002:str", str(k)) if isinstance(k, str) else dumper.represent_data(k)
        pairs.append((key, dumper.represent_data(v)))
    return yaml.MappingNode("tag:yaml.org,2002:map", pairs, flow_style=False)


_Dumper.add_representer(str, _str)
_Dumper.add_representer(dict, _dict)


def dump(cfg: dict, header_lines: Optional[Iterable[str]] = None) -> str:
    body = yaml.dump(cfg, Dumper=_Dumper, sort_keys=False, default_flow_style=False, allow_unicode=True, width=4096)
    head = "".join(f"# {line}\n" for line in (header_lines or []))
    return "---\n" + head + body


def load(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Semantic equivalence
# --------------------------------------------------------------------------- #
UNORDERED_PATHS = {("dp_ip",)}


def semantic_diff(a: Any, b: Any, path: tuple = ()) -> List[str]:
    """Differences between two loaded YAML documents.

    Equal means: same keys, same values, same types ("100" != 100, true != 1) and
    same list order (except paths in UNORDERED_PATHS). Formatting, quoting style,
    key order and comments are ignored because they are not part of the data.
    """
    where = "/".join(str(p) for p in path) or "<root>"
    if type(a) is not type(b):
        return [f"{where}: type {type(a).__name__} != {type(b).__name__} ({a!r} vs {b!r})"]
    if isinstance(a, dict):
        out = []
        for k in sorted(set(a) | set(b), key=str):
            if k not in a:
                out.append(f"{where}/{k}: missing on the left")
            elif k not in b:
                out.append(f"{where}/{k}: missing on the right")
            else:
                out.extend(semantic_diff(a[k], b[k], path + (k,)))
        return out
    if isinstance(a, list):
        key = tuple(p for p in path if not isinstance(p, int))
        if key in UNORDERED_PATHS:
            sa = sorted(a, key=repr)
            sb = sorted(b, key=repr)
            return [] if sa == sb else [f"{where}: {a!r} != {b!r} (unordered)"]
        if len(a) != len(b):
            return [f"{where}: list length {len(a)} != {len(b)}"]
        out = []
        for i, (x, y) in enumerate(zip(a, b)):
            out.extend(semantic_diff(x, y, path + (i,)))
        return out
    return [] if a == b else [f"{where}: {a!r} != {b!r}"]
