# Ansible callback used only inside xl2yaml staging directories.
"""Records every task and loop-item result to a JSON file for the xl2yaml result gate.

The normal screen output is unchanged (this is an aggregate callback, not a
stdout callback). Module invocations are scrubbed so the provider password
never reaches the file.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
name: xl2yaml_recorder
type: aggregate
short_description: Record task results for the xl2yaml result gate
description:
  - Writes task and loop-item results to the file named by XL2YAML_RESULTS_FILE.
requirements:
  - enabled via callbacks_enabled in the xl2yaml-generated ansible.cfg
"""

import json
import os

from ansible.plugins.callback import CallbackBase

_SCRUB_KEYS = {"invocation", "password", "_ansible_no_log"}


def _scrub(value):
    if isinstance(value, dict):
        return {k: _scrub(v) for k, v in value.items() if k not in _SCRUB_KEYS}
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    return value


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "aggregate"
    CALLBACK_NAME = "xl2yaml_recorder"
    CALLBACK_NEEDS_ENABLED = True

    def __init__(self, *args, **kwargs):
        super(CallbackModule, self).__init__(*args, **kwargs)
        self._path = os.environ.get("XL2YAML_RESULTS_FILE")
        self._records = []

    def _record(self, status, result, item_level, ignore_errors=False):
        task = result._task
        res = _scrub(dict(result._result))
        if status == "ok" and res.get("changed"):
            status = "changed"
        self._records.append({
            "status": status,
            "item_level": item_level,
            "task": task.get_name(),
            "action": getattr(task, "resolved_action", None) or task.action,
            "host": result._host.get_name(),
            "item": res.get("item") if item_level else None,
            "ignore_errors": bool(ignore_errors or getattr(task, "ignore_errors", False)),
            "result": res,
        })

    # task level
    def v2_runner_on_ok(self, result):
        self._record("ok", result, False)

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self._record("failed", result, False, ignore_errors)

    def v2_runner_on_skipped(self, result):
        self._record("skipped", result, False)

    def v2_runner_on_unreachable(self, result):
        self._record("unreachable", result, False)

    # loop items
    def v2_runner_item_on_ok(self, result):
        self._record("ok", result, True)

    def v2_runner_item_on_failed(self, result):
        self._record("failed", result, True)

    def v2_runner_item_on_skipped(self, result):
        self._record("skipped", result, True)

    def v2_playbook_on_stats(self, stats):
        summary = {h: stats.summarize(h) for h in sorted(stats.processed.keys())}
        if self._path:
            with open(self._path, "w") as fh:
                json.dump({"records": self._records, "stats": summary}, fh, indent=1, default=str)
