"""xl2yaml - optional Excel front-end for the DefensePro create_full_config playbook.

The package converts a guided Excel workbook into per-device ``create_vars.yml``
files in exactly the format ``playbooks/create_full_config.yml`` already uses,
and adds the safety layer around running it (input selection, preflight,
isolated staging, two-phase execution with a partial-failure gate).

Nothing in this package modifies the existing playbooks or modules.
"""

__version__ = "0.3.0"
