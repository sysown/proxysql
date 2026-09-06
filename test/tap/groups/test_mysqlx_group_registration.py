#!/usr/bin/env python3
import json
from pathlib import Path


GROUPS = Path(__file__).with_name("groups.json")


def test_mysqlx_and_plugin_units_have_mysqlx_g1():
    groups = json.loads(GROUPS.read_text(encoding="utf-8"))
    expected = {
        name
        for name in groups
        if (name.startswith("mysqlx_") or name.startswith("plugin_"))
        and name.endswith("_unit-t")
    }
    selected = {name for name, tags in groups.items() if "mysqlx-g1" in tags}

    assert expected <= selected
    assert "test_mysqlx_e2e_handshake-t" not in selected
    assert "test_mysqlx_soak_behavioral-t" not in selected


if __name__ == "__main__":
    test_mysqlx_and_plugin_units_have_mysqlx_g1()
