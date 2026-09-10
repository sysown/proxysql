#!/usr/bin/env python3
import json
from pathlib import Path


GROUPS = Path(__file__).with_name("groups.json")
UNIT_SOURCES = GROUPS.parents[1] / "tests" / "unit"


def test_mysqlx_and_plugin_units_have_mysqlx_g1():
    groups = json.loads(GROUPS.read_text(encoding="utf-8"))
    expected = {
        source.stem
        for source in UNIT_SOURCES.glob("*_unit-t.cpp")
        if source.name.startswith(("mysqlx_", "plugin_"))
    }
    selected = {name for name, tags in groups.items() if "mysqlx-g1" in tags}

    assert expected <= groups.keys()
    assert expected <= selected
    assert "test_mysqlx_e2e_handshake-t" not in selected
    assert "test_mysqlx_soak_behavioral-t" not in selected


if __name__ == "__main__":
    test_mysqlx_and_plugin_units_have_mysqlx_g1()
