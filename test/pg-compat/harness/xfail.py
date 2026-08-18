"""Loader for the pg-compat xfail / finding catalogue (test/pg-compat/xfail.toml).

Two independent sections live in that one file (see its header comment and
README.md for the full policy):

  [[xfail]]   -- known divergences that currently fail a specific test_id.
                 load() returns these; conftest.py turns each into an
                 xfail(strict=False) marker on the matching test.
  [[finding]] -- verified ProxySQL behavioral differences that do NOT
                 currently fail any test (e.g. because the harness
                 neutralizes them), so there is no test_id to attach a
                 marker to. findings() returns these for completeness /
                 tooling; nothing in conftest.py consumes them today.
"""
import os

import tomli

_XFAIL_TOML = os.path.join(os.path.dirname(__file__), "..", "xfail.toml")


def _load_toml():
    if not os.path.exists(_XFAIL_TOML):
        return {}
    with open(_XFAIL_TOML, "rb") as f:
        return tomli.load(f)


def load():
    """Return the list of [[xfail]] entries (each a dict with test_id/mode/reason/ref).

    Returns [] if xfail.toml is missing entirely.
    """
    return _load_toml().get("xfail", [])


def findings():
    """Return the list of [[finding]] entries (each a dict with summary/mode/detail/discovered_by/ref).

    Returns [] if xfail.toml is missing entirely.
    """
    return _load_toml().get("finding", [])
