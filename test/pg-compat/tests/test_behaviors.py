"""Shared, driver-agnostic behavior set run against the Python (psycopg3)
adapter. The reuse mechanism: each module under ``behaviors/`` defines a
single ``run(Adapter)`` that is written once against the small adapter
interface in ``drivers/python/adapter.py`` -- SP-3 adds Java/Go/Node
adapters and parametrizes this same behavior list over them, with zero
changes to the behavior modules themselves.
"""
import pytest

from behaviors import connect, transactions, prepared, session_isolation
from drivers.python.adapter import PsycopgAdapter

BEHAVIORS = [connect, transactions, prepared, session_isolation]


@pytest.mark.parametrize(
    "behavior", BEHAVIORS, ids=[b.__name__.split(".")[-1] for b in BEHAVIORS]
)
def test_behavior_python(behavior):
    behavior.run(PsycopgAdapter)
