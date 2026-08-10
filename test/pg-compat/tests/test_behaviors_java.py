import pytest
from tests._subproc import run_behavior

PROGRAM = "/pg-compat/bin/behaviors-java"
BEHAVIORS = ["connect", "transactions", "prepared", "session_isolation"]

@pytest.mark.parametrize("behavior", BEHAVIORS, ids=BEHAVIORS)
def test_behavior_java(behavior):
    run_behavior(PROGRAM, behavior)
