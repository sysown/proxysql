import pytest
from tests._subproc import run_behavior

PROGRAM = "/pg-compat/bin/behaviors-java"
BEHAVIORS = ["connect"]   # Tasks 2-4 extend per language

@pytest.mark.parametrize("behavior", BEHAVIORS, ids=BEHAVIORS)
def test_behavior_java(behavior):
    run_behavior(PROGRAM, behavior)
