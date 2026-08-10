import pytest
from tests._subproc import run_behavior

PROGRAM = "/pg-compat/bin/behaviors-prisma"
BEHAVIORS = ["connect", "transactions", "prepared", "session_isolation"]

@pytest.mark.parametrize("behavior", BEHAVIORS, ids=BEHAVIORS)
def test_behavior_prisma(behavior):
    run_behavior(PROGRAM, behavior)
