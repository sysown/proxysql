"""Driver-agnostic behavior: a fresh connection can run a trivial query.

The simplest possible contract -- if this fails, nothing else in the
behavior set is meaningful for that driver/target.
"""


def run(Adapter):
    a = Adapter()
    assert a.exec_simple("SELECT 1")[0][0] == 1
    a.close()
