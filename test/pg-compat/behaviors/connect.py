"""Driver-agnostic behavior: a fresh connection can run a trivial query.

The simplest possible contract -- if this fails, nothing else in the
behavior set is meaningful for that driver/target.
"""


def run(Adapter):
    a = Adapter()
    try:
        assert a.exec_simple("SELECT 1")[0][0] == 1
        # Uniform with the four SP-3 driver ports (go/java/node/prisma):
        # assert the client_encoding=UTF8 pin took effect -- see
        # harness/targets.py's encoding rationale (backend DBs default to
        # SQL_ASCII; ProxySQL imposes UTF8).
        assert a.exec_simple("SHOW client_encoding")[0][0] == "UTF8"
    finally:
        a.close()
