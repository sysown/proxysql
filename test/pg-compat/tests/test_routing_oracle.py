"""Routing oracle: prove *where* a query actually landed by reading each
backend node's own ``pg_stat_statements`` (harness/oracle.py), rather than
trusting ProxySQL's own reporting of what it routed.

IMPORTANT subtlety (do not "fix" by routing verification reads through the
proxy): a verification query like ``SELECT count(*) FROM pg_stat_statements``
issued THROUGH the proxy would itself match the ``^SELECT`` reader rule and
get routed to a replica, polluting the very counts being inspected. So
``oracle.calls_for()`` connects directly to each backend node (as the
sandbox superuser -- see harness/oracle.py docstring for why), never through
ProxySQL.
"""
from harness import oracle

# Real (not TEMP) table: a TEMP table's DDL/DML still executes against
# whichever hostgroup the statement is routed to under the ^SELECT rule
# (write statements -> writer), but a TEMP table would never physically
# replicate to the readers even if a read against it were misrouted there --
# which would silently launder a real routing bug. A REAL table makes a
# leaked read-on-replica or leaked write-on-replica actually observable via
# pg_stat_statements. Dropped at the end of the test for idempotency across
# repeated runs and across the differential suite (see run-pg-compat.bash).
WRITE_TABLE = "oracle_w"


def test_select_lands_on_a_reader(proxy_conn):
    oracle.reset_all()
    with proxy_conn.cursor() as cur:
        for _ in range(20):
            cur.execute("SELECT 42 AS oracle_probe")
            cur.fetchone()
    counts = oracle.calls_for("%oracle_probe%")
    # read/write split: SELECTs must hit readers (replicas), never the
    # primary/writer.
    assert counts["primary"] == 0, f"SELECT hit the primary: {counts}"
    assert counts["replica1"] + counts["replica2"] == 20, (
        f"reads not fully accounted for on the replicas: {counts}"
    )


def test_write_pins_to_primary(proxy_conn):
    oracle.reset_all()
    try:
        with proxy_conn.cursor() as cur:
            cur.execute(f"CREATE TABLE IF NOT EXISTS {WRITE_TABLE} (id int)")
            cur.execute(f"INSERT INTO {WRITE_TABLE} VALUES (1)")
        counts = oracle.calls_for(f"%{WRITE_TABLE}%")
        assert counts["replica1"] == 0 and counts["replica2"] == 0, (
            f"write leaked to a replica: {counts}"
        )
        assert counts["primary"] > 0, (
            f"write did not land on the primary at all: {counts}"
        )
    finally:
        # Always drop, even on assertion failure, so the table never leaks
        # into the differential/selfcheck suites or a re-run of this test.
        with proxy_conn.cursor() as cur:
            cur.execute(f"DROP TABLE IF EXISTS {WRITE_TABLE}")
