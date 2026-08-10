"""Driver-agnostic behavior: BEGIN/COMMIT/ROLLBACK are honored end-to-end
through ProxySQL.

Read-after-write through the RW-split (trap, see SP-1 lessons folded into
this SP-2 task): the infra routes a bare ``^SELECT`` to a READER hostgroup.
``INSERT ... COMMIT`` followed by a bare ``SELECT count(*)`` would send the
verification read to a replica, where the freshly committed row may not be
visible yet (streaming replication lag) -- a flake that has nothing to do
with transaction semantics.

Fix applied here: every verification read runs inside its own explicit
``begin()``/``commit()`` pair. ``BEGIN`` does not match ``^SELECT``, so it
takes the default hostgroup (the writer); ProxySQL then keeps that
transaction pinned to the same backend connection until it commits, so the
SELECT inside it is also pinned to the writer -- the same connection that
just did the INSERT/COMMIT, so there is no cross-node replication lag to
race. This was verified empirically against the oracle (see the task
report): the verify-SELECT below carries a distinctive column alias
(``AS verify_read``) precisely so it can be isolated in
``pg_stat_statements`` and proven to land only on the primary, never a
replica.
"""

TABLE = "behavior_tx_t"


def run(Adapter):
    a = Adapter()
    try:
        a.exec_simple(f"DROP TABLE IF EXISTS {TABLE}")
        a.exec_simple(f"CREATE TABLE {TABLE} (id int)")

        a.begin()
        a.exec_simple(f"INSERT INTO {TABLE} VALUES (1)")
        a.rollback()

        a.begin()
        count = a.exec_simple(f"SELECT count(*) AS verify_read FROM {TABLE}")[0][0]
        a.commit()
        assert count == 0, "rollback did not discard the insert"

        a.begin()
        a.exec_simple(f"INSERT INTO {TABLE} VALUES (2)")
        a.commit()

        a.begin()
        count = a.exec_simple(f"SELECT count(*) AS verify_read FROM {TABLE}")[0][0]
        a.commit()
        assert count == 1, "commit did not persist the insert"
    finally:
        # Leave no state behind, whether or not the assertions above passed,
        # and use a table name distinct from other behaviors/tests
        # (tests/test_routing_oracle.py's own probe table is "oracle_w") so
        # runs never collide.
        #
        # Roll back first: if any statement above raised between begin() and
        # commit(), the session is left in PostgreSQL's aborted-transaction
        # state, where DROP TABLE fails with "current transaction is aborted"
        # -- so the table would leak AND the cleanup error would mask the real
        # failure. The rollback is best-effort for the same reason.
        try:
            a.rollback()
        except Exception:
            pass
        try:
            a.exec_simple(f"DROP TABLE IF EXISTS {TABLE}")
        finally:
            a.close()
