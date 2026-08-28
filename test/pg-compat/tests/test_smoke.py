"""Wiring smoke tests for the pg-compat harness.

These prove: the pytest container reaches the ProxySQL PG frontend (6133)
and the ProxySQL admin over the PG protocol (6132) on the infra's backend
network, and the admin config primitive (snapshot/set/load/restore) works.
"""


def test_proxy_select_one(proxy_conn):
    with proxy_conn.cursor() as cur:
        cur.execute("SELECT 1")
        assert cur.fetchone()[0] == 1


def test_admin_reconfig_roundtrip(admin):
    saved = admin.snapshot(["pgsql-authentication_method"])
    try:
        admin.set_var("pgsql-authentication_method", 1)
        admin.load_vars()
        val = admin.query(
            "SELECT variable_value FROM global_variables "
            "WHERE variable_name='pgsql-authentication_method'"
        )
        assert val[0][0] == "1"
    finally:
        # Must run even if the assertion above fails, so the suite never
        # leaks state into a subsequent run.
        admin.restore(saved)
