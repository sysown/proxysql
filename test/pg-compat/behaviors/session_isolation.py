"""Driver-agnostic behavior: session state set on one connection must not
leak to a different connection.

Trap avoided here (folded in from SP-1's lessons, ahead of the original
brief which probed ``application_name``): ProxySQL explicitly lists
``application_name`` in ``ignore_vars`` (see ``lib/PgSQL_Variables.cpp``) --
it is never forwarded to or tracked against the backend, which hardcodes
``application_name = 'proxysql'`` on its own server connections. That means
``SHOW application_name`` can NEVER reflect a client ``SET``, through
ProxySQL, and a probe built on it would fail for a reason that has nothing
to do with session isolation. This behavior instead probes ``TimeZone``,
which IS a tracked/forwarded/reset variable (``pgsql_tracked_variables[]``
in ``include/proxysql_structs.h``) -- the same swap validated by SP-1's
pool-churn TAP test.

Structure: connection A sets the distinctive value and asserts it, then
CLOSES before connection B ever opens. This makes backend-connection reuse
between A and B at least *possible* (A's backend connection is free by the
time B asks for one), so this behavior is testing the real cross-driver
contract: IF B happens to land on the same physical backend connection A
just released, ProxySQL must have reset/not-inherited A's session state.
Note for anyone tightening this later: a trivial pass is possible here if B
lands on a *different* backend than A (then there was never any shared
state to leak in the first place) -- this is an inherent limitation of a
black-box, connection-pool-driven probe run against a live multi-backend
pool where which physical backend serves which client session is not
observable/controllable from here. The deterministic, single-backend
variant (that forces A and B onto the very same backend and proves the
reset explicitly) lives in SP-1's TAP test; this behavior's job is only to
exercise the same contract identically across every driver adapter (Python
here, Java/Go/Node in SP-3).
"""

DISTINCTIVE_TZ = "Antarctica/Troll"


def run(Adapter):
    a = Adapter()
    b = None
    try:
        a.exec_simple(f"SET TimeZone = '{DISTINCTIVE_TZ}'")
        assert a.exec_simple("SHOW TimeZone")[0][0] == DISTINCTIVE_TZ
        # Close A before B opens (deliberate -- see module docstring): this
        # keeps A's backend connection possibly free by the time B asks for
        # one. The `finally` below closes A again as a resource-hygiene
        # backstop on an assert failure above; the adapter's close() is
        # idempotent so that repeat call is a safe no-op.
        a.close()

        b = Adapter()
        val = b.exec_simple("SHOW TimeZone")[0][0]
        assert val != DISTINCTIVE_TZ, "session state leaked across connections"
    finally:
        a.close()
        if b is not None:
            b.close()
