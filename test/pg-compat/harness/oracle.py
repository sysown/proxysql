"""Routing oracle: prove WHERE a query landed by reading each backend node's
own ``pg_stat_statements`` view.

Design (a) from the task brief's two options: connect to every backend as
the sandbox **superuser** (``postgres``), not as ``testuser``. Two reasons:

  * ``pg_stat_statements_reset()`` requires superuser (or an explicit
    ``GRANT EXECUTE``); ``testuser`` has neither. Rather than add a second
    no-reset baseline-delta design (option (b)), connecting as ``postgres``
    keeps the API a simple reset()/calls_for() pair, matching the brief.
  * The superuser sees ALL sessions' statements on that node (not just its
    own), which matters here because the workload runs through ProxySQL as
    ``testuser`` while the oracle needs a clear, unfiltered view.

The password is NOT a fixed/default credential: the infra entrypoint
(test/infra/infra-dbdeployer-pgsql17-repl/docker/entrypoint.sh) sets
``ALTER ROLE postgres WITH PASSWORD '${ROOT_PASSWORD}'`` where
``ROOT_PASSWORD=$(echo -n "${INFRA_ID}" | sha256sum | head -c 10)`` (see
docker-compose-init.bash). ``run-pg-compat.bash`` already forwards
``INFRA_ID`` into the pytest container (``-e INFRA_ID``), so the same
derivation is reproduced here in Python rather than requiring a new env
var or touching the infra entrypoint.

Verified live against sdd-sp2: connecting as
``postgres`` / ``sha256("sdd-sp2")[:10]`` to each of the three per-node
DSNs (host+port from PGCOMPAT_{PRIMARY,REPLICA1,REPLICA2}_{HOST,PORT} --
there is no single PGCOMPAT_BACKEND_PORT, see harness/targets.py) succeeds,
``pg_stat_statements_reset()`` runs, and a probe query
``SELECT 42 AS oracle_probe`` is normalized by pg_stat_statements to
``SELECT $1 AS oracle_probe`` (literal folded to a parameter placeholder,
as expected). A substring pattern like ``%oracle_probe%`` still matches the
normalized text since "oracle_probe" itself is not a literal that gets
folded, so callers do not need to spell out ``$1`` in their pattern.
"""
import hashlib
import os

import psycopg

_BACKENDS = {
    "primary": ("PGCOMPAT_PRIMARY_HOST", "PGCOMPAT_PRIMARY_PORT"),
    "replica1": ("PGCOMPAT_REPLICA1_HOST", "PGCOMPAT_REPLICA1_PORT"),
    "replica2": ("PGCOMPAT_REPLICA2_HOST", "PGCOMPAT_REPLICA2_PORT"),
}


def _root_password():
    # Same derivation as docker-compose-init.bash:
    #   ROOT_PASSWORD=$(echo -n "${INFRA_ID}" | sha256sum | head -c 10)
    infra_id = os.environ["INFRA_ID"]
    return hashlib.sha256(infra_id.encode()).hexdigest()[:10]


def _dsn(host, port):
    return (
        f"host={host} port={port} user=postgres password={_root_password()} "
        f"dbname=testuser sslmode=disable client_encoding=UTF8"
    )


def _connect(name):
    host_var, port_var = _BACKENDS[name]
    return psycopg.connect(
        _dsn(os.environ[host_var], os.environ[port_var]),
        autocommit=True,
    )


def reset_all():
    """Reset pg_stat_statements counters on every backend node."""
    for name in _BACKENDS:
        with _connect(name) as conn, conn.cursor() as cur:
            cur.execute("SELECT pg_stat_statements_reset()")


def calls_for(pattern):
    """Sum of ``calls`` per node for statements whose normalized query text
    LIKE-matches ``pattern`` (e.g. ``"%oracle_probe%"``).

    Returns ``{"primary": int, "replica1": int, "replica2": int}``.
    """
    out = {}
    for name in _BACKENDS:
        with _connect(name) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT COALESCE(SUM(calls), 0) FROM pg_stat_statements "
                "WHERE query LIKE %s",
                (pattern,),
            )
            out[name] = int(cur.fetchone()[0])
    return out
