"""The 6 differential targets for the pg-compat engine.

Each SQL case is run against every AVAILABLE target and ProxySQL must be
indistinguishable from a direct PostgreSQL backend (status tag, column
names, type OIDs, rows). The target matrix is a 3-way product:

    {proxy, direct} x {libpq-backend, native-backend} x {text, binary}

collapsed to 6 because the native-backend axis does not apply to a direct
connection:

    proxy_libpq_text     proxy_libpq_binary
    proxy_native_text    proxy_native_binary
    direct_text          direct_binary

Native-backend axis (spec 2.2): the two ``proxy_native_*`` targets toggle
``pgsql-use_native_backend_protocol``. That variable does NOT exist in this
build (PR #5882 unmerged), so ``all_targets`` probes the admin once and marks
those two targets ``available=False`` with a reason. The differential test
reports them as pytest SKIPS (never silent omissions, never failures); when
#5882 merges the probe returns present and they light up with ZERO code
changes here.

Env contract (see test/tap/groups/pg-compat/env.sh + run-pg-compat.bash):
proxy = ``PGCOMPAT_PROXY_HOST``/``PGCOMPAT_PROXY_PORT`` (testuser/testuser,
db testuser); direct primary = ``PGCOMPAT_PRIMARY_HOST``/
``PGCOMPAT_PRIMARY_PORT`` (per-node vars -- there is NO PGCOMPAT_BACKEND_PORT).
"""
import os
from dataclasses import dataclass
from typing import Optional

# psycopg is imported so callers can ``from harness import targets`` and reach
# the same driver the engine uses; diff.py performs the actual connections.
import psycopg  # noqa: F401

NATIVE_VAR = "pgsql-use_native_backend_protocol"
NATIVE_ABSENT_REASON = f"{NATIVE_VAR} absent (PR #5882 not merged)"


def _dsn(host, port, dbname="testuser", user="testuser", pw="testuser"):
    # client_encoding is pinned to UTF8 on EVERY target so proxy and direct
    # runs are apples-to-apples. Without it the two sides get DIFFERENT
    # defaults (verified live on the sdd-sp2 infra): the dbdeployer backend
    # databases are SQL_ASCII, so a direct session defaults client_encoding
    # to SQL_ASCII (psycopg then maps it to Python's 'ascii' codec and cannot
    # even send non-ASCII SQL like 'héllo'), while a session THROUGH ProxySQL
    # reports client_encoding=UTF8 (ProxySQL imposes it on its backend
    # connections rather than inheriting the server default -- a session-
    # default divergence flagged in the Task 6 report). Pinning the parameter
    # standardizes the client side only; compare() still requires identical
    # status/columns/OIDs/rows.
    return (
        f"host={host} port={port} user={user} password={pw} "
        f"dbname={dbname} sslmode=disable client_encoding=UTF8"
    )


def _proxy():
    return _dsn(os.environ["PGCOMPAT_PROXY_HOST"], os.environ["PGCOMPAT_PROXY_PORT"])


def _direct():
    # Per-node env vars; there is deliberately no single PGCOMPAT_BACKEND_PORT
    # in this infra (the dbdeployer container exposes three ports on one host).
    return _dsn(os.environ["PGCOMPAT_PRIMARY_HOST"], os.environ["PGCOMPAT_PRIMARY_PORT"])


@dataclass
class Target:
    name: str
    dsn: str
    binary: bool
    native_backend: Optional[bool]  # True=native, False=libpq, None=direct (N/A)
    available: bool = True
    skip_reason: str = ""


def native_var_present(admin):
    """True iff ProxySQL knows ``pgsql-use_native_backend_protocol``.

    Probes the admin once. Absent today (PR #5882 unmerged) -> the two native
    targets are marked unavailable.
    """
    rows = admin.query(
        "SELECT count(*) FROM global_variables "
        f"WHERE variable_name='{NATIVE_VAR}'"
    )
    return int(rows[0][0]) > 0


def all_targets(admin):
    present = native_var_present(admin)

    def _native(name, binary):
        return Target(
            name, _proxy(), binary, True,
            available=present,
            skip_reason="" if present else NATIVE_ABSENT_REASON,
        )

    return [
        Target("proxy_libpq_text",   _proxy(),  False, False),
        Target("proxy_libpq_binary", _proxy(),  True,  False),
        _native("proxy_native_text",  False),
        _native("proxy_native_binary", True),
        Target("direct_text",   _direct(), False, None),
        Target("direct_binary", _direct(), True,  None),
    ]
