"""Admin config primitive for the pg-compat suite.

Talks to ProxySQL's admin interface over the PG wire protocol (port 6132)
via psycopg. Provides the read/SET/LOAD/snapshot/restore cycle that later
pg-compat tests use to flip a runtime variable, exercise behavior, and put
the variable back.

Deviation from the brief: the brief's DSN used user/password `admin`/`admin`.
Empirically, ProxySQL's PG-protocol admin interface rejects the literal
username `admin` from any peer that is not 127.0.0.1/::1/localhost
(PgSQL_Session.cpp: "User '%s' can only connect locally" — the check is a
strcmp() against the literal string "admin", scoped to the ADMIN_HOSTGROUP
default hostgroup). Since this harness always connects from a separate
container over the docker network, the literal `admin` user can never log
in here. ProxySQL ships a second admin credential pair via
`admin-admin_credentials` (default `admin:admin;radmin:radmin`) where
`radmin` maps to the same ADMIN_HOSTGROUP/privileges but is NOT subject to
the localhost-only check (the strcmp only matches "admin"). So this harness
authenticates as radmin/radmin, verified against the running sdd-sp2 infra:
  docker exec <dbdeployer> psql -h proxysql -p 6132 -U admin  -d admin ...  -> FATAL: User 'admin' can only connect locally
  docker exec <dbdeployer> psql -h proxysql -p 6132 -U radmin -d admin ...  -> works
"""
import os

import psycopg


def _admin_dsn():
    host = os.environ["PGCOMPAT_ADMIN_HOST"]
    port = os.environ["PGCOMPAT_ADMIN_PORT"]
    # See module docstring: "admin" is restricted to loopback connections
    # only; "radmin" carries the same admin privileges without that
    # restriction, so it is what a remote (containerized) client must use.
    return f"host={host} port={port} user=radmin password=radmin dbname=admin sslmode=disable"


def _sql_quote(value):
    """SQL-quote a string literal for the ProxySQL admin parser.

    Escapes by doubling single quotes (verified live against the admin:
    `SET pgsql-server_version='16.1''test'` stores `16.1'test` and reads
    back correctly from global_variables). Backslashes are passed through
    literally — the admin's SQLite-based parser uses standard-conforming
    string literals and does not treat backslash as an escape character.
    NUL cannot be represented in a SQL string literal, so it is rejected.
    """
    if "\x00" in value:
        raise ValueError("NUL byte not representable in a SQL string literal")
    return "'" + value.replace("'", "''") + "'"


class Admin:
    def __init__(self):
        # prepare_threshold=None disables psycopg's automatic server-side
        # prepared statements. ProxySQL's PG-protocol admin interface does NOT
        # support the extended-query Parse/Bind path, so once psycopg silently
        # promoted a repeated statement to a prepared one (default threshold =
        # 5 executions) the admin returned "Feature not supported". Admin
        # queries are cheap and infrequent, so plain simple-protocol execution
        # is both correct and sufficient here.
        self.conn = psycopg.connect(
            _admin_dsn(), autocommit=True, prepare_threshold=None
        )

    def query(self, sql):
        with self.conn.cursor() as cur:
            cur.execute(sql)
            return cur.fetchall() if cur.description else None

    def set_var(self, name, value):
        # str  -> SQL-quoted, single quotes doubled (see _sql_quote).
        #         Always quoting strings is safe even for numeric variables:
        #         verified live that SET name=1 and SET name='1' behave
        #         identically, so restore() (whose values from snapshot()
        #         are always str) round-trips every variable type.
        # bool -> bare true/false (verified live: SET
        #         pgsql-connection_warming=true / =false are accepted and
        #         read back as "true"/"false"). Checked before the generic
        #         path because bool is a subclass of int.
        # int/float -> bare, unquoted.
        if isinstance(value, bool):
            literal = "true" if value else "false"
        elif isinstance(value, str):
            literal = _sql_quote(value)
        else:
            literal = str(value)
        self.query(f"SET {name}={literal}")

    def load_vars(self):
        self.query("LOAD PGSQL VARIABLES TO RUNTIME")

    def snapshot(self, var_names):
        # Variable names are expected to be literals from trusted call
        # sites, but quote them with the same doubling as values for
        # consistency/safety.
        placeholders = ",".join(_sql_quote(v) for v in var_names)
        rows = self.query(
            "SELECT variable_name, variable_value FROM global_variables "
            f"WHERE variable_name IN ({placeholders})"
        )
        return dict(rows)

    def restore(self, saved):
        for name, value in saved.items():
            self.set_var(name, value)
        self.load_vars()
