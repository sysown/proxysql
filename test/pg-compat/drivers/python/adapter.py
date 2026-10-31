"""Reference driver adapter: psycopg3 against the ProxySQL PG frontend.

This is the reuse mechanism SP-3 hooks Java/Go/Node adapters into: each
behavior in ``behaviors/`` is written once against a small adapter
interface (``connect`` via the constructor, ``exec_simple``, ``exec_params``,
``begin``/``commit``/``rollback``, ``close``) and every driver gets the same
behavior for free by implementing that interface.

Named-prepared-statement methods (``prepare(name, sql)`` /
``exec_prepared(name, params)``) are deliberately NOT implemented here.
psycopg3 has no explicit named-prepared-statement API of its own -- it
auto-prepares a parameterized statement after it has been executed
``prepare_threshold`` (default 5) times on the same connection (see
psycopg's ``prepared.py``), which is exactly what ``behaviors/prepared.py``
exercises through ``exec_params``. Add ``prepare``/``exec_prepared`` here
(and to the shared behaviors) only when a driver that needs explicit named
statements (e.g. a Node/Go client) is wired up in SP-3.

Env contract: connects to ``PGCOMPAT_PROXY_HOST``/``PGCOMPAT_PROXY_PORT``
(testuser/testuser, db ``testuser`` by default) -- the same ProxySQL PG
frontend used everywhere else in this harness (see conftest.py /
harness/targets.py). ``client_encoding=UTF8`` is pinned in the DSN for the
same reason targets.py pins it: the dbdeployer backend databases default to
SQL_ASCII, which psycopg maps to Python's restrictive 'ascii' codec.
"""
import os

import psycopg


class PsycopgAdapter:
    def __init__(self, dbname="testuser"):
        h = os.environ["PGCOMPAT_PROXY_HOST"]
        p = os.environ["PGCOMPAT_PROXY_PORT"]
        self.conn = psycopg.connect(
            f"host={h} port={p} user=testuser password=testuser dbname={dbname} "
            f"sslmode=disable client_encoding=UTF8",
            autocommit=True,
        )

    def exec_simple(self, sql):
        with self.conn.cursor() as cur:
            cur.execute(sql)
            return cur.fetchall() if cur.description else None

    def exec_params(self, sql, params, binary=False):
        with self.conn.cursor(binary=binary) as cur:
            cur.execute(sql, params)
            return cur.fetchall() if cur.description else None

    def begin(self):
        self.conn.autocommit = False

    def commit(self):
        self.conn.commit()
        self.conn.autocommit = True

    def rollback(self):
        self.conn.rollback()
        self.conn.autocommit = True

    def close(self):
        # Idempotent: behaviors/session_isolation.py closes its first
        # connection explicitly before opening the second (deliberately, so
        # the second connection can land on the same freed backend), then
        # closes it again from a `finally` guarding the whole behavior body.
        # Guard on psycopg's `closed` property so the repeat call is a safe
        # no-op instead of erroring on an already-closed connection.
        if not self.conn.closed:
            self.conn.close()
