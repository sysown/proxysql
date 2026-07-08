import os

import psycopg
import pytest

from harness.proxysql import Admin


@pytest.fixture(scope="session")
def admin():
    return Admin()


def _proxy_dsn(dbname="testuser"):
    h = os.environ["PGCOMPAT_PROXY_HOST"]
    p = os.environ["PGCOMPAT_PROXY_PORT"]
    return f"host={h} port={p} user=testuser password=testuser dbname={dbname} sslmode=disable"


@pytest.fixture
def proxy_conn():
    conn = psycopg.connect(_proxy_dsn(), autocommit=True)
    yield conn
    conn.close()
