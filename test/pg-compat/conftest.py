import os
import warnings

import psycopg
import pytest

from harness import xfail as _xfail
from harness.proxysql import Admin


@pytest.fixture(scope="session")
def admin():
    return Admin()


def _proxy_dsn(dbname="testuser"):
    h = os.environ["PGCOMPAT_PROXY_HOST"]
    p = os.environ["PGCOMPAT_PROXY_PORT"]
    # client_encoding pinned to UTF8 for the same reason harness/targets.py
    # and drivers/python/adapter.py pin it: the dbdeployer backend databases
    # default to SQL_ASCII, which psycopg maps to Python's restrictive
    # 'ascii' codec.
    return (
        f"host={h} port={p} user=testuser password=testuser dbname={dbname} "
        f"sslmode=disable client_encoding=UTF8"
    )


@pytest.fixture
def proxy_conn():
    conn = psycopg.connect(_proxy_dsn(), autocommit=True)
    yield conn
    conn.close()


# --- xfail catalogue (discovery-phase reporting; spec sec 2.1) -------------
#
# test/pg-compat/xfail.toml's [[xfail]] entries are keyed by pytest test_id
# (item.nodeid, e.g. "tests/test_differential.py::test_case_is_transparent
# [002_bytea_json_array.sql]"). Any test_id listed there gets an
# xfail(strict=False) marker applied at collection time:
#   - while the entry's divergence persists, the test reports "xfailed"
#     (an expected failure) instead of "failed" -- the suite stays green
#     without loosening any assertion;
#   - if/when the underlying bug is fixed, the SAME test starts passing and
#     is reported "xpassed" (visible with `-rxX`) because strict=False --
#     that's the signal the entry should be removed from xfail.toml.
_XFAILS = {e["test_id"]: e for e in _xfail.load()}


def pytest_collection_modifyitems(config, items):
    matched_ids = set()
    for item in items:
        entry = _XFAILS.get(item.nodeid)
        if entry:
            matched_ids.add(item.nodeid)
            item.add_marker(
                pytest.mark.xfail(
                    reason=f'{entry["reason"]} ({entry["ref"]})', strict=False
                )
            )

    # Catalogue hygiene: a [[xfail]] entry whose test_id matched NO collected
    # item is currently a silent no-op (e.g. a typo'd nodeid, or a test that
    # was renamed/removed without updating xfail.toml). Warn -- don't fail
    # collection -- so a stale/typo'd entry is visible in the run instead of
    # quietly doing nothing forever.
    for test_id in _XFAILS:
        if test_id not in matched_ids:
            warnings.warn(
                f"xfail.toml entry test_id={test_id!r} matched no collected "
                f"test item -- stale or typo'd entry?",
                stacklevel=1,
            )
