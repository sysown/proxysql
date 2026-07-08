# pg-compat

Polyglot PostgreSQL-protocol compatibility suite for ProxySQL (SP-2). It
drives real PG client drivers (psycopg, asyncpg) against the ProxySQL PG
frontend and cross-checks/configures behavior via the ProxySQL admin
interface, running against the `infra-dbdeployer-pgsql17-repl` backend
(one primary + two replicas, automatic RW-split, fronted by Toxiproxy).

This is a **discovery-phase, non-gating** suite (see the "Global
Constraints" / §2.1 framing in the plan below): its first job is to build a
failure inventory, not to be all-green. Known divergences are recorded as
`xfail` entries in `xfail.toml` (see "xfail / finding catalogue" below)
rather than by loosening assertions.

## Running

The suite runs **inside a container** joined to the infra's Docker network
(no ProxySQL/backend ports are published to the host — see Global
Constraints). Never start containers or networks by hand; always go
through `test/infra/control/*`.

```bash
# 1. Bring up (or reuse) the infra + ProxySQL for this TAP group.
WORKSPACE=$(pwd) INFRA_ID=<infra-id> TAP_GROUP=pg-compat test/infra/control/ensure-infras.bash

# 2. Build the pg-compat image and run pytest in a container on the infra network.
WORKSPACE=$(pwd) INFRA_ID=<infra-id> test/pg-compat/run-pg-compat.bash            # full suite
WORKSPACE=$(pwd) INFRA_ID=<infra-id> test/pg-compat/run-pg-compat.bash tests/test_smoke.py   # one file
```

Extra arguments after the script name are forwarded verbatim to `pytest`
(e.g. `-k`, a specific test file, `-v`).

If ProxySQL was rebuilt, re-run
`test/infra/control/start-proxysql-isolated.bash` to pick up the new binary
(it only restarts the ProxySQL container, leaving backends up).

## Env contract

Populated by `test/tap/groups/pg-compat/env.sh` (sourced by
`run-pg-compat.bash`) plus two pairs set by `run-pg-compat.bash` itself:

| Variable | Meaning |
|---|---|
| `PGCOMPAT_PRIMARY_HOST` / `_PORT` | dbdeployer PG primary (single container, per-node port) |
| `PGCOMPAT_REPLICA1_HOST` / `_PORT` | dbdeployer replica 1 |
| `PGCOMPAT_REPLICA2_HOST` / `_PORT` | dbdeployer replica 2 |
| `PGCOMPAT_TOXI_ADMIN` | Toxiproxy admin API (`host:port`) |
| `PGCOMPAT_TOXI_PRIMARY_HOST` / `_PORT` | Toxiproxy listener in front of the primary |
| `PGCOMPAT_TOXI_REPLICA1_HOST` / `_PORT` | Toxiproxy listener in front of replica 1 |
| `PGCOMPAT_TOXI_REPLICA2_HOST` / `_PORT` | Toxiproxy listener in front of replica 2 |
| `PGCOMPAT_PROXY_HOST` / `_PORT` | ProxySQL PG frontend (default `proxysql:6133`); user `testuser`/`testuser`, db `testuser` |
| `PGCOMPAT_ADMIN_HOST` / `_PORT` | ProxySQL admin over the PG protocol (default `proxysql:6132`) |

There is intentionally **no** single `PGCOMPAT_BACKEND_PORT` — each node has
its own host/port pair because all three nodes are one dbdeployer
container. `run-pg-compat.bash` forwards every `PGCOMPAT_*` variable
currently in the environment into the container, so new variables added to
`env.sh` are picked up automatically.

### Admin credentials

The admin config primitive (`harness/proxysql.py::Admin`) connects as
`radmin`/`radmin`, not `admin`/`admin`. ProxySQL's PG-protocol admin
interface rejects the literal username `admin` from any non-loopback peer
("User 'admin' can only connect locally"); `radmin` carries the same admin
privileges without that restriction and is intended for exactly this kind
of remote/containerized use. See the docstring in `harness/proxysql.py` for
the empirical verification.

## xfail / finding catalogue

`xfail.toml` is the suite's living failure inventory (spec §2.1). It has two
independent sections — see the loader in `harness/xfail.py` and the header
comment in `xfail.toml` itself for the authoritative format:

- **`[[xfail]]`** — a known divergence that currently makes one specific
  test fail. Each entry maps a pytest `test_id` (`item.nodeid`, e.g.
  `tests/test_differential.py::test_case_is_transparent[002_bytea_json_array.sql]`)
  to `mode` (`libpq` | `native` | `both`), a human `reason`, and a tracking
  `ref` (issue/PR). `conftest.py`'s `pytest_collection_modifyitems` hook
  applies `pytest.mark.xfail(reason=..., strict=False)` to every listed
  `test_id` at collection time. Because `strict=False`:
  - the test still runs every time, so nothing is silently skipped;
  - while the divergence persists, it reports `xfailed` — an *expected*
    failure — instead of `failed`, so the suite stays green without
    loosening any assertion;
  - once the underlying bug is fixed, the *same* test starts passing and is
    reported `xpassed` (visible with `-rxX`, on by default via `pytest.ini`'s
    `addopts = -rxX`). An `xpassed` report is the signal to delete that
    entry from `xfail.toml` — the fix landed. Do not "fix" an xpass by
    flipping to `strict=True`; the point is that closing a divergence is
    detected by the run itself, not by someone remembering to edit the toml.
  - **To add an entry:** find (or intentionally reproduce) the failing
    `test_id`, add a `[[xfail]]` block with `test_id`/`mode`/`reason`/`ref`,
    re-run — it should now report `xfailed` rather than `failed`.
- **`[[finding]]`** — a real, verified ProxySQL behavioral difference
  discovered while building this suite that does **not** currently fail any
  test (typically because the harness neutralizes it, e.g. by pinning a
  session parameter so a differential comparison stays apples-to-apples).
  It has no `test_id` to attach an xfail marker to, so it's recorded here
  instead purely so the finding isn't lost. Fields: `summary`, `mode`,
  `detail`, `discovered_by`, `ref`. `harness/xfail.py::findings()` exposes
  these for tooling; nothing in `conftest.py` acts on them automatically.
  Today's one entry: ProxySQL imposes `client_encoding=UTF8` on backend
  connections instead of inheriting the server default (discovered against
  the SQL_ASCII dbdeployer backend in Task 6; see `xfail.toml` for detail).

## Layout

- `harness/proxysql.py` — `Admin` class: `query`, `set_var`, `load_vars`,
  `snapshot`, `restore` — the read/modify/LOAD/verify/restore cycle used by
  every test that flips a ProxySQL runtime variable.
- `harness/xfail.py` — `load()` / `findings()`: loaders for the two sections
  of `xfail.toml` (see "xfail / finding catalogue" above).
- `conftest.py` — `admin` (session-scoped `Admin`) and `proxy_conn`
  (function-scoped psycopg connection to the ProxySQL PG frontend)
  fixtures shared by all tests, plus the `pytest_collection_modifyitems`
  hook that applies xfail markers from `xfail.toml`.
- `tests/` — the test suite (`test_smoke.py`, `test_behaviors.py`,
  `test_differential.py`, `test_differential_selfcheck.py`,
  `test_routing_oracle.py` today).
- `SPIKE-dbdeployer-pg.md` — prior spike notes on the dbdeployer PG infra;
  left as-is.
