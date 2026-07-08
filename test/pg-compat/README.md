# pg-compat

Polyglot PostgreSQL-protocol compatibility suite for ProxySQL (SP-2). It
drives real PG client drivers (psycopg, asyncpg) against the ProxySQL PG
frontend and cross-checks/configures behavior via the ProxySQL admin
interface, running against the `infra-dbdeployer-pgsql17-repl` backend
(one primary + two replicas, automatic RW-split, fronted by Toxiproxy).

This is a **discovery-phase, non-gating** suite (see the "Global
Constraints" / §2.1 framing in the plan below): its first job is to build a
failure inventory, not to be all-green. Known divergences are recorded as
`xfail` entries (added in a later task; see
`docs/superpowers/plans/2026-07-08-pgsql-sp2-polyglot-foundation.md`) rather
than by loosening assertions.

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

## Layout

- `harness/proxysql.py` — `Admin` class: `query`, `set_var`, `load_vars`,
  `snapshot`, `restore` — the read/modify/LOAD/verify/restore cycle used by
  every test that flips a ProxySQL runtime variable.
- `conftest.py` — `admin` (session-scoped `Admin`) and `proxy_conn`
  (function-scoped psycopg connection to the ProxySQL PG frontend)
  fixtures shared by all tests.
- `tests/` — the test suite (`test_smoke.py` today).
- `SPIKE-dbdeployer-pg.md` — prior spike notes on the dbdeployer PG infra;
  left as-is.
