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

### Report output (`--junitxml` and friends)

`run-pg-compat.bash`'s container runs with `--rm`, so anything pytest writes
to its own filesystem is destroyed the moment the container exits. The
script bind-mounts a host directory to `/pg-compat-reports` inside the
container (default `${WORKSPACE}/pg-compat-reports`, override with
`PGCOMPAT_REPORT_DIR`) so report files survive. Write reports there, e.g.:

```bash
WORKSPACE=$(pwd) INFRA_ID=<infra-id> test/pg-compat/run-pg-compat.bash \
  --junitxml=/pg-compat-reports/pg-compat.xml -rxX
# report lands at: ${WORKSPACE}/pg-compat-reports/pg-compat.xml
```

## Driver matrix (SP-3)

Beyond the reference Python/psycopg3 harness, the suite runs the same
4-behavior contract (`connect`, `transactions`, `prepared`,
`session_isolation` — see `behaviors/*.py`, the FROZEN cross-driver
contract) through four more real-world driver stacks, each its own
self-contained CLI program compiled/installed into the pg-compat image by
the multi-stage `Dockerfile` (`drivers/<lang>/`). All five stacks pass the
full behavior contract through ProxySQL with **zero `xfail.toml` entries
added** — every pass below is a genuine pass, not a catalogued divergence.

| Language | Driver | Version | Placeholders | Prepared-statement strategy | Encoding pin |
|---|---|---|---|---|---|
| Python | psycopg3 | 3.2.* | `%s` (client-side) | auto-prepare after `prepare_threshold=5` (driver default) | DSN `client_encoding=UTF8` |
| Go | pgx | v5.7.5 | `$1, $2` | default `QueryExecMode=cache_statement` — Parse once per distinct SQL text (extended protocol), then Bind/Execute-only on every subsequent call via the server-side statement cache | DSN param `client_encoding=UTF8` |
| Java | pgjdbc | 42.7.4 | `?` | server-side NAMED statement after `prepareThreshold=5` (driver default); one `PreparedStatement` object reused for all 50 iterations | `options=-c client_encoding=UTF8` connection property |
| Node | pg (node-postgres) | 8.13.1 | `$1, $2` | UNCONDITIONAL named statements — `Parse` sent once at iteration 0 via `{name, text, values}`, every later call is `Bind`/`Execute` only | `client_encoding` config key |
| Node | Prisma | 5.22.0 | tagged-template (`$queryRaw`) | always-prepared — the Rust query engine has no simple-query mode; every `$queryRaw`/`$executeRawUnsafe` call is a real Parse/Bind/Execute; `connection_limit=1` pins the client to one backend connection | URL param `client_encoding` is accepted but IGNORED by the Rust engine (verified: `LATIN1` in the URL still yields UTF8) — the factory issues an explicit `SET client_encoding TO 'UTF8'` instead |

**Headline finding:** four distinct prepared-statement strategies — including
pgjdbc's server-side NAMED statements (the classic connection-pooler
breaker: `prepared statement "S_1" does not exist`) and Prisma's
always-prepared Rust engine — all stay transparent through ProxySQL's
connection multiplexing.

**Prisma caveat:** the Prisma behavior program (`drivers/prisma/behaviors.mjs`)
exercises only the **raw-query API** (`$queryRaw`/`$executeRawUnsafe`/
`$transaction`), not Prisma's model/ORM query path (`prisma.model.findMany()`
etc.) — there are no real models in `schema.prisma` (a single unused dummy
model exists only to satisfy `prisma generate`). The ORM query path is a
possible future extension, not covered here.

### Running one language

Extra arguments to `run-pg-compat.bash` are forwarded to `pytest`, so a
single language's wrapper file (or `-k`) selects just that driver, e.g.:

```bash
WORKSPACE=$(pwd) INFRA_ID=<infra-id> test/pg-compat/run-pg-compat.bash tests/test_behaviors_go.py -v
```

Per-language wrapper files: `tests/test_behaviors_go.py`,
`tests/test_behaviors_java.py`, `tests/test_behaviors_node.py`,
`tests/test_behaviors_prisma.py` (Python's own behaviors run via
`tests/test_behaviors.py`, in-process rather than as a subprocess).

### Behavior-CLI contract

Every language ships ONE compiled/installed binary at
`/pg-compat/bin/behaviors-<lang>` implementing the same CLI:

```
behaviors-<lang> <behavior>      # <behavior> ∈ {connect, transactions, prepared, session_isolation}
```

- **exit 0** — behavior passed.
- **exit 1** — behavior assertion failed; a human-readable reason on stderr.
- **exit 2** — usage or infra error (unknown behavior name, not-yet-implemented
  behavior, missing/invalid env); never a behavior-contract failure.
- No stdout output is required on pass.

`tests/_subproc.py::run_behavior(program, behavior)` runs
`[program, behavior]`, translates exit 0/1/2 into pytest pass/fail, and
`pytest.skip`s if the binary is absent from the image (so a partial image
still runs the languages it does have).

### Adding a language

1. Implement the 4 behaviors (`connect`, `transactions`, `prepared`,
   `session_isolation`) against `behaviors/*.py` as the frozen reference —
   same assertions, same trap adaptations (session-isolation probe is
   `SET TimeZone = 'Antarctica/Troll'` / `SHOW TimeZone`, **never**
   `application_name` — it's in ProxySQL's `ignore_vars`; every transaction
   verification read runs inside its own `BEGIN`/`COMMIT` so it pins to the
   writer instead of racing replica lag; every connection pins
   `client_encoding=UTF8`; placeholders are driver-native, not psycopg's `%s`).
2. Expose them behind the uniform CLI contract above, in its own
   `drivers/<lang>/` directory. Use a per-language table name for the
   transactions behavior (`behavior_tx_t_<lang>`) so runs never collide
   with another language's.
3. Add a build stage to `Dockerfile` that produces
   `/pg-compat/bin/behaviors-<lang>` (a compiled binary, or a thin shell
   wrapper invoking an interpreter — see the Java/Node stages for both
   patterns) and pin the exact driver version in both the Dockerfile
   (`ARG`/lockfile) and this table.
4. Add `tests/test_behaviors_<lang>.py` — a thin subprocess wrapper using
   `tests/_subproc.py::run_behavior` and
   `@pytest.mark.parametrize("behavior", BEHAVIORS, ids=BEHAVIORS)` so
   nodeids stay stable (`tests/test_behaviors_<lang>.py::test_behavior_<lang>[<behavior>]`)
   for the `xfail.toml` exact-nodeid catalogue.
5. A behavior that genuinely fails through ProxySQL is a FINDING, not a bug
   to hide — add an `[[xfail]]` entry (or a `[[finding]]` if nothing fails
   but a divergence was neutralized), never weaken the assertion.

## CI

The suite is wired into CI as `CI-pg-compat` (`.github/workflows/CI-pg-compat.yml`
caller on `v3.0` + `ci-pg-compat.yml` reusable on `GH-Actions`, per the
two-branch split in `doc/GH-Actions/README.md`). Unlike the TAP families it
does not chain off `CI-trigger`/`CI-builds`; it builds ProxySQL inline
(`PROXYSQL31=1 make debug`), like the `CI-3p-*` family, since its triggers
have no guaranteed prior `CI-builds` cache to restore from.

- **Triggers:** nightly at 03:00 UTC (`schedule`), any `pull_request` that
  carries the `pg-compat` label, and manual `workflow_dispatch`.
- **Status: non-gating.** Per the discovery-phase framing above, the run
  step uses `|| true` so a real/uncatalogued divergence does not fail the
  workflow. Promote to gating (drop `|| true`, tighten `xfail.toml`) once
  the suite is green and stable.
- **Artifact:** the junitxml report is uploaded as `pg-compat-report` on
  every run (`if: always()`), whether the underlying pytest run passed,
  xfailed, or hit real failures.

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
