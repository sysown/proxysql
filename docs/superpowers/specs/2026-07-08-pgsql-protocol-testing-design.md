# PostgreSQL Protocol Automated Testing — Design

**Date:** 2026-07-08
**Status:** Approved for planning
**Author:** Rene Cannao (with Claude Code)
**Scope of this document:** SP-1 (TAP coverage gaps) and SP-2 (polyglot test-harness foundation), specified in full. SP-3 and SP-4 are captured as a roadmap only.

---

## 1. Motivation

ProxySQL already has solid PostgreSQL protocol test coverage in its TAP suite (~60 unique `pgsql-*-t.cpp` integration tests + 8 unit tests) — strong on transaction state, extended-query protocol, COPY, query routing, and SSL. Two things are missing:

1. **Behavioral coverage gaps** in known-thin areas: a deliberate auth-method matrix, systematic data-type/binary-encoding round-trips, server-side cursors, and pool-churn/max-connections behavior.
2. **Whole classes of test *technique*** that the leading PG proxies (PgBouncer, pgcat, pgdog) rely on and ProxySQL lacks: deterministic fault injection (chaos), differential/golden-master transparency testing, a `pg_stat_statements` routing oracle, and a **cross-driver matrix** that runs the same behaviors through many real client drivers.

This program adds both, phased: fast coverage wins in the existing harness first (SP-1), then the reusable infrastructure for the new techniques (SP-2), then breadth and chaos (SP-3, SP-4).

### Prior art surveyed (informing this design)

- **PgBouncer** — pytest harness; shared `QueryRunner` base class hit by both proxy and backend through one API; in-process fault injection (`drop_traffic`/`reject_traffic`/`add_latency` via iptables/`tc`, plus a `socat` MITM proxy); `PortLock` for parallel isolation; systematic packet-buffer boundary matrix; PG-version CI matrix (13/15/16/18).
- **pgcat** — polyglot (Ruby/Python/Rust/Go) drivers against one instance; **Toxiproxy in front of every backend** (1-byte `limit_data` toxic to simulate a hung host, instantly reversible); **`pg_stat_statements` as the routing oracle**; raw-socket protocol diff-testing; programmatic TOML config + live `RELOAD`.
- **pgdog** — 7-language driver matrix; **6-target differential SQL harness** (proxy-vs-direct, text/binary/sharded, asserting identical status, column names, **type OIDs**, rowcounts, payloads via drop-in SQL files); Toxiproxy chaos with **bounded-error-rate assertions**; WAL-state synthesis for un-hookable crash windows; build-once/fan-out CI.

The two highest-leverage borrowed ideas are the **differential harness** (proxy output must be byte-identical to a direct backend) and the **`pg_stat_statements` routing oracle** (prove *where* a query landed without parsing logs).

---

## 2. Goals and non-goals

### Goals
- Close the SP-1 behavioral gaps within the existing TAP/C++ harness, gating on every PR.
- Stand up a reusable polyglot test foundation (SP-2) proving the differential + routing-oracle + chaos-ready techniques end-to-end with one reference driver (Python).
- Design SP-2 so SP-3 (more drivers) and SP-4 (chaos suite) are additive, not rewrites.

### Non-goals / explicit scope exclusions
- **No single-table sharding / cross-shard tests.** Confirmed from code: ProxySQL PG routing maps one query to exactly one `destination_hostgroup` (`PgSQL_Query_Processor.cpp:356,491`); there is no shard-key, shard-map, scatter/gather, or cross-shard aggregation. All pgdog/pgcat sharding-style tests are out of scope. (This reduces the differential harness from pgdog's 6 targets to 4.)
- **No LISTEN/NOTIFY *delivery* test.** LISTEN is explicitly rejected with `0A000 feature_not_supported` (`PgSQL_Session.cpp:865`, `:6547`) and there is no `NotificationResponse`/`PQnotifies` forwarding path (backends are consumed via libpq). We test the current rejection contract only and capture forwarding as a future feature (see §3.6 and Appendix A).
- **No two-phase-commit crash-safety / logical-replication-resharding tests** (pgdog features ProxySQL doesn't have).
- SP-3 and SP-4 are **not** implemented under this spec; only stubbed as roadmap (§6).

---

## 3. SP-1 — TAP coverage gaps

**Harness:** existing `test/tap/tests/` (`-t.cpp`), registered in `test/tap/groups/groups.json`. **CI:** per-PR, gating. **Backends:** existing `test/infra/docker-pgsql16-single` (and `infra-pgsql17-repl` where multi-node is needed). Debug build required (per `CLAUDE.md`).

### 3.0 Shared harness enabler — extend `pg_lite_client`

`test/tap/tests/pg_lite_client.{h,cpp}` is the hand-rolled raw-socket wire client. Today its auth support is limited to `AuthenticationOk` and cleartext (type 3); SCRAM (10) and MD5 (5) throw "Unsupported authentication method". Several SP-1 tests need deliberate control over the auth exchange and over result formats.

**Work:** add to `pg_lite_client`:
- **MD5 auth** (type 5) — `md5(md5(password+user)+salt)`.
- **SCRAM-SHA-256** (type 10 → SASL) — reuse ProxySQL's vendored `libscram` (`deps/`) rather than re-implementing; the client drives `SASLInitialResponse`/`SASLResponse` and validates the server signature.
- A knob to **force** a specific requested auth type / to assert the auth request type the server sent (so a test can assert "server asked for scram-sha-256", not just "auth succeeded").

This is a prerequisite for 3.1 and reused by 3.2/3.3.

### 3.1 Auth-method matrix — `pgsql-auth_method_matrix-t.cpp`

Deliberately exercises each method rather than letting libpq auto-negotiate:
- **Success paths:** trust (local), cleartext password, md5, scram-sha-256, cert-only (`hostssl ... cert`).
- **Failure paths:** wrong password per method; unknown user; method-mismatch (server demands scram, client offers md5); expired/rotated password (ties to existing `pgsql-scram_cache_invalidation-t`).
- **Assertions:** the auth request type the frontend received, the final `ReadyForQuery`, and the exact `SQLSTATE` on failure (`28P01` etc.).

Backend `pg_hba.conf` in `docker-pgsql16-single` already provides scram + cert; add md5 and cleartext user entries as needed (init SQL, not a new topology).

### 3.2 Data-type / binary-encoding matrix — `pgsql-datatype_matrix-t.cpp`

Systematic round-trips, **each type in both text and binary result format**, asserting value fidelity *and* the column type OID and format code:
- Scalars: `bool`, `int2/4/8`, `float4/8`, `numeric` (incl. NaN, ±Inf, high precision), `text`/`varchar` (incl. multibyte UTF-8, embedded NUL-adjacent), `bytea` (incl. bytes 0x00–0xFF), `uuid`, `date`/`time`/`timestamp`/`timestamptz` (incl. infinity), `interval`.
- Composite/edge: `jsonb`/`json`, 1-D and **multi-dimensional arrays** (incl. NULL elements, quoting/escaping edge cases), `inet`/`cidr`/`macaddr`.
- **Assertion mechanism:** driven through `pg_lite_client` with explicit result-format codes; overlaps the SP-2 differential engine conceptually but stays in TAP for the per-PR gate. (SP-2 later generalizes this into the proxy-vs-direct diff.)

### 3.3 Server-side cursors — `pgsql-server_side_cursors-t.cpp`

- `DECLARE cur CURSOR FOR ...` / `FETCH n` / `MOVE` / `CLOSE` over simple protocol.
- Extended protocol **portal suspension**: `Execute` with a non-zero max-row count → `PortalSuspended` → continue → completion, across multiplexed connections (assert the portal stays pinned to its backend). `pg_lite_client` already supports portals.

### 3.4 Pool churn / max-connections — `pgsql-pool_churn-t.cpp`

- Connection storm exceeding `pgsql-max_connections` per hostgroup; assert queuing / clean rejection, no leak (`SHOW ... pool` counters via admin).
- **Session-state isolation across multiplexing:** set a session GUC / prepared statement / temp state on connection A, force backend reuse, assert connection B does not observe A's state. This is the classic pooler-correctness risk and is currently only indirectly covered.

### 3.5 LISTEN/NOTIFY negative test — `pgsql-listen_notify_rejection-t.cpp`

Pins the **current contract** (chosen option: negative test + feature note):
- `LISTEN chan` over **simple** protocol → asserts `0A000` with message "LISTEN is not supported".
- `LISTEN chan` over **extended** protocol (Parse/Bind/Execute) → same rejection (`PgSQL_Session.cpp:6547` path).
- `NOTIFY chan, 'payload'` as a plain query → completes cleanly (routed as ordinary query), no hang, no crash; connection remains usable afterward.
- `UNLISTEN` behavior asserted consistently.

Appendix A sketches what real NOTIFY forwarding would require (captured, not built).

### 3.6 SP-1 grouping & CI

- Register new tests in `groups.json` under an appropriate `legacy-g*` group (following existing pgsql placement), tagged with the correct `@proxysql_min_version` if any behavior is tier-gated.
- All SP-1 tests run in the normal per-PR gating TAP matrix. No new CI workflow.

---

## 4. SP-2 — Polyglot test-harness foundation

**Harness:** new top-level directory `test/pg-compat/` (Python/pytest). **CI:** nightly cron + opt-in `pg-compat` PR label; non-gating relative to normal PRs. **Reference driver:** Python (psycopg3 + asyncpg). SP-2 proves the whole machine with Python only; SP-3 adds the other languages.

### 4.1 New backend topology — `test/infra/infra-pgsql-lb/`

No primary+2-replica topology exists today; SP-2 needs one.
- **Nodes:** `pgdb1` (primary) + `pgdb2`, `pgdb3` (2 streaming replicas), PG 17 (align with `infra-pgsql17-repl`).
- **Fault-injection layer:** one **Toxiproxy** instance exposing one proxy endpoint per backend; ProxySQL's `pgsql_servers` point at the Toxiproxy ports, not the real PG ports. This makes every backend individually degradable (latency, `limit_data` slow-loris, reset-peer) without touching containers — the mechanism SP-4 will lean on.
- **Routing config:** use the **automatic** monitor-driven path — populate `pgsql_replication_hostgroups (writer_hostgroup, reader_hostgroup, check_type='read_only')` and let the monitor's `pg_is_in_recovery()` check (`PgSQL_Monitor.cpp:824,1859`) place primary→writer HG and replicas→reader HG. This is deliberately *different* from the static placement in `infra-pgsql17-repl`, because the automatic machinery is what read/write split and SP-4 failover actually depend on.
- Follows existing infra conventions (docker-compose + `.env` with `WHG`/`RHG`, `bin/` wait/post scripts, `conf/` layout). Reuses `test/infra/control/` runners; introduces no new manual Docker steps.

### 4.2 Directory layout — `test/pg-compat/`

```
test/pg-compat/
├── conftest.py            # fixtures: proxysql admin conn, backend conns, toxiproxy client,
│                          #   per-test config snapshot/restore, port isolation
├── harness/
│   ├── proxysql.py        # admin-driven config mutation + LOAD ... TO RUNTIME (test primitive)
│   ├── targets.py         # connection factories for the 4 differential targets
│   ├── oracle.py          # pg_stat_statements routing oracle (per-backend call counts)
│   ├── toxi.py            # thin Toxiproxy wrapper (add/reset toxics) — used by SP-4, stubbed here
│   └── diff.py            # differential comparison engine (§4.4)
├── drivers/
│   └── python/            # reference driver adapter (psycopg3 + asyncpg)
│       └── adapter.py     # implements the driver-adapter interface (§4.3)
├── behaviors/            # shared, driver-agnostic behavior set (§4.3)
│   ├── connect.py
│   ├── transactions.py
│   ├── prepared.py
│   ├── rw_split.py
│   └── session_isolation.py
├── cases/               # drop-in SQL cases for the differential harness (§4.4)
│   └── NNN_slug.sql
├── requirements.txt
└── README.md
```

### 4.3 Shared behavior set + driver-adapter interface

The core reuse mechanism: **behaviors are written once, driver-agnostic**, and each driver provides a small **adapter** implementing a fixed interface (open connection, exec-simple, exec-params(text|binary), prepare/execute-named, begin/commit/rollback, close). SP-3 adds Java/Go/Node adapters against the *same* `behaviors/`.

Behavior modules for SP-2:
- **connect** — startup params, options, unix socket, reconnect.
- **transactions** — BEGIN/COMMIT/ROLLBACK, savepoints, txn-state after errors, idle-in-transaction.
- **prepared** — named + unnamed prepared statements reused across multiplexed backends (the classic pooler breakage); assert result correctness and that ProxySQL's prepared-statement handling stays consistent.
- **rw_split** — SELECT → reader HG, writes/`SELECT ... FOR UPDATE` → writer HG; verified by the routing oracle (§4.5).
- **session_isolation** — session GUC / temp / prepared state must not leak across multiplexed reuse (mirrors SP-1 3.4 but through a real driver).

### 4.4 Differential engine (golden-master transparency)

Adapted from pgdog's harness, reduced to **4 targets** (no sharding):

| Target | Connection | Result format |
|---|---|---|
| `proxy_text` | via ProxySQL | text |
| `proxy_binary` | via ProxySQL | binary |
| `direct_text` | direct to primary | text |
| `direct_binary` | direct to primary | binary |

- Each case in `cases/NNN_slug.sql` is run against all 4 targets. The engine asserts **identical**: command status tag, column names, **column type OIDs**, row count, and row payloads. `proxy_*` must be indistinguishable from `direct_*`.
- Case metadata in SQL comments (pgdog convention): `-- transactional:`, `-- skip-targets:`, `-- only-targets:`.
- **Adding a test = dropping in one SQL file.** Initial cases cover the SP-1 data-type matrix expressed as differential cases (bytea, numeric, jsonb, arrays, network, temporal), giving us the same coverage through a *second, independent* mechanism (real driver + direct-backend diff) that catches transparency bugs the TAP self-asserting tests can't.

### 4.5 Routing oracle

Adapted from pgcat. `harness/oracle.py`:
- Before a behavior, snapshot `pg_stat_statements` per backend (reset or record baseline).
- Run the workload through ProxySQL.
- Read `SELECT sum(calls) FROM pg_stat_statements WHERE query LIKE ...` on each backend to prove *where* each query landed.
- Exact assertions for deterministic routing (write → writer HG only); **margin-of-error** assertions for balanced reads across the 2 replicas.
- Requires `pg_stat_statements` preloaded on every backend (infra config, §4.1).

### 4.6 Config-as-primitive

`harness/proxysql.py` mutates ProxySQL config through the **admin interface** (`pgsql_servers`, `pgsql_query_rules`, `pgsql_replication_hostgroups`, `pgsql-*` variables) followed by `LOAD ... TO RUNTIME`, then restores a snapshot in fixture teardown. This lets a single running ProxySQL be reconfigured per test (pool mode, multiplex on/off, HG layout) without restart — the PgBouncer/pgcat pattern. Debug build assumed (admin debug commands).

### 4.7 CI

- **New workflow** (e.g. `.github/workflows/CI-pg-compat.yml` caller on `v3.0`, reusable on `GH-Actions` per the two-branch split in `doc/GH-Actions/README.md`).
- **Triggers:** nightly `schedule` + `pull_request` gated on the `pg-compat` label.
- **Shape:** build proxysql (debug, `PROXYSQL31=1`) once → cache → job spins up `infra-pgsql-lb` (+ Toxiproxy) via the standard `test/infra/control/` runners → runs `pytest test/pg-compat`. SP-3 will fan out per-language matrix jobs from the same cached binary.
- **Not gating** on normal PRs (heavy, multi-toolchain); nightly failures triaged per `CLAUDE.md`'s "never dismiss as flaky" policy.

---

## 5. Testing the tests (validation strategy)

- **Differential engine self-check:** a deliberately non-transparent config (e.g. a query rewrite rule) must make a differential case *fail* — proves the engine detects divergence, not just passes.
- **Routing oracle self-check:** a case pinned to the writer HG must show zero calls on replicas — proves the oracle actually discriminates.
- **Toxiproxy wiring self-check (SP-2 scope):** applying a full-block toxic to a replica must make the monitor shun it and reads reroute — proves the fault layer + monitor path are correctly wired, even though the *chaos suite* itself is SP-4.
- SP-1 tests follow existing TAP conventions and run under the isolated harness (`run-tests-isolated.bash`, debug binary).

---

## 6. Roadmap — SP-3 and SP-4 (not in this spec)

- **SP-3 — Driver matrix expansion.** Add adapters under `test/pg-compat/drivers/`: **Java** (pgjdbc, +HikariCP), **Go** (pgx native), **Node.js** (node-postgres, postgres.js, Prisma). Each runs the existing `behaviors/` set + differential cases. CI fans out one matrix job per language from the cached binary. Prisma/pgjdbc are the highest-value targets (aggressive server-side prepared statements historically break poolers).
- **SP-4 — Chaos & resilience suite.** Build on SP-2's Toxiproxy layer: failover/shunning (1-byte `limit_data` slow-loris), latency toxics, reset-peer, health-check detection and auto-recovery — with **bounded-error-rate assertions** (pgdog/pgcat style: "≤N errors of M", "reroute within T"), exercising the automatic `pgsql_replication_hostgroups` monitor path from §4.1.

---

## Appendix A — Future feature note: NOTIFY forwarding (not built)

Real LISTEN/NOTIFY support would require, at minimum: (1) removing the `LISTEN` rejection in both `PgSQL_Session.cpp` paths; (2) pinning a LISTEN-ing frontend to a dedicated backend (incompatible with transaction-level multiplexing — likely a session-mode-only feature); (3) a backend `NotificationResponse`/`PQnotifies` consumption path (ProxySQL currently consumes results via libpq's result API, which swallows async 'A' messages) and forwarding them to the pinned frontend; (4) lifecycle handling for `UNLISTEN` and connection teardown. This is a feature, tracked separately; SP-1 §3.5 only pins the current rejection contract so it can't silently regress.

---

## Appendix B — Decision log

| Decision | Choice |
|---|---|
| Primary goal | Both coverage-gaps and new-techniques, **phased** |
| Phase-2 harness | **Polyglot driver matrix** (heaviest, highest driver-breadth) |
| Driver ecosystems | Python (psycopg3+asyncpg+SQLAlchemy), Java (pgjdbc), Go (pgx), Node (node-pg+Prisma) |
| First spec | **SP-1 + SP-2 combined** (this document) |
| CI cadence | SP-1 per-PR gating; **SP-2 nightly + `pg-compat` label**, non-gating |
| LISTEN/NOTIFY | **Negative test now + feature appendix** |
| Sharding tests | **Excluded** (no PG sharding in ProxySQL) |
| Differential targets | **4** (proxy/direct × text/binary) |
| Replica routing | **Automatic** `pgsql_replication_hostgroups` + `pg_is_in_recovery()` (new 3-node infra) |
