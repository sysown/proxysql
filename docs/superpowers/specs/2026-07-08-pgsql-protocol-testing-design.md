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
- Produce, from the first runs, a **catalogue of what ProxySQL currently fails** — the initial phase is diagnostic (see §2.1).

### 2.1 Operating assumption — the initial phase is discovery, not green CI

The first runs of these suites (especially SP-2's differential + cross-driver matrix, and anything on the new native backend path — §2.2) are expected to **surface failures**, not pass. There is **no expectation of 100% success** in the initial phase. Concretely:

- The deliverable of the initial phase is a **failure inventory** — a catalogue of divergences (transparency violations, driver-specific protocol breakage, routing surprises), each triaged per `CLAUDE.md`'s "never dismiss as flaky" policy into: real ProxySQL bug / test-harness bug / known-and-accepted limitation.
- Failing cases are recorded as **expected-failures (xfail) with a reason and a tracking reference**, not deleted or skipped silently. An xfail that starts passing (xpass) is itself reported, so fixes are noticed.
- CI (SP-2) is therefore **non-gating** by construction in this phase; its job is reporting, not blocking. Promotion of individual behaviors to gating happens only once they are green and stable.

### 2.2 Cross-cutting axis — backend protocol mode (libpq vs native)

PR #5882 (`feature/pgsql-native-backend-protocol`, open against `v3.0` as of 2026-07-07) introduces an **opt-in native PostgreSQL wire-protocol implementation on the ProxySQL→backend data path**, behind runtime flag `pgsql-use_native_backend_protocol` (default **off**; libpq remains as fallback and for monitor/plugins). The native path already implements native auth (trust/cleartext/MD5/SCRAM-SHA-256, plus SCRAM-SHA-256-PLUS channel binding), the extended-query pipeline, native `COPY ... TO STDOUT`, and **native NOTIFY** — and ships its own differential tests (e.g. `pgsql-native_notify-t`, "27/27 strict prepared-statement cases, byte-equal").

Consequences for this design:
- **Backend protocol mode is a first-class test parameter.** Where feasible, SP-1 and SP-2 behaviors run under **both** `pgsql-use_native_backend_protocol = off` and `= on`, and the two are diffed against each other and against direct-PG. This is the single highest-value new axis, because the native path is young and evolving.
- The feature-gap analysis in this document is **path-dependent and will change quickly** as #5882 lands and progresses. Claims below that reference libpq behavior (notably LISTEN/NOTIFY, §3.5) are explicitly scoped to the *libpq* path and are expected to shift; the native path is closing several of them.

### Non-goals / explicit scope exclusions
- **No single-table sharding / cross-shard tests.** Confirmed from code: ProxySQL PG routing maps one query to exactly one `destination_hostgroup` (`PgSQL_Query_Processor.cpp:356,491`); there is no shard-key, shard-map, scatter/gather, or cross-shard aggregation. All pgdog/pgcat sharding-style tests are out of scope. (This reduces the differential harness from pgdog's 6 targets to 4.)
- **LISTEN/NOTIFY delivery is path-dependent, not a flat exclusion.** On the **libpq** path LISTEN is explicitly rejected (`0A000`, `PgSQL_Session.cpp:865`, `:6547`) with no `NotificationResponse`/`PQnotifies` forwarding; on the **native** path (#5882) NOTIFY support is being added. SP-1 §3.5 therefore pins the *current per-mode contract* rather than assuming a single behavior; forwarding design lives in the native PR, not here (Appendix A updated accordingly).
- **No two-phase-commit crash-safety / logical-replication-resharding tests** (pgdog features ProxySQL doesn't have).
- SP-3 and SP-4 are **not** implemented under this spec; only stubbed as roadmap (§6).

---

## 3. SP-1 — TAP coverage gaps

**Harness:** existing `test/tap/tests/` (`-t.cpp`), registered in `test/tap/groups/groups.json`. **CI:** per-PR, gating. **Backends:** existing `test/infra/docker-pgsql16-single` (and `infra-pgsql17-repl` where multi-node is needed). Debug build required (per `CLAUDE.md`).

**Backend-mode note:** where a behavior touches the backend data path (auth, prepared statements, COPY, NOTIFY), the test parameterizes over `pgsql-use_native_backend_protocol` off/on (§2.2) so both paths are covered as the native path matures. Cases that are known-broken on the young native path are marked xfail (§2.1), not skipped. Note SP-1's frontend-facing tests (e.g. `pg_lite_client` auth, §3.0) are independent of backend mode.

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

### 3.5 LISTEN/NOTIFY contract test — `pgsql-listen_notify_contract-t.cpp`

Pins the **current per-mode contract** (chosen option: contract test + feature note). Because behavior differs by backend protocol mode (§2.2), the test parameterizes over `pgsql-use_native_backend_protocol`:

- **libpq path (`off`):** `LISTEN chan` over **simple** protocol → asserts `0A000` "LISTEN is not supported"; over **extended** protocol → same rejection (`PgSQL_Session.cpp:6547`). `NOTIFY chan,'payload'` as a plain query → completes cleanly, no hang/crash, connection reusable. `UNLISTEN` asserted consistently.
- **native path (`on`):** asserts whatever contract #5882 lands (its `pgsql-native_notify-t` already covers NOTIFY differentially). This portion is expected to move and is marked xfail where the native path is incomplete, rather than hard-coding today's snapshot.

This intentionally avoids baking one behavior into the assertion set, since the native path is actively changing what LISTEN/NOTIFY does. Appendix A tracks the forwarding design as owned by the native PR, not this spec.

### 3.6 SP-1 grouping & CI

- Register new tests in `groups.json` under an appropriate `legacy-g*` group (following existing pgsql placement), tagged with the correct `@proxysql_min_version` if any behavior is tier-gated.
- All SP-1 tests run in the normal per-PR gating TAP matrix. No new CI workflow.

---

## 4. SP-2 — Polyglot test-harness foundation

**Harness:** new top-level directory `test/pg-compat/` (Python/pytest). **CI:** nightly cron + opt-in `pg-compat` PR label; non-gating relative to normal PRs. **Reference driver:** Python (psycopg3 + asyncpg). SP-2 proves the whole machine with Python only; SP-3 adds the other languages.

### 4.1 New backend topology — `test/infra/infra-dbdeployer-pgsql17-repl/` (dbdeployer)

No primary+2-replica PG topology exists today; SP-2 needs one. **New infras use dbdeployer** — matching the established `test/infra/infra-dbdeployer-*` convention (currently MySQL/MariaDB only; this is the first dbdeployer PG infra). dbdeployer supports PostgreSQL replication sandboxes, so a single container runs dbdeployer to deploy the whole topology internally and expose its ports, exactly like `infra-dbdeployer-mysql84-gr`.

- **Provisioning:** dbdeployer inside one container image (`proxysql/ci-infra:dbdeployer-pgsql17-repl`), following the sibling layout — `docker/{Dockerfile,build.sh,entrypoint.sh}`, `bin/docker-*-post.bash`, `docker-compose{,-init,-destroy}.bash`, `.env`. dbdeployer deploys **1 primary + 2 replicas** (PG 17) as a replication sandbox.
- **`.env`:** defines `WHG`/`RHG` (and `PREFIX`) hostgroups and the dbdeployer host/port block, per the `infra-dbdeployer-*` pattern.
- **Fault-injection layer:** one **Toxiproxy** endpoint per backend port; ProxySQL's `pgsql_servers` point at the Toxiproxy ports, not the real PG ports, so every backend is individually degradable (latency, `limit_data` slow-loris, reset-peer) without touching the sandbox — the mechanism SP-4 leans on. (Toxiproxy sits between ProxySQL and dbdeployer's exposed PG ports.)
- **Routing config:** use the **automatic** monitor-driven path — populate `pgsql_replication_hostgroups (writer_hostgroup, reader_hostgroup, check_type='read_only')` and let the monitor's `pg_is_in_recovery()` check (`PgSQL_Monitor.cpp:824,1859`) place primary→writer HG and replicas→reader HG. Deliberately *different* from the static placement in `infra-pgsql17-repl`, because that automatic machinery is what read/write split and SP-4 failover actually depend on.
- Reuses `test/infra/control/` runners; introduces no new manual Docker/dbdeployer steps (all wrapped by the standard `ensure-infras.bash` flow).

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

Adapted from pgdog's harness. No sharding, but the **backend-mode axis (§2.2) splits the proxy target in two**, giving **6 targets**:

| Target | Connection | Result format |
|---|---|---|
| `proxy_libpq_text` | via ProxySQL, `use_native_backend_protocol=off` | text |
| `proxy_libpq_binary` | via ProxySQL, `use_native_backend_protocol=off` | binary |
| `proxy_native_text` | via ProxySQL, `use_native_backend_protocol=on` | text |
| `proxy_native_binary` | via ProxySQL, `use_native_backend_protocol=on` | binary |
| `direct_text` | direct to primary | text |
| `direct_binary` | direct to primary | binary |

- Each case in `cases/NNN_slug.sql` runs against all targets; the engine asserts **identical** command status tag, column names, **column type OIDs**, row count, and row payloads. Every `proxy_*` must be indistinguishable from `direct_*` — and, valuably, `proxy_libpq_*` vs `proxy_native_*` diffs pinpoint native-path regressions directly.
- This **complements the native PR's own differential tests** (e.g. `pgsql-native_notify-t`, its strict byte-equal prepared-statement cases): those live in TAP and gate the native work; this harness is the broader, driver-driven, case-drop-in golden master across both modes.
- Case metadata in SQL comments (pgdog convention): `-- transactional:`, `-- skip-targets:`, `-- only-targets:` (e.g. `only-targets: proxy_native_*`).
- Per §2.1, divergences in the discovery phase become **xfail entries with a reason**, feeding the failure inventory rather than blocking.
- **Adding a test = dropping in one SQL file.** Initial cases cover the SP-1 data-type matrix expressed as differential cases (bytea, numeric, jsonb, arrays, network, temporal), giving the same coverage through a *second, independent* mechanism (real driver + direct-backend diff) that catches transparency bugs the TAP self-asserting tests can't.

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
- **Shape:** build proxysql (debug, `PROXYSQL31=1`) once → cache → job spins up `infra-dbdeployer-pgsql17-repl` (+ Toxiproxy) via the standard `test/infra/control/` runners → runs `pytest test/pg-compat` across both backend modes (§2.2). SP-3 (as built — see §6) runs all languages from one multi-language runner image in the same job; a per-language matrix fan-out remains an option at promote-to-gating.
- **Not gating** on normal PRs (heavy, multi-toolchain) — and, per §2.1, **reporting-oriented** in the discovery phase: the job publishes the failure inventory / xfail summary rather than going red on expected divergences. Nightly failures triaged per `CLAUDE.md`'s "never dismiss as flaky" policy.

---

## 5. Testing the tests (validation strategy)

- **Differential engine self-check:** a deliberately non-transparent config (e.g. a query rewrite rule) must make a differential case *fail* — proves the engine detects divergence, not just passes.
- **Routing oracle self-check:** a case pinned to the writer HG must show zero calls on replicas — proves the oracle actually discriminates.
- **Toxiproxy wiring self-check (SP-2 scope):** applying a full-block toxic to a replica must make the monitor shun it and reads reroute — proves the fault layer + monitor path are correctly wired, even though the *chaos suite* itself is SP-4.
- **Expected-failure catalogue (discovery phase, §2.1):** a single source-of-truth file (e.g. `test/pg-compat/xfail.toml`) lists each known-failing case with `reason`, `mode` (libpq/native/both), and a tracking reference. The harness treats listed cases as xfail and **reports xpass** (a listed case that now passes) so fixes are caught. This file *is* the living failure inventory.
- SP-1 tests follow existing TAP conventions and run under the isolated harness (`run-tests-isolated.bash`, debug binary).

---

## 6. Roadmap — SP-3, SP-3b and SP-4

- **SP-3 — Driver matrix expansion (AS BUILT, complete 2026-07-08).** Ran the
  existing SP-2 `behaviors/` contract (`connect`, `transactions`, `prepared`,
  `session_isolation` — frozen, unchanged) through four more driver stacks:
  **Go** (pgx v5.7.5), **Java** (pgjdbc 42.7.4), **Node.js** (pg/node-postgres
  8.13.1), and **Node.js/Prisma** (5.22.0, raw-query API only). Each ships one
  self-contained CLI program (`<prog> <behavior>`, exit 0/1/2) built into the
  pg-compat image by a multi-stage `Dockerfile` extension, invoked from pytest
  via subprocess wrappers (`tests/test_behaviors_<lang>.py` +
  `tests/_subproc.py::run_behavior`) so the existing xfail catalogue, junit
  report, and CI wiring apply unchanged.
  - **Scope decision (user-approved 2026-07-08): behaviors only.** The
    differential engine (§4.4) stays Python/psycopg-only — its comparison
    unit is psycopg's row/type decode semantics, which the other languages
    don't share — so it was NOT extended to the new drivers in SP-3. See
    SP-3b below for that follow-up.
  - CI fans out via a **single fat multi-language image**, not a one-job-
    per-language matrix as originally sketched below: same coverage (all
    five drivers run every CI invocation), no matrix-job complexity. Revisit
    the split if/when this suite is promoted to gating.
  - **Result: all five driver stacks pass the full behavior contract with
    zero `xfail.toml` entries added** — four distinct prepared-statement
    strategies (psycopg auto-prepare@5, pgx's default statement-cache,
    pgjdbc's server-side NAMED statements after `prepareThreshold=5` — the
    classic connection-pooler breaker — and Prisma's always-prepared Rust
    engine) all stay transparent through ProxySQL's connection multiplexing.
    See `test/pg-compat/README.md`'s "Driver matrix (SP-3)" section for the
    full per-language table (versions, placeholder syntax, encoding-pin
    mechanism) and the Prisma raw-vs-ORM caveat.
- **SP-3b — Per-language differential runners (stub, deferred).** Extend each
  non-Python driver's behavior program with a differential-case runner that
  executes the same case files as §4.4 and emits a normalized result
  (status, column names, OIDs/type tags, decoded row values) on stdout for
  Python's `compare()` to consume — so the differential engine's comparisons
  gain Go/Java/Node/Prisma coverage without reimplementing the comparator
  once per language. Deferred pending nightly stability of the SP-3
  behaviors-only suite (see `ci-pg-compat.yml`'s non-gating `|| true`); not
  scheduled against a specific SP number yet.
- **SP-4 — Chaos & resilience suite.** Build on SP-2's Toxiproxy layer: failover/shunning (1-byte `limit_data` slow-loris), latency toxics, reset-peer, health-check detection and auto-recovery — with **bounded-error-rate assertions** (pgdog/pgcat style: "≤N errors of M", "reroute within T"), exercising the automatic `pgsql_replication_hostgroups` monitor path from §4.1.

---

## Appendix A — NOTIFY forwarding: owned by the native-backend PR (#5882)

This is **not** a feature this test spec proposes; it is being addressed by the native-backend work. As of 2026-07-07 the native path already ships NOTIFY support and a `pgsql-native_notify-t` differential test. For reference, full LISTEN/NOTIFY support entails: (1) lifting the `LISTEN` rejection in both `PgSQL_Session.cpp` paths; (2) pinning a LISTEN-ing frontend to a dedicated backend (incompatible with transaction-level multiplexing — likely session-mode-only); (3) a backend `NotificationResponse` (async 'A') consumption+forwarding path — the native wire layer makes this reachable in a way the libpq result API did not; (4) `UNLISTEN`/teardown lifecycle. SP-1 §3.5 pins the *current per-mode contract* so neither path silently regresses while #5882 evolves; it does not gate the feature.

---

## Appendix B — Decision log

| Decision | Choice |
|---|---|
| Primary goal | Both coverage-gaps and new-techniques, **phased** |
| Phase-2 harness | **Polyglot driver matrix** (heaviest, highest driver-breadth) |
| Driver ecosystems | Python (psycopg3+asyncpg+SQLAlchemy), Java (pgjdbc), Go (pgx), Node (node-pg+Prisma) |
| First spec | **SP-1 + SP-2 combined** (this document) |
| CI cadence | SP-1 per-PR gating; **SP-2 nightly + `pg-compat` label**, non-gating |
| Initial-phase expectation | **Discovery, not 100% green** — deliverable is a failure inventory; failing cases = xfail w/ reason (§2.1) |
| Backend-protocol axis | Parameterize over `pgsql-use_native_backend_protocol` off/on (§2.2, tracks PR #5882) |
| LISTEN/NOTIFY | **Per-mode contract test** + note; NOTIFY forwarding owned by #5882 (Appendix A) |
| Sharding tests | **Excluded** (no PG sharding in ProxySQL) |
| Differential targets | **6** (proxy-libpq / proxy-native / direct × text/binary) |
| New infra tooling | **dbdeployer** (`infra-dbdeployer-pgsql17-repl`), per existing `infra-dbdeployer-*` convention |
| Replica routing | **Automatic** `pgsql_replication_hostgroups` + `pg_is_in_recovery()` (primary + 2 replicas) |
