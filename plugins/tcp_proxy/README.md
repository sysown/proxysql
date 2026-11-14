# `tcp_proxy` — native opaque TCP forwarding plugin

This directory contains the production ProxySQL 4.0 TCP proxy plugin:

* `include/tcp_proxy.h` — frozen, ProxySQL-independent Engine API.
* `src/config.cpp`, `engine.cpp` — the shared production Engine (also driven
  by the standalone Engine tests). The retired standalone selection/health
  implementation is not part of the four-table product.
* `include/tcp_proxy_plugin.h`, `src/plugin.cpp`, `src/admin.cpp`,
  `src/metrics.cpp` — plugin lifecycle, four persistent configuration tables,
  runtime/status and listener/rule statistics projections, exact Admin
  commands/aliases, the LOAD hand-off, and Prometheus relay/listener/rule
  metrics.
* `tests/admin_unit.cpp`, `tests/Makefile.admin` — focused Admin/schema/lock
  tests using a real isolated `SQLite3DB` and a deterministic Engine test
  double. The DSO itself is built from the real Engine sources.
* `exports.map` — exports only `proxysql_plugin_descriptor_v1`.
* `src/backend_provider.cpp` — ABI18 adapter to the core raw-backend service
  V2. Every TCP hostgroup is mapped to an actual MySQL/PostgreSQL HGM; the
  native manager owns selection, shared limits, counters, status, health and
  monitor decisions. Every connection is destroyed on release; `OFFLINE_HARD`
  closes existing streams.

## Build

```sh
make PROXYSQL40=1                     # whole v4 tree
make -C plugins/tcp_proxy PROXYSQL40=1
```

Artifact: `proxysql_tcp_proxy.so`. Build with the same toolchain, feature tier
and release/debug setting as the core. Linux only in this version.

## Load

```ini
plugins=(
    "tcp_proxy"
)
```

or:

```sh
proxysql --load-plugin tcp_proxy --plugin-dir /path/to/plugins/tcp_proxy
```

## Configuration

Exactly four editable tables:

| Table | Role |
|---|---|
| `tcp_settings` | Relay worker/buffer/limit/timeout settings |
| `tcp_hostgroups` | Mandatory `hostgroup_id`, `source_protocol`, `source_hostgroup`, `comment` mapping |
| `tcp_listeners` | Frontend listener and connect/idle/retry controls |
| `tcp_routing_rules` | First-match peer-CIDR `ROUTE`/`REJECT` rules |

The authoritative `tcp_hostgroups` DDL is:

```sql
CREATE TABLE tcp_hostgroups ( hostgroup_id INTEGER PRIMARY KEY CHECK(hostgroup_id >= 0), source_protocol TEXT NOT NULL CHECK(source_protocol IN ('MYSQL','PGSQL')), source_hostgroup INTEGER NOT NULL CHECK(source_hostgroup >= 0), comment TEXT NOT NULL DEFAULT '')
```

There is no `tcp_servers`, `tcp_hostgroup_mappings`, runtime server/mapping
table or TCP server statistics table. A source hostgroup may be empty/absent
and later populated by monitor/Admin without another TCP LOAD. Multiple TCP
groups may share one source hostgroup and the native per-backend connection
limits. Source hostnames use the protocol monitor's existing DNS cache; the
TCP path performs no blocking lookup. TLS remains passthrough; backends see
ProxySQL's source address.

Canonical TCP commands and aliases remain:

```sql
LOAD TCP CONFIG TO RUNTIME;
SAVE TCP CONFIG TO DISK;
LOAD TCP CONFIG FROM DISK;
-- aliases include: LOAD TCP CONFIG FROM MEMORY, SAVE TCP CONFIG TO MEMORY,
-- LOAD TCP CONFIG TO MEMORY, SAVE TCP CONFIG FROM MEMORY
```

Persist source endpoints with the existing protocol commands, for example
`LOAD MYSQL SERVERS TO RUNTIME` / `SAVE MYSQL SERVERS TO DISK` and the PgSQL
equivalents. Native status/role changes do not need another TCP LOAD. A monitor
demoting a writer marks the old HGM entry `OFFLINE_HARD` and closes its pinned
streams; established streams are never rerouted.

Older five/six-table databases are refused before destructive schema work.
Stop ProxySQL and use the explicit offline converter:

```sh
python3 plugins/tcp_proxy/tools/migrate_tcp_config.py \
    --database /var/lib/proxysql/proxysql.db --check
python3 plugins/tcp_proxy/tools/migrate_tcp_config.py \
    --database /var/lib/proxysql/proxysql.db --apply
```

The apply step creates an exclusive backup and rolls back on failure. See the
canonical user guide: [`doc/tcp-proxy-plugin.md`](../../doc/tcp-proxy-plugin.md).

## Focused tests

```sh
make -f plugins/tcp_proxy/tests/Makefile.admin \
     DEPS_PATH=/path/to/proxysql/deps
./plugins/tcp_proxy/tests/admin_unit-t
```

The target verifies descriptor/schema registration without DB access in Phase B,
defaults, all columns, strict parsing (int32 bounds, embedded NUL, nullable rule
values, enums), transactional disk copies, runtime-vs-memory separation,
statistics/runtime projections, Counter/Gauge metric typing with delta sampling,
retained core-owned metric families with plugin-owned sample cleanup, same-type
and empty foreign-family ownership, foreign sample-label rejection, allocation-
failure tracking rollback, serialization with fake Admin counter resets, bounded
reproduction of sampler/read failures, coherent-runtime read rejection without
touching editable rows, metric registration/pruning/cleanup, idle Context
finalization, and the LOAD try-lock / Admin handoff including failure
reacquisition.

Engine tests, adversarial socket tests and full daemon checks:

```sh
make -C plugins/tcp_proxy/tests run
cd plugins/tcp_proxy/tests
make -f Makefile.integration local-manifest
make -f Makefile.integration test READY_MARKER=/tmp/native-tcp-proxy/test-final-local-manifest.json
cd ../../..
python3 plugins/tcp_proxy/tests/daemon_admin_smoke.py \
    --proxysql "$PWD/src/proxysql" --plugin "$PWD/plugins/tcp_proxy/proxysql_tcp_proxy.so" \
    --case all
```

The socket harness needs the repository JSON dependency. The daemon checks need
a matching release v4 core and the MySQL command-line client. See the
[user guide](../../doc/tcp-proxy-plugin.md).

Final matching-artifact validation on 2026-11-11: Admin **5/5 PASS**, mapped
**15/15 PASS** including the complete portable upgrade case with **86 checks**,
and the retained actual Engine suite is **36/36 PASS** equivalence. The
[four-mode measured report](../../docs/benchmarks/2026-11-11-tcp-four-table-daemon.md)
is current; historical reports remain historical.

Historical only (earlier six-table/mapped/static implementations):

* [mapped daemon report](../../docs/benchmarks/2026-11-11-tcp-hostgroup-mapping-daemon.md)
* [standalone Engine benchmark](../../docs/benchmarks/2026-11-11-native-tcp-proxy.md)

Mapped daemon test and benchmark commands are documented in
[tests/README.integration.md](tests/README.integration.md).
