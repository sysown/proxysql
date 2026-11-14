# Native TCP proxy plugin (`tcp_proxy`)

`tcp_proxy` is a ProxySQL 4.0 plugin that forwards opaque TCP connections
through a **mandatory mapping** to an existing MySQL or PostgreSQL hostgroup.
The relay itself is native and in-process: the production plugin and the
standalone Engine tests use the same `tcp_proxy::Engine`. There is no HAProxy
child process, no second relay and no TCP-specific backend pool.

The plugin has exactly four editable/persistent configuration tables:

* `tcp_settings`
* `tcp_hostgroups`
* `tcp_listeners`
* `tcp_routing_rules`

`tcp_hostgroups` defines the mapping. Backend selection, weight, capacity,
health, administrative status,
counters and errors belong exclusively to the named native MySQL/PostgreSQL
hostgroup manager (HGM).

Mapped mode requires a matching rebuilt v4 core with plugin ABI 18 and raw
backend service version 2. Build the core and plugin from this checkout
together.

## Scope and version boundaries

Supported:

* Numeric IPv4 and IPv6 listeners.
* Byte-transparent TLS passthrough. TLS is not terminated and no SNI/payload is
  inspected.
* One native HGM backend connection per accepted client connection, always
  freshly acquired and always destroyed on release.
* Mandatory `MYSQL` or `PGSQL` source hostgroup for every TCP hostgroup.
* Shared capacity when several TCP hostgroups name the same source hostgroup.
* Source-address CIDR routing rules with `ROUTE` and `REJECT`.
* Frontend/global admission limits, relay connect timeout and bounded retry,
  idle timeout, half-close, worker/buffer and shutdown controls.
* Runtime status plus listener/rule statistics and Prometheus relay/listener/
  rule families.

Not supported in this version: UDP, TLS termination, SNI or SQL/application
routing, PROXY protocol, transparent source spoofing, protocol authentication,
application health scripts, backend connection pooling/free-socket reuse,
queued excess connections, automatic Cluster replication, synchronous DNS
resolution and local TCP backend definitions. Configure backend selection,
health checks and server status in the native protocol HGM.

Linux is the initial data-plane platform. The plugin build reports unsupported
platforms explicitly rather than silently building another relay.

## Build and load

Build with the same compiler, C++ standard library, feature tier and `DEBUG`
setting as the ProxySQL core.

```sh
# Normal v4 build, including this plugin
make -j4 PROXYSQL40=1

# Or build only this DSO
make -C plugins/tcp_proxy PROXYSQL40=1

# Matching debug build
make -j4 PROXYSQL40=1 debug
# or: make -C plugins/tcp_proxy PROXYSQL40=1 OPTZ='-O0 -ggdb -DDEBUG'
```

The artifact is `plugins/tcp_proxy/proxysql_tcp_proxy.so`. Load it through the
core plugin chassis, either from `proxysql.cnf`:

```ini
plugins=(
    "tcp_proxy"
)
```

or from the command line:

```sh
proxysql --load-plugin tcp_proxy --plugin-dir /path/to/plugins/tcp_proxy
# or an absolute module path:
proxysql --load-plugin /path/to/plugins/tcp_proxy/proxysql_tcp_proxy.so
```

An installed build places the DSO in `/usr/lib/proxysql/plugins` through the
top-level `make install` target.

## Tables and defaults

All IDs are nonnegative signed 32-bit integers; ports are 1..65535. Every table
except `tcp_settings` has `comment TEXT NOT NULL DEFAULT ''`.

### `tcp_settings`

Exactly one row with `id=1`.

| Column | Default | Meaning |
|---|---:|---|
| `id` | 1 | `PRIMARY KEY`, `CHECK(id=1)` |
| `worker_threads` | 2 | 1..64; startup-only after workers run |
| `max_connections` | 10000 | 1..1000000 across all listeners, including pending connects |
| `buffer_size` | 16384 | 1024..1048576 bytes per direction; startup-only |
| `shutdown_timeout_ms` | 5000 | 0..60000 stop draining deadline |
| `half_close_timeout_ms` | 30000 | 1..3600000 completion after first EOF |

### `tcp_hostgroups` (mandatory mapping)

Authoritative DDL:

```sql
CREATE TABLE tcp_hostgroups ( hostgroup_id INTEGER PRIMARY KEY CHECK(hostgroup_id >= 0), source_protocol TEXT NOT NULL CHECK(source_protocol IN ('MYSQL','PGSQL')), source_hostgroup INTEGER NOT NULL CHECK(source_hostgroup >= 0), comment TEXT NOT NULL DEFAULT '')
```

| Column | Default | Meaning |
|---|---:|---|
| `hostgroup_id` | required | TCP hostgroup ID; independent of MySQL/PgSQL IDs |
| `source_protocol` | required | `MYSQL` or `PGSQL`, exactly upper case |
| `source_hostgroup` | required | Existing HGM hostgroup in the selected protocol namespace |
| `comment` | `''` | Free-form text, preserved byte-for-byte |

There are no balance, health, weight, capacity or fallback columns. Every TCP
hostgroup must have exactly one mapping row. A listener default/ROUTE
destination must reference a TCP hostgroup. The named source hostgroup may be
empty or absent at configuration time; it can be populated later by monitor,
Admin or Cluster without another TCP `LOAD`. For the same reason an empty core
source rejects new admissions until its protocol manager has an eligible
backend. `MYSQL` and `PGSQL` hostgroup IDs are separate namespaces: `10` in
`MYSQL` is not `10` in `PGSQL`.

Several TCP hostgroups may name the same `(source_protocol,
source_hostgroup)`. They then share that HGM's per-backend connection limits,
status, health, counters and error policy. This adds no single hostgroup-wide
connection limit, second TCP reservation or local pool.

Source server hostnames must already resolve through the source protocol
monitor's DNS cache. The TCP path uses that existing cache and never performs
a blocking DNS lookup; numeric source addresses need no DNS resolution.

### `tcp_listeners`

| Column | Default | Meaning |
|---|---:|---|
| `listener_id` | required | `PRIMARY KEY` |
| `active` | 1 | 0 or 1 |
| `bind_address` | `0.0.0.0` | Numeric IPv4/IPv6 address only |
| `bind_port` | required | 1..65535 |
| `default_hostgroup` | required | Existing `tcp_hostgroups.hostgroup_id` |
| `max_connections` | 10000 | Per-listener FRONTEND admission limit, 1..1000000 |
| `connect_timeout_ms` | 2000 | Total backend establish budget, 1..60000 |
| `idle_timeout_ms` | 60000 | 0 disables, otherwise 1..86400000 |
| `max_connect_attempts` | 3 | 1..16 failed connect attempts |
| `comment` | `''` | Free-form text |

Every listener row, including `active=0`, must have a
`default_hostgroup` that references an existing `tcp_hostgroups` mapping.
Disabling a listener does not make its references optional; activating it later
never needs a mapping edit.

`max_connections` here is a frontend admission limit. It does not create a
backend reservation. `connect_timeout_ms`, `max_connect_attempts`,
`idle_timeout_ms`, `worker_threads`, `buffer_size`, `shutdown_timeout_ms` and
`half_close_timeout_ms` are active controls, not ignored knobs.

### `tcp_routing_rules`

| Column | Default | Meaning |
|---|---:|---|
| `rule_id` | required | `PRIMARY KEY` |
| `active` | 1 | 0 or 1 |
| `listener_id` | NULL | NULL matches every listener |
| `source_cidr` | NULL | NULL matches every actual peer; canonical CIDR |
| `action` | `ROUTE` | `ROUTE` or `REJECT` |
| `destination_hostgroup` | NULL | Required for every ROUTE, including inactive rows; must reference `tcp_hostgroups` |
| `comment` | `''` | Free-form text |

Rules use actual-peer CIDR matching and first-match order. `REJECT` must not
name a destination. A rule cannot override the mapping: `destination_hostgroup`
is a TCP hostgroup whose source mapping is mandatory. Every ROUTE destination,
including in an `active=0` row, must reference an existing mapped TCP hostgroup;
inactive rules are not exempt from referential validation.

## SQL quickstart

Create a MySQL source endpoint, map a TCP hostgroup to it, and expose a listener:

```sql
-- Normal native MySQL configuration. Its HGM owns selection/health/capacity.
DELETE FROM mysql_servers WHERE hostgroup_id = 10;
INSERT INTO mysql_servers
  (hostgroup_id, hostname, port, status, weight, max_connections, comment)
VALUES
  (10, '127.0.0.1', 3306, 'ONLINE', 1, 200, 'tcp source');
LOAD MYSQL SERVERS TO RUNTIME;

-- Mandatory TCP mapping plus listener.
DELETE FROM tcp_routing_rules;
DELETE FROM tcp_listeners;
DELETE FROM tcp_hostgroups;
INSERT INTO tcp_hostgroups
  (hostgroup_id, source_protocol, source_hostgroup, comment)
VALUES (20, 'MYSQL', 10, 'mysql application TCP');
INSERT INTO tcp_listeners
  (listener_id, active, bind_address, bind_port, default_hostgroup,
   max_connections, connect_timeout_ms, idle_timeout_ms, max_connect_attempts,
   comment)
VALUES (1, 1, '127.0.0.1', 16033, 20, 10000, 2000, 60000, 3, 'mysql listener');
LOAD TCP CONFIG TO RUNTIME;
```

A PostgreSQL mapping is identical except the source uses the PgSQL namespace:

```sql
INSERT INTO pgsql_servers
  (hostgroup_id, hostname, port, status, weight, max_connections, comment)
VALUES (30, '127.0.0.1', 5432, 'ONLINE', 1, 100, 'tcp pg source');
LOAD PGSQL SERVERS TO RUNTIME;

INSERT INTO tcp_hostgroups
  (hostgroup_id, source_protocol, source_hostgroup, comment)
VALUES (40, 'PGSQL', 30, 'pg application TCP');
LOAD TCP CONFIG TO RUNTIME;
```

Two TCP hostgroups sharing one source namespace and capacity:

```sql
INSERT INTO tcp_hostgroups (hostgroup_id, source_protocol, source_hostgroup)
VALUES (20, 'MYSQL', 10), (21, 'MYSQL', 10);
```

Both use the same backends in `MYSQL` hostgroup `10` and share each backend's
`max_connections` limit. A flow in group 20 consumes capacity on its selected
backend that is also available to group 21.

A source-address rule:

```sql
INSERT INTO tcp_routing_rules
  (rule_id, active, listener_id, source_cidr, action,
   destination_hostgroup, comment)
VALUES
  (1, 1, 1, '192.0.2.0/24', 'REJECT', NULL, 'management client'),
  (2, 1, 1, NULL, 'ROUTE', 20, 'default');
LOAD TCP CONFIG TO RUNTIME;
```

## Persistence and commands

The existing canonical commands and aliases remain:

```sql
LOAD TCP CONFIG TO RUNTIME;
SAVE TCP CONFIG FROM RUNTIME;
LOAD TCP CONFIG FROM DISK;
SAVE TCP CONFIG TO DISK;
```

Aliases: `LOAD TCP CONFIG FROM MEMORY`, `SAVE TCP CONFIG TO MEMORY`,
`LOAD TCP CONFIG TO MEMORY`, `SAVE TCP CONFIG FROM MEMORY`.

`LOAD ... TO RUNTIME` validates and activates all four editable tables as one
runtime generation. `SAVE ... FROM RUNTIME` copies that generation back to
editable Admin memory. `LOAD ... FROM DISK` copies disk configuration to editable
Admin memory; `SAVE ... TO DISK` copies editable Admin memory to disk. Neither
disk command changes the active runtime. Each copy is transactional. A failed
LOAD TO RUNTIME leaves the previous runtime generation and working listeners
intact. Disk copies preserve quotes, NUL-free text, tabs and every comment byte.
The mapping is saved in `tcp_hostgroups` and projected in
`runtime_tcp_hostgroups`; there is no TCP server or separate mapping projection.

Source protocol configuration has its own, separate persistence commands:

```sql
LOAD MYSQL SERVERS TO RUNTIME;
SAVE MYSQL SERVERS TO DISK;
LOAD PGSQL SERVERS TO RUNTIME;
SAVE PGSQL SERVERS TO DISK;
```

A native status/role/weight change is applied by its protocol command; it does
not require another TCP LOAD. `OFFLINE_HARD` from the source HGM closes an
established mapped stream and forbids retry of that accepted stream.
`OFFLINE_SOFT` and SHUNNED preserve established flows; the HGM decides whether
new admissions are eligible. Role changes follow the resulting native HGM
status. In particular, monitor-driven loss of the writer role marks the old
writer entry `OFFLINE_HARD`, which closes streams pinned to that entry. No TCP
LOAD is needed and established streams are never rerouted.

## Operational removal

### Soft removal (drain)

Set the source server's protocol status and load that protocol:

```sql
UPDATE mysql_servers SET status='OFFLINE_SOFT'
 WHERE hostgroup_id=10 AND hostname='127.0.0.1' AND port=3306;
LOAD MYSQL SERVERS TO RUNTIME;
```

Established flows continue. The source server receives no new admissions; other
eligible backends in its source hostgroup may still accept new connections.
To drain a whole mapped service, deactivate or remove its TCP listener and
`LOAD TCP CONFIG TO RUNTIME`. Alternatively, install an active `REJECT` rule
matching all peers on that listener, before any matching `ROUTE` rule, and load
the TCP configuration. Existing admitted flows continue draining in either case.
Disabling or removing a `ROUTE` rule alone does not stop new admissions: unmatched
connections use the listener's `default_hostgroup`.

### Hard removal (immediate disconnect)

```sql
UPDATE mysql_servers SET status='OFFLINE_HARD'
 WHERE hostgroup_id=10 AND hostname='127.0.0.1' AND port=3306;
LOAD MYSQL SERVERS TO RUNTIME;
```

The native HGM's HARD fence is authoritative. It immediately closes attached
and pending mapped streams, closes both sides and never reroutes or retries the
accepted stream.

### Endpoint replacement

Replace the endpoint in the protocol server table and load that protocol. An
established mapped flow remains pinned to its already-acquired HGM handle until
it closes or is fenced. New admissions use the replacement. Do not expect a TCP
`LOAD` to perform core server removal or health policy.

## Persistence, startup and `--no-start`

On first start with `--initial`, the core creates the exact four-table schema
and seeds `tcp_settings`. On later starts, saved four-table rows and their
protocol source rows are restored from the datadir.

`--no-start` exposes the Admin schema (including the four TCP tables) without
binding TCP listeners. `PROXYSQL START` starts them; `PROXYSQL STOP` stops the
relay and leaves no listening TCP port until the next START. Both are tested on
a saved mapped configuration.

To set startup-only relay options before the first START, seed the settings
row if it is absent, then edit it:

```sql
INSERT OR IGNORE INTO tcp_settings(id) VALUES(1);
UPDATE tcp_settings SET worker_threads=4, buffer_size=32768 WHERE id=1;
PROXYSQL START;
```

## Runtime, statistics and metrics

Runtime projections are `runtime_tcp_settings`, `runtime_tcp_hostgroups`,
`runtime_tcp_listeners`, `runtime_tcp_routing_rules` and
`runtime_tcp_status`. The mandatory mapping is part of
`runtime_tcp_hostgroups`; there is no server or separate mapping projection.
Statistics keep listener and rule rows/families only.

Status/diagnostic queries:

```sql
SELECT * FROM runtime_tcp_status;
SELECT * FROM runtime_tcp_settings;
SELECT * FROM runtime_tcp_hostgroups;
SELECT * FROM runtime_tcp_listeners;
SELECT * FROM runtime_tcp_routing_rules;
SELECT * FROM stats_tcp_listeners;
SELECT * FROM stats_tcp_rules;
SHOW PROMETHEUS METRICS;
```

Backend `ConnUsed`, `ConnFree`, `ConnOK`, `ConnERR`, `MaxConnUsed`,
`Bytes_data_sent`, `Bytes_data_recv`, role and health are read from the source
protocol HGM/stat tables, for example `stats_mysql_connection_pool` or
`stats_pgsql_connection_pool`. There is no `stats_tcp_servers`,
`proxysql_tcp_selected_total` or `proxysql_tcp_server_health` metric. TCP
metrics retain relay, listener, rule, generation and running families, with
actual application-byte accounting.
