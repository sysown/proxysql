# PgBouncer compatibility

ProxySQL can read an existing PgBouncer deployment's configuration and can answer
PgBouncer's `SHOW` commands on its PostgreSQL admin port. Together these let a
PgBouncer installation be replaced without rewriting its configuration by hand and
without changing the monitoring that reads from it.

The implementation lives in `lib/pgbouncer_compat/` and is built into
`libproxysql.a` for every tier — there is no feature flag.

> This document describes the behaviour that is actually implemented. Where a
> PgBouncer feature has no ProxySQL equivalent it is listed as such rather than
> approximated, because a silent approximation is worse than a reported gap.

---

## 1. Importing a PgBouncer configuration

Two entry points, one conversion engine.

### `proxysql-cli` (offline)

`proxysql-cli` is the `proxysql` binary under a second name. `main()` compares
`basename(argv[0])` against `proxysql-cli` and dispatches to the CLI without ever
starting the daemon. Packages install it as a symlink next to `proxysql`.

```bash
# Print the SQL that would be applied, with an explanatory comment per statement
proxysql-cli import-pgbouncer /etc/pgbouncer/pgbouncer.ini --dry-run

# Warn on unmappable parameters instead of failing
proxysql-cli import-pgbouncer /etc/pgbouncer/pgbouncer.ini --ignore-warnings

# Apply against a running instance
proxysql-cli import-pgbouncer /etc/pgbouncer/pgbouncer.ini \
  | psql -h 127.0.0.1 -p 6132 -U admin
```

### `IMPORT PGBOUNCER CONFIG` (online)

From the admin interface:

```sql
IMPORT PGBOUNCER CONFIG FROM '/etc/pgbouncer/pgbouncer.ini';
IMPORT PGBOUNCER CONFIG FROM '/etc/pgbouncer/pgbouncer.ini' DRY RUN;
IMPORT PGBOUNCER CONFIG FROM '/etc/pgbouncer/pgbouncer.ini' IGNORE WARNINGS;
IMPORT PGBOUNCER CONFIG FROM '/etc/pgbouncer/pgbouncer.ini' DRY RUN IGNORE WARNINGS;
```

The path is read by the **server**, not the client.

### Import-once, strict by default

The import bootstraps ProxySQL; from then on the admin interface owns the
configuration. There is no continuous sync back to `pgbouncer.ini`.

By default the import is **strict**: any parameter that cannot be mapped is an
error and nothing is applied. `IGNORE WARNINGS` / `--ignore-warnings` downgrades
those to warnings and applies the rest. Strictness is deliberate — a partially
imported pooler configuration is a production incident waiting to happen.

The converter rewrites `pgsql_servers`, `pgsql_users` and `pgsql_query_rules`
from scratch (each is `DELETE`d before its `INSERT`s), so an import replaces the
PostgreSQL-side configuration rather than merging into it.

---

## 2. What the parser reads

| File | Parsed by | Notes |
|---|---|---|
| `pgbouncer.ini` | `PgBouncer_ConfigParser` | `[pgbouncer]`, `[databases]`, `[users]`, `[peers]`; `%include` to 10 levels |
| `userlist.txt` | `PgBouncer_AuthFileParser` | `"user" "password"`; detects plain / MD5 / SCRAM |
| `pg_hba.conf` | `PgBouncer_HBAParser` | followed when `auth_hba_file` is set |

Quoting follows PgBouncer: a single-quoted value in `[pgbouncer]` protects spaces
and `#`/`;`, and `''` is a literal quote. In `pg_hba.conf`, `""` inside a
double-quoted token is a literal quote, and an unterminated quote is an error
rather than a silently truncated field.

---

## 3. Configuration mapping

### Global settings

| PgBouncer | ProxySQL | Note |
|---|---|---|
| `listen_addr` + `listen_port` | `pgsql-interfaces` | |
| `max_client_conn` | `pgsql-max_connections` | |
| `server_connect_timeout` | `pgsql-connect_timeout_server` | |
| `server_lifetime` | `pgsql-connection_max_age_ms` | s → ms |
| `client_idle_timeout` | `pgsql-wait_timeout` | s → ms |
| `log_min_duration` | `pgsql-long_query_time` | |
| `idle_transaction_timeout` | `pgsql-max_transaction_idle_time` | s → ms |
| `transaction_timeout` | `pgsql-max_transaction_time` | s → ms |
| `max_prepared_statements` | `pgsql-max_stmts_per_connection` | |
| `server_tls_sslmode` | `use_ssl` on all imported servers | `require`/`verify-ca`/`verify-full` |
| `server_tls_ca_file` | `pgsql-ssl_p2s_ca` | |
| `server_tls_cert_file` | `pgsql-ssl_p2s_cert` | |
| `server_tls_key_file` | `pgsql-ssl_p2s_key` | |
| `server_check_query` | `pgsql-monitor_enabled=1` | |
| `server_check_delay` | `pgsql-monitor_ping_interval` | s → ms |
| `tcp_keepalive` | `pgsql-use_tcp_keepalive` | |
| `tcp_keepidle` | `pgsql-tcp_keepalive_time` | |

### `[databases]`

Each entry becomes a hostgroup with one `pgsql_servers` row per host (a
comma-separated `host=` list yields several rows in the same hostgroup), plus a
`pgsql_query_rules` row routing that database name to the hostgroup. The `*`
wildcard database becomes the default hostgroup and gets no routing rule.
`pool_size` maps to `max_connections` on the server row.

### `[users]` and `userlist.txt`

Each user becomes a `pgsql_users` row. `pool_mode` maps as:

| PgBouncer `pool_mode` | ProxySQL |
|---|---|
| `session` | `fast_forward=1` |
| `transaction` | `transaction_persistent=1` |
| `statement` | neither flag |

### `pg_hba.conf`

`host`/`hostssl` records with `trust`, `md5`, `scram-sha-256` or `password`
become `pgsql_firewall_whitelist_rules` entries and enable
`pgsql-firewall_whitelist_enabled`. `hostssl` additionally sets `use_ssl=1` on
the matching users.

---

## 4. What is *not* mapped

These are reported per occurrence — fatal in strict mode, warnings otherwise.

**Authentication.** `auth_query`, `auth_user`, `auth_dbname`. ProxySQL
authenticates from `pgsql_users` (or LDAP), not by querying the backend.

**Pre-hashed passwords.** A `userlist.txt` entry holding an MD5 or SCRAM verifier
is imported verbatim but **will not authenticate**. ProxySQL derives both the MD5
challenge response and the SCRAM verifier from the *cleartext* password stored in
`pgsql_users.password`, so a pre-hashed value cannot be used. Replace those
entries with the cleartext password after importing.

**`dbname=` aliases.** PgBouncer's `dbname=` connects to a backend database under
a different name than the client asked for. ProxySQL routes to a hostgroup but
does not rewrite the database in the startup packet, so the alias cannot be
honoured.

**HBA `reject` rules.** The ProxySQL firewall whitelist is allow-only and has no
deny entry, so a `reject` that precedes a broader allow cannot be reproduced —
the allow would win. Enforce the denial upstream.

**HBA `local` / `hostnossl` records**, and the `cert`, `peer`, `pam`, `ident`,
`gss` and `sspi` methods.

**Clustering.** `peer_id` and the `[peers]` section — use ProxySQL Cluster.

**No equivalent.** `so_reuseport`, `disable_pqexec`, `application_name_add_host`,
`dns_zone_check_period`, `resolv_conf`, a non-default `server_reset_query`,
`sbuf_loopcnt`, `pkt_buf`.

---

## 5. PgBouncer `SHOW` commands

Available on the **PostgreSQL admin port**. Each command also accepts a
`SHOW EXTENDED <command>` form that appends ProxySQL-specific columns to the
right of the PgBouncer-compatible ones, so a tool reading by column position or
by the documented PgBouncer names keeps working.

| Command | Backed by |
|---|---|
| `SHOW POOLS` | `stats_pgsql_connection_pool` |
| `SHOW STATS` | `stats_pgsql_query_digest` |
| `SHOW SERVERS` | `stats_pgsql_connection_pool` (+ `runtime_pgsql_servers` when extended) |
| `SHOW CLIENTS` | `stats_pgsql_processlist` |
| `SHOW DATABASES` | `runtime_pgsql_servers` |
| `SHOW USERS` | `runtime_pgsql_users` |
| `SHOW CONFIG` | `global_variables` (`pgsql-` prefix stripped) |
| `SHOW VERSION` | identifies as ProxySQL in PgBouncer compatibility mode |
| `SHOW STATE` | always `active` |
| `SHOW LISTS` | object counts |

Rejected with an explanatory error: `SHOW DNS_HOSTS`, `SHOW DNS_ZONES`,
`SHOW FDS`, `SHOW PEERS`, `SHOW PEER_POOLS`, `SHOW MEM`, `SHOW ACTIVE_SOCKETS`,
`SHOW SOCKETS`.

Some columns are structurally absent from ProxySQL and are reported as `0` or the
empty string rather than omitted, so the column count stays stable: per-client
wait times, `local_addr`/`local_port` on servers, socket pointers (`ptr`, `link`)
and `prepared_statements`.

### Interaction with ProxySQL's own `SHOW`

The translation runs **before** ProxySQL's generic `SHOW` handling, because
ProxySQL already owns some of the same command words — `SHOW DATABASES` most
notably. Only the exact command set above is claimed: anything with a trailing
token (`SHOW POOLS foo`) falls through to normal admin handling, as does every
other `SHOW`.

---

## 6. Tests

| Test | Covers |
|---|---|
| `test/tap/tests/unit/pgbouncer_config_parser_unit-t` | INI / userlist / HBA parsing, quoting, includes, malformed input |
| `test/tap/tests/unit/pgbouncer_converter_unit-t` | mapping rules, strict vs relaxed, generated column names |
| `test/tap/tests/unit/pgbouncer_show_commands_unit-t` | `SHOW` translation and rejection |
| `test/tap/tests/pgsql-pgbouncer_compat-t` | **executes** every `SHOW` and every generated statement against a live admin port |

The integration test matters disproportionately here. The unit tests compare
generated strings, which cannot catch a wrong column name — and three such
defects (`pgsql_query_rules.schemaname`, `stats_pgsql_processlist.db`, and
reading `weight`/`max_connections` from `stats_pgsql_connection_pool`) passed the
full unit suite while being unable to execute. Any new mapping or `SHOW`
translation must be exercised by `pgsql-pgbouncer_compat-t`, not by a string
comparison alone.
