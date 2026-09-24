# Backup weight threshold (within-hostgroup spares)

**Status:** Approved
**Tier:** `PROXYSQL31` (and therefore `PROXYSQL40`). Not in stable v3.0.x.

## Goal

Allow servers in a hostgroup to receive traffic **only when no primary server in that same hostgroup is available**, so that:

- p99 is not pulled by spare/DR/high-latency members while primaries are up;
- query routing stays inside the hostgroup the query processor already chose.

This is **not** a fallback hostgroup. A hostgroup is a set of servers with the same logical function. Crossing to another hostgroup after routing would be a routing lie. Spares are extra members of the same hostgroup, interpreted via weight.

## Non-goals

- No `fallback_hostgroup` on `mysql_hostgroup_attributes` / `pgsql_hostgroup_attributes` (issue #5670). mysqlx may keep its own route-level fallback; this feature does not share that path.
- No `mysql_servers.backup` / `pgsql_servers.backup` flag. A role bit follows a server across topology moves (reader → writer) and stays wrong; weight is a number interpreted by the hostgroup.
- No schema change to hostgroup-attribute tables (online upgrade + cluster cost).
- No change to query rules, `locked_on_hostgroup`, transactions, multiplex, or error 9001.
- No change to `weight = 0` (still never selected).
- Not in stable v3.0.x.

## Why not fallback hostgroup

Available vs not-available is already a local, binary view (shunning is per-proxy and not clustered). A fallback hostgroup would add a second routing decision after the query processor, and would put dissimilar functions (e.g. cache vs replica) behind one query rule. The supported answer for “only one class of backend should see traffic” remains: one backend enabled at a time, switched externally, if the operator wants to pay HA for p99.

Weight-threshold spares are for **same-function** members (e.g. local readers vs a far DR reader in the same reader hostgroup). Putting cache and DB in one hostgroup to hide the DB is still a homogeneity violation; this feature does not make that a recommended layout.

## Config

Keys in `mysql_hostgroup_attributes.hostgroup_settings` and `pgsql_hostgroup_attributes.hostgroup_settings` (existing JSON, already in the cluster checksum):

```json
{"backup_weight_threshold": 10, "backup_availability": "selectable"}
```

| Key | Missing default | Valid values |
|---|---|---|
| `backup_weight_threshold` | `0` (feature off) | integer `0 … 10000000` (same bounds as `mysql_servers.weight`) |
| `backup_availability` | `"selectable"` | `"selectable"` \| `"status"` \| `"capacity"` |

Parse in `init_myhgc_hostgroup_settings` (MySQL and PgSQL), same pattern as `handle_warnings` / `default_query_timeout`: invalid type or range → log error, **do not update that field**. Unknown JSON keys remain ignored (v3.0.x never sees these keys compiled in).

`BaseHGC::reset_attributes()` sets threshold `0` and availability `selectable`.

v3.0.x: do not declare the fields, do not parse the keys, do not two-pass, do not export the counters. A JSON blob that contains these keys is still valid JSON and loads; the keys are inert.

## Selection rule

Let `T = backup_weight_threshold`.

| Server weight | Role |
|---|---|
| `weight = 0` | Never selected, including when the primary set is empty |
| `weight >= T` | Primary |
| `0 < weight < T` | Backup |

`T = 0`: no weight is `< 0`, pass 2 is empty, behaviour identical to today (early-out).

If every server has `0 < weight < T`, the primary set is empty and backups are used. That is misconfiguration, not a deadlock.

### What “no primary available” means

`backup_availability` **only** decides whether to run pass 2. A returned server is always one that today’s `get_random_MySrvC` filters would accept (ONLINE, `max_connections`, latency, lag, GTID/Aurora as applicable). The mode must not cause an ineligible server to be returned.

- `"selectable"` (default): fall through iff pass 1 (full filters, `weight >= T`) is empty. This **is** the current candidate filter.
- `"status"`: fall through iff no primary (`weight >= T`, `weight > 0`) is ONLINE. A busy or high-latency ONLINE primary does **not** open the backup set; pass 1 may still return NULL (9001).
- `"capacity"`: fall through iff no primary is ONLINE **and** under `max_connections`. Latency/lag/GTID do not open the backup set.

### Algorithm (`get_random_MySrvC`, both protocols)

Gated with `#ifdef PROXYSQL31`. `T == 0` takes the existing path.

1. Pass 1: existing filters, keep `weight >= T` (and `weight > 0`). If non-empty, weighted random among them.
2. If pass 1 is empty **and** `T > 0` **and** the availability mode says no primary is present: pass 2, same existing filters, keep `0 < weight < T`. If non-empty, weighted random among them.
3. If still empty: today’s desperate unshun, then stop. An ONLINE backup is preferred over unshunning a recently failed primary.

MySQL GTID and Aurora lag stay inside the existing filters (`selectable`). PgSQL has the same two-pass; it simply has fewer extra filters.

### Unchanged surrounding behaviour

- Query processor / `destination_hostgroup` / `locked_on_hostgroup` / in-transaction connection: unchanged. Spares are in the same hostgroup.
- Multiplex: a connection already held on a backup is kept until released. The **next** `get_random_MySrvC` prefers primaries again if they are back.
- `max_num_online_servers` still disables the **whole** hostgroup (circuit breaker), including backups.
- Connect retries and query retries stay in the same hostgroup. Error 9001 is still the client-visible failure when nothing in the HG can be selected.
- Galera/GR `backup_writer_hostgroup` is unrelated (topology placement, not query-time selection). After a candidate master moves to the writer HG, that HG’s own `T` applies (writer HG default `T = 0` → normal selection).

## Observability

Rate-limited warning when pass 2 returns a server (same cadence as the current “no servers available” log).

Prometheus, hostgroup manager, `PROXYSQL31` only, labeled by `hostgroup`:

| Metric | Type |
|---|---|
| `proxysql_mysql_hostgroup_backup_server_selected_total` | counter, increment when pass 2 returns a server |
| `proxysql_pgsql_hostgroup_backup_server_selected_total` | counter, same |

Not 31-gated behind a second flag: the feature itself is 31. No “currently on backups” gauge (racy). No config gauges. Per-server `connection_pool_queries` already shows which endpoints received traffic.

## Implementation sketch

- `BaseHGC::attributes`: `backup_weight_threshold`, `backup_availability` enum, under `#ifdef PROXYSQL31`. Defaults in `reset_attributes()`.
- `init_myhgc_hostgroup_settings` in `MySQL_HostGroups_Manager.cpp` and `PgSQL_HostGroups_Manager.cpp`: parse the two keys.
- `MyHGC::get_random_MySrvC` and `PgSQL_HGC::get_random_MySrvC`: two-pass as above. Aurora/GTID/unshun stay in these functions; this work does not wire production to `ServerSelection.cpp`.
- `ServerSelection.cpp` / `server_selection_unit-t.cpp`: the same weight-tier split and availability modes, for unit tests only.
- Prometheus dyn counters on both hostgroup managers, `#ifdef PROXYSQL31`, labeled by `hostgroup` like `hostgroup_pool_*`.

No changes to `ProxySQL_Admin_Tables_Definitions.h` table DDL, cluster queries, or online-upgrade paths.

## Testing

### Unit (`test/tap/tests/unit/`)

Extend `server_selection_unit-t.cpp` (and `ServerSelection.cpp` as needed):

- `T = 0` → identical to today, including `weight = 0` never selected
- primaries present → never pick `0 < weight < T`
- primaries empty, backups eligible → pick backup; weighted random among backups
- all `weight = 0` → none
- all below `T` → backups used
- `backup_availability` `selectable` / `status` / `capacity` (max_conn, latency, lag)

### TAP (`PROXYSQL31=1` debug build, isolated harness)

One MySQL and one PgSQL test, registered with `@proxysql_min_version:3.1`:

- High-weight ONLINE → 0% of queries on low-weight servers
- Shun high-weight → traffic moves to low-weight; Prometheus counter increments only then
- Unshun high-weight → traffic returns to primaries
- `LOAD MYSQL SERVERS TO RUNTIME` / `LOAD PGSQL SERVERS TO RUNTIME` applies JSON without restart
- Invalid `backup_weight_threshold` / `backup_availability` values are logged and left at previous/default; valid sibling keys in the same JSON still apply

No new schema, cluster-sync, or online-upgrade tests.

## Documentation

Admin / hostgroup_settings docs: the two keys, the comparison rule, `weight = 0`, the three availability modes, and that this is not a fallback hostgroup and not a recommended way to mix cache with DB.
