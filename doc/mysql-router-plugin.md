# MySQL Router compatibility plugin

The `mysql_router` plugin lets a ProxySQL 4.0 build register with an InnoDB
Cluster as a MySQL Router-compatible instance. It reads MySQL InnoDB Cluster
Metadata 2.2, maintains ProxySQL-native servers, users, hostgroups, rules, and
listeners, and reconciles them as topology and account state change.

## Build and install

Build the core and the real plugin with the same feature tiers and toolchain:

```bash
make PROXYSQL40=1 PROXYSQL31=1 -j2
make PROXYSQL40=1 PROXYSQL31=1 -C plugins/mysql_router all
sudo make install
```

The source-tree artifact is
`plugins/mysql_router/proxysql_mysql_router.so`; `make install` places it in
`/usr/lib/proxysql/plugins/proxysql_mysql_router.so`. The plugin is part of the
ProxySQL 4.0 build surface and is not yet included in release packages.

## Bootstrap and normal startup

Supply the metadata password through a readable file descriptor. Passwords in
the bootstrap URI are rejected.

```bash
exec 3< /run/secrets/mysql-router-bootstrap-password
proxysql --load-plugin=mysql_router \
  --bootstrap cluster_admin@db1.example:3306 \
  --bootstrap-password-fd=3 \
  --router-name=proxysql-router-1
```

Bootstrap uses the MySQL Shell-compatible registration and account contracts,
stores the service credential through the core encrypted-secret service, and
publishes the first complete topology before marking local bootstrap complete.
After bootstrap, start ProxySQL normally while continuing to load the plugin:

```bash
proxysql --load-plugin=mysql_router
```

The plugin resumes from its persisted identity, starts its reconciliation
worker, and opens the Router-owned listener gates only after a complete live
generation is available. `MYSQL ROUTER RECONCILE` requests an immediate
reconciliation through the Admin interface.

## Endpoints

| Port | Behavior |
|---:|---|
| 6033 | Existing ProxySQL MySQL endpoint; fully operator-owned and query-aware |
| 6446 | Router Classic read/write endpoint; writer route, then fast-forward after the first `COM_QUERY` |
| 6447 | Router Classic read-only endpoint; eligible reader route, then fast-forward after the first `COM_QUERY` |
| 6450 | Router Classic read/write-split endpoint; remains query-aware and uses native ProxySQL query rules |

The port numbers above are defaults. `--conf-base-port` and the listener
options can move the three Router endpoints; behavior follows the compiled
endpoint intent, not a hard-coded port comparison.

The direct rules use the native query-rule attribute
`{"switch_to_fast_forward":true}`. Operators can insert a lower rule ID with
`apply=1` to override a Router default for selected users or traffic. Such
operator rules remain operator-owned and are preserved byte-for-byte during
Router reconciliation. The 6450 rules do not contain the fast-forward action,
so normal ProxySQL query processing, hostgroup selection, and transaction
tracking remain available there.

## Ownership and collisions

The plugin allocates eight hostgroups for stable writer/reader routes and
internal Group Replication, asynchronous-reader, and offline roles. It also
owns its five baseline rules, its three listener endpoints, and only the users
that were successfully normalized from metadata. Ownership is recorded in the
core plugin ledger in both memory and disk.

Publication is one atomic generation across main, disk, and live runtime.
Unrelated operator servers, users, rules, interfaces, and attributes are not
replaced. A collision with an operator-owned identity fails that object closed;
the plugin reports the conflict rather than taking ownership. Explicit user
release keeps the local row and transfers ownership to the operator.

## Status and diagnostics

Useful Admin queries include:

```sql
SELECT * FROM runtime_mysql_router_status;
SELECT * FROM runtime_mysql_router_topology;
SELECT * FROM runtime_mysql_router_hostgroups;
SELECT * FROM runtime_mysql_router_users;
SELECT * FROM stats_mysql_router_refresh ORDER BY refresh_id DESC LIMIT 20;
SELECT * FROM stats_mysql_router_errors ORDER BY last_seen DESC;
SELECT rule_id,proxy_port,destination_hostgroup,attributes,comment
  FROM runtime_mysql_query_rules WHERE comment LIKE 'mysql_router:%';
```

`runtime_mysql_router_status` reports metadata and registration availability,
active topology/user generations, gate readiness, staleness, collisions, and
the last error. Closed listener gates reject an accepted connection before a
session or MySQL handshake is created; they reopen only after the plugin has a
complete usable generation.

## Routing Guidelines

With InnoDB Cluster metadata 2.3 or 2.4 (created by MySQL Shell 9.2 or later), the
plugin applies MySQL Router Routing Guidelines managed with an unmodified MySQL
Shell (`createRoutingGuideline()`, `addDestination()`, `addRoute()`,
`setRoutingOption('guideline', ...)`). The plugin advertises
`SupportedRoutingGuidelinesVersion` 1.1 and reports `CurrentRoutingGuideline` in
`v2_routers`, so Shell accepts it as a Router that supports guidelines.

How a guideline is applied:

- The active guideline is selected like MySQL Router does (router option, then
  ClusterSet, then Cluster) and re-read on every topology refresh.
- Destinations (`$.server.*`) are evaluated against the live topology at every
  refresh. Each enabled route gets three plugin-owned hostgroups in the
  8000-8999 band (`rg:<route>:all|writer|reader`), published in the same atomic
  generation as the rest of the Router configuration.
- Routes (`$.session.*`, `$.router.*`) are evaluated per client session with the
  full expression language, through the ABI-10 MySQL route hook, when the
  session's first statement is routed. The hook only remaps the plugin's own
  `route_writer`/`route_reader` destinations on the Router listeners; any other
  destination selected by operator-owned `mysql_query_rules` is left unchanged,
  and operator rules are never modified.
- A session that matches no route, or whose route has no available destination,
  gets an error for the statement (the connection stays open).

Differences from MySQL Router (also reported per route in
`runtime_mysql_router_guideline_routes.notes`):

- Priority fallback uses the first destination group that has an available
  member at the last topology refresh.
- `round-robin` maps to equal weights and `first-available` to decreasing
  weights on ProxySQL's weighted load balancing.
- On the read/write split port, writes use the PRIMARY members and reads the
  other members of the route's first group that has them.
- `connectionSharingAllowed` is not applied; ProxySQL multiplexing rules apply.
- Existing sessions select a route again on their next statement after the
  guideline changes, instead of being disconnected.
- `$.router.routeName` is not supported inside destinations.

Invalid or unsupported documents never replace the last valid guideline: the
state becomes `stale` (or `invalid` when there is no previous valid guideline)
and the error is recorded in `stats_mysql_router_errors`. Removing the guideline
option releases the route hostgroups and restores the baseline routing.

```sql
SELECT * FROM runtime_mysql_router_guideline;
SELECT * FROM runtime_mysql_router_guideline_routes ORDER BY route_order, pool;
SELECT * FROM runtime_mysql_router_guideline_destinations;
SELECT * FROM stats_mysql_router_errors WHERE kind LIKE 'guideline_%';
```

## Supported scope

The current foundation supports InnoDB Cluster Metadata 2.2 to 2.4, Group
Replication members, MySQL Shell-managed asynchronous read replicas, and Routing
Guidelines on InnoDB Cluster (issue
[#6145](https://github.com/sysown/proxysql/issues/6145)).

Current exclusions are MySQL X Router endpoints, takeover of an existing MySQL
Router deployment, InnoDB ReplicaSet, ClusterSet (including their Routing
Guidelines), and release packaging. Each requires its own reviewed
implementation and acceptance plan.
