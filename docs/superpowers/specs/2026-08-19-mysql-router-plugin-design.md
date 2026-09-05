# MySQL Router Plugin for ProxySQL 4.0 — Design

**Status:** Design approved; implementation plan pending
**Date:** 2026-08-19
**Target:** ProxySQL 4.0 (`PROXYSQL40`)
**Plugin identifier:** `mysql_router`

## Executive summary

ProxySQL 4.0 will provide an optional `mysql_router` plugin that integrates a
ProxySQL instance with one MySQL AdminAPI topology and makes it visible to an
unmodified MySQL Shell as a registered routing component.

The plugin supports MySQL 8.4 and newer and all three AdminAPI topology types:

- InnoDB Cluster, including asynchronous read replicas
- InnoDB ReplicaSet
- InnoDB ClusterSet

The compatibility boundary is deliberately asymmetric:

- **Control-plane compatibility:** bootstrap, topology discovery, metadata
  registration, MySQL Shell integration, standard Classic ports, Router
  options, and takeover of an existing Router deployment.
- **ProxySQL-native data plane:** hostgroups, monitoring, connection pooling,
  query rules, transaction tracking, and read/write splitting retain ProxySQL
  semantics. The plugin does not reproduce MySQL Router's packet-forwarding or
  routing engine.

The initial scope excludes Routing Guidelines and MySQL X endpoints. It uses
the familiar Classic endpoints 6446 (writer), 6447 (reader), and 6450
(read/write split), while leaving the normal ProxySQL endpoint 6033 intact.

## Motivation

ProxySQL already has the core capabilities needed to route traffic to MySQL
high-availability topologies, but using it in place of MySQL Router still
requires manual hostgroup, user, monitoring, and query-rule configuration.
MySQL Shell also has no metadata record through which it can report or manage
the ProxySQL instance.

The desired experience is:

1. Point ProxySQL at an AdminAPI topology, or at an existing
   `mysqlrouter.conf`.
2. Let the plugin discover and continuously reconcile topology and application
   accounts.
3. Use unmodified MySQL Shell commands to list the instance and manage
   supported Router options.
4. Connect applications to familiar Router ports while using ProxySQL's native
   routing and read/write-splitting capabilities.

One AdminAPI topology is managed per ProxySQL instance. The plugin owns a
bounded set of hostgroups for that topology; operators may continue using
other hostgroups for unrelated ProxySQL routing.

## Current implementation assessment

The existing bootstrap prototype is spread across:

- `lib/ProxySQL_GloVars.cpp` and `include/proxysql_glovars.hpp` for CLI state
- `src/main.cpp` for bootstrap execution and metadata connections
- `lib/Admin_Bootstrap.cpp` and `include/proxysql_admin.h` for configuration
  materialization

It is a useful proof of concept, but is not a MySQL Router integration layer:

- It discovers `performance_schema.replication_group_members` directly rather
  than consuming AdminAPI metadata.
- It handles only a Group Replication group, not ReplicaSet or ClusterSet.
- It does not register in `mysql_innodb_cluster_metadata.v2_routers`, update
  check-in state, or consume per-Router options.
- It configures only the 6446 and 6447 Classic endpoints.
- Several parsed options, including socket and account-host choices, are not
  reflected completely in the generated configuration.
- It replaces broad server and user state rather than reconciling an explicit
  managed scope.
- It imports account data without a complete ongoing synchronization and
  collision policy.
- It stores bootstrap state and credentials without a Router-equivalent secure
  secret abstraction.
- Test coverage is limited mainly to argument parsing; there is no end-to-end
  bootstrap, Shell, topology-change, or failover suite.

The ProxySQL 4.0 plugin chassis also needs extension. Plugins are currently
loaded after core CLI parsing and the legacy bootstrap path, which is too late
for a plugin-owned bootstrap action. Snapshot services in
`include/ProxySQL_Plugin.h` are not yet sufficient for atomic topology and
configuration publication. The current query hook is an allow/deny hook and
is not relevant to this design because routing remains native to ProxySQL.

## Goals

1. Integrate with an unmodified MySQL Shell 8.4 or newer.
2. Support InnoDB Cluster, ReplicaSet, and ClusterSet.
3. Register and maintain a normal AdminAPI Router metadata record.
4. Support MySQL metadata schema 2.2 as the baseline and capability-negotiate
   newer compatible 2.x schemas.
5. Add standard Classic ports 6446, 6447, and 6450 to `mysql-interfaces` when
   the plugin profile is bootstrapped.
6. Use ProxySQL-native hostgroups, monitors, query processing, and connection
   pooling.
7. Continuously reconcile a well-defined set of plugin-managed hostgroups.
8. Synchronize plugin-created application users while preserving
   operator-created users.
9. Import an existing MySQL Router configuration and adopt its metadata
   identity where safe.
10. Keep all AdminAPI- and MySQL-Router-specific behavior inside the plugin;
    core changes must be generic plugin-chassis capabilities.

## Non-goals for the initial release

- Routing Guidelines
- MySQL X endpoints 6448 and 6449
- MySQL Router packet-forwarding semantics
- Exact connection-pinning parity
- Reimplementation of Router's read/write-splitting engine
- Byte-for-byte generation of Router configuration, state, keyring, or service
  artifacts
- Support for MySQL Server or MySQL Shell older than 8.4
- Support for metadata schema 1.x
- Management of more than one AdminAPI topology by one plugin instance

An optional Router-artifact export may be considered later for operational
rollback or legacy tooling. It is not required for the initial release.

## Architectural decision

The selected architecture is a control-plane plugin over ProxySQL's existing
data plane:

```text
Unmodified MySQL Shell
          |
          v
AdminAPI metadata <----> mysql_router plugin
                              |
                    desired topology and options
                              |
                              v
                 ProxySQL hostgroups and users
                              |
                              v
                 Native ProxySQL query routing
```

The plugin owns bootstrap, metadata-version adapters, topology interpretation,
Shell-visible registration, Router-option translation, managed-hostgroup
reconciliation, managed-user synchronization, and existing-Router import.

ProxySQL core continues to own the Classic protocol, frontend authentication,
query processing, transaction tracking, backend connection pools, monitoring,
and load balancing.

### Rejected alternatives

**Full Router data plane inside the plugin.** This would duplicate Classic and
X protocol listeners, authentication, connection pools, and monitoring. It
would effectively embed a second proxy and discard the main reasons to deploy
ProxySQL.

**Metadata-to-SQL adapter using only today's plugin ABI.** This could prototype
basic InnoDB Cluster discovery, but would depend on raw internal SQLite state,
would start at the wrong lifecycle phase, and could not publish topology and
user changes atomically. It is not a stable production architecture.

## ProxySQL 4.0 core boundary

### Removal of legacy bootstrap

All existing bootstrap-specific core code is excluded under `PROXYSQL40`,
using `#ifndef PROXYSQL40` around the current CLI definitions, globals,
execution path, `Admin_Bootstrap` materialization, and bootstrap-only storage.

ProxySQL 3.x retains the existing implementation unchanged. ProxySQL 4.0 has
no built-in knowledge of MySQL Router or AdminAPI. If bootstrap is requested
without a plugin claiming the action, it reports that no bootstrap provider is
installed.

### Required generic chassis extensions

The chassis gains the following generic facilities:

1. **Early plugin discovery.** Discover manifests and validate ABI compatibility
   before complete CLI parsing.
2. **Action and option registration.** Allow a plugin to register one-shot CLI
   actions and their options. Parsing is two-pass: locate/load the requested
   plugin first, then parse the plugin-extended CLI.
3. **Minimal action services.** One-shot actions may use logging, filesystem,
   cryptography, outbound MySQL connectivity, secure secrets, and transactional
   configuration storage without starting the full proxy.
4. **Runtime-ready callback.** Start reconciliation only after Admin,
   authentication, hostgroups, query processing, and monitoring are ready.
5. **Atomic configuration transactions.** Publish a complete set of scoped
   server, hostgroup, user, interface, and tagged baseline-rule changes or none
   of them.
6. **Managed-listener readiness.** Allow plugin-added listeners to reject or
   defer traffic until their initial topology has been validated without
   blocking Admin or unrelated listeners.
7. **Secure secret service.** Store plugin service-account credentials without
   plaintext plugin tables.
8. **Typed snapshots and status registration.** Replace stub snapshot accessors
   with versioned, owned snapshots and continue using plugin-registered Admin
   and stats views.

These are chassis capabilities, not MySQL Router APIs. Other topology and
configuration plugins should be able to reuse them.

### Lifecycle

The lifecycle is:

1. Discover and ABI-validate installed/configured plugins.
2. Register plugin actions and options.
3. Parse the complete command line.
4. For a one-shot action, initialize minimal services, invoke the owner, commit
   or roll back its configuration transaction, and exit.
5. For normal startup, initialize ProxySQL core and configured plugins.
6. Invoke the runtime-ready callback.
7. Let `mysql_router` validate the persisted topology, reconcile state, and
   mark its listeners ready.

A plugin failure never falls back silently to the removed 4.0 bootstrap path.

## Plugin identity and naming

The public naming is:

| Purpose | Name |
|---|---|
| Plugin identifier | `mysql_router` |
| Shared library | `proxysql_mysql_router.so` |
| CLI selector | `--load-plugin=mysql_router` |
| Configuration namespace | `mysql_router.*` |
| Ownership marker | `mysql_router` |
| Prometheus prefix | `proxysql_mysql_router_*` |

The word `compat` is intentionally absent. This is a supported MySQL Router
integration, not a provisional compatibility shim.

## Metadata and topology model

The plugin maintains three immutable, versioned models:

```text
AdminAPI metadata ----> DesiredTopology
Live server state ----> ObservedHealth
                             |
                             v
                    EffectiveTopology
```

### Desired topology

`DesiredTopology` contains:

- Metadata schema version and capabilities
- Topology type, UUID, and name
- Clusters and instances known to AdminAPI
- ClusterSet membership, primary cluster, invalidation, and selected target
- InnoDB Cluster read replicas
- Instance addresses, roles, attributes, and tags
- Supported global and per-Router options
- Router registration and endpoint state

### Observed health

`ObservedHealth` contains live routing eligibility:

- Reachability and connection health
- Group Replication membership, role, quorum, and state
- ReplicaSet replication/source state
- `read_only`/`super_read_only` and writable-role observations
- Replication lag where ProxySQL supports it
- Monitor-derived online, shunned, and offline state

AdminAPI metadata describes intended membership and policy; live observations
decide whether an intended member is currently safe to use. The plugin must
not infer topology identity solely from `performance_schema`.

### Metadata adapters

The baseline is metadata schema 2.2 from MySQL 8.4. Later compatible 2.x
schemas use explicit capability adapters. Examples include schema-specific
Router check-in storage and newly available Router attributes.

The plugin probes metadata schema objects and version compatibility rather
than guessing from the MySQL Shell version. An unsupported newer schema fails
with a precise error before publishing configuration. Metadata 1.x is rejected.

### Topology anchoring

One plugin instance is permanently anchored to one AdminAPI topology UUID
until explicit replacement. A hostname or seed address is never treated as
topology identity. Reusing an address for a different topology cannot silently
retarget ProxySQL.

## Bootstrap

### Native bootstrap

A new deployment uses a plugin-owned action, for example:

```bash
proxysql --load-plugin=mysql_router \
         --bootstrap admin@db1.example:3306 \
         --router-name=proxysql-east
```

The administrator password is prompted securely or read from a protected file
descriptor. It is never accepted as a visible command-line password.

Native bootstrap:

1. Connects to the seed and discovers the authoritative metadata server.
2. Validates MySQL 8.4+, metadata compatibility, topology identity, and safe
   topology state.
3. Detects InnoDB Cluster, ReplicaSet, or ClusterSet.
4. Creates or validates the plugin service account and minimal grants.
5. Registers or updates the instance in `v2_routers`.
6. Allocates collision-free managed hostgroups and persists their mapping.
7. Adds Classic ports 6446, 6447, and 6450 to existing `mysql-interfaces`.
8. Seeds tagged baseline query rules while preserving all unrelated rules.
9. Materializes the initial managed servers and users.
10. Stores service credentials through the secure secret service.
11. Persists `mysql_router` in the normal plugin load configuration.

Re-running bootstrap against the same topology is idempotent. Replacing the
managed topology requires an explicit replacement option.

Remote AdminAPI metadata and the local ProxySQL database cannot share one
transaction. Bootstrap therefore uses stable topology/router identities and
idempotent operations, and records enough progress to resume safely.

## Existing MySQL Router takeover

An existing Router deployment can be imported, for example:

```bash
proxysql --load-plugin=mysql_router \
         --import-mysqlrouter=/etc/mysqlrouter/mysqlrouter.conf
```

The importer reads:

- Metadata bootstrap addresses and topology identity
- Router name and `router_id`
- Metadata service-account username
- Classic RW, RO, and R/W-split bind addresses, ports, and sockets
- TLS settings relevant to the supported Classic endpoints
- Metadata-cache refresh settings
- Dynamic-state and keyring locations
- Route intent that maps to writer, reader, or native R/W split

When the configuration and metadata identity match, the plugin adopts the
existing `v2_routers` row. This preserves Shell-visible identity and per-Router
options. The operator must stop the old Router before takeover; port conflicts
cause import/bootstrap to fail.

The importer follows references to the dynamic-state and keyring files. If the
keyring and master key can be read safely, credentials are migrated into the
ProxySQL secure-secret service. Unsupported external key providers or
undecryptable keyrings cause a credential prompt or replacement-account flow;
they never cause silent secret loss.

An imported Router service account normally has metadata-cache grants but not
the additional account-definition read privilege required by managed-user
synchronization. Import validates this separately. When it is missing, the
operator supplies bootstrap-administrator credentials so the importer can add
the narrow grant, or selects a separately provisioned plugin service account.
Import never assumes that possession of the existing Router password permits
the plugin to grant itself more privileges.

Original Router files are read-only migration inputs. They are not overwritten
or deleted, preserving a rollback path. After successful import, ProxySQL's
configuration database is authoritative.

Every section receives one of three outcomes in the import report: imported,
translated, or unresolved. X routes and Routing Guidelines are reported as
unsupported in the initial release rather than silently discarded.

## Unmodified MySQL Shell contract

The plugin writes the AdminAPI metadata contract expected by MySQL Shell.

The initial registration advertises:

| Field | Value |
|---|---|
| `product_name` | `ProxySQL` |
| `version` | Implemented MySQL Router contract, initially `8.4.0` |
| RW endpoint | Configured 6446 endpoint |
| RO endpoint | Configured 6447 endpoint |
| R/W-split endpoint | Configured 6450 endpoint |
| X endpoints | Unset |
| Supported Routing Guidelines version | Unset |

The actual ProxySQL and plugin versions are stored in separate custom
attributes. The Router `version` field is a compatibility contract because
MySQL Shell uses it for feature and configuration-schema decisions.

The metadata allows these unmodified Shell operations to work normally:

- `listRouters()`
- `routerOptions()`
- `routingOptions()`
- `setRoutingOption()`
- `setupRouterAccount()`
- `removeRouterMetadata()`

The plugin consumes supported 8.4 options as follows:

| Topology | Consumed options |
|---|---|
| InnoDB Cluster | `read_only_targets`, `unreachable_quorum_allowed_traffic`, `stats_updates_frequency` |
| ReplicaSet | `stats_updates_frequency` |
| ClusterSet | `target_cluster`, `invalidated_cluster_policy`, `use_replica_primary_as_rw`, `read_only_targets`, `stats_updates_frequency` |

Tags remain stored and visible but have no routing effect without Routing
Guidelines. Newer Shell versions see an 8.4-compatible component that does not
advertise guideline support. The compatibility version is raised only when
the associated behavior is implemented.

The plugin updates `last_check_in` in the schema-appropriate location. If a
running registration is removed through Shell, the plugin does not silently
recreate it. It continues with the last safe topology, reports an unregistered
state, and requires re-bootstrap to register again.

## Native ProxySQL routing

The plugin adds these defaults to `mysql-interfaces` while preserving existing
interfaces:

| Port | Purpose | ProxySQL behavior |
|---:|---|---|
| 6033 | Existing general endpoint | Unchanged |
| 6446 | Writer endpoint | Route to stable managed writer hostgroup |
| 6447 | Reader endpoint | Route to stable managed reader hostgroup |
| 6450 | R/W-split endpoint | ProxySQL-native query routing |

Port-aware baseline query rules use `proxy_port`. For 6450, eligible reads use
the stable reader hostgroup, while writes, locking reads, unsafe or ambiguous
statements, and transaction-sensitive traffic use the stable writer
hostgroup. ProxySQL's existing parser, transaction persistence, multiplexing,
query rules, and connection pooling remain authoritative.

This is not an attempt to duplicate Router internals. Applications receive
familiar endpoint intent, but observable routing and pooling semantics are
ProxySQL's.

## Hostgroup materialization and ownership

Bootstrap allocates and persists a collision-free set of managed hostgroup
IDs. The exact IDs are local implementation details and are visible through
Admin status.

The managed set includes, as required by the topology:

- Stable route-facing writer and reader hostgroups
- InnoDB Cluster GR writer, backup-writer, reader, and offline groups
- Separate asynchronous read-replica groups
- ReplicaSet source, replica, and offline groups
- ClusterSet role groups for each constituent cluster

The stable writer and reader groups decouple port/query rules from topology
changes. For example, switching a ClusterSet target changes managed membership
without rewriting all operator routing rules. Separate internal groups also
prevent asynchronous read replicas from being treated as GR members.

Within the persisted managed hostgroup set, the plugin is authoritative. It
may add, update, move, or delete rows that differ from the effective topology.
Direct Admin writes remain allowed, but drift inside managed hostgroups may be
corrected at the next reconciliation.

All hostgroups outside the managed set are operator-owned. The plugin never
changes their servers or related hostgroup configuration. Operators may use
them for other backends and may route to them through normal query rules.

The plugin owns only its tagged baseline query rules. It never deletes or
rewrites unrelated rules. Operator rules with higher priority may refine or
override the defaults.

## User synchronization and ownership

The plugin reads supported application-account definitions from the
authoritative topology writer and materializes ProxySQL users needed for
native frontend and pooled backend authentication.

The service account receives the standard Router metadata grants plus the
narrowest practical read privilege for required account-definition fields.
Startup validates the grants and reports exact missing privileges.

Plugin-created users are recorded in a private ownership registry tied to the
topology UUID and carry a visible ownership marker. Reconciliation may update
or remove only those managed rows. Operator-created `mysql_users` rows remain
untouched.

If an operator modifies a managed user, reconciliation may restore the
topology-derived values. An explicit exclusion/release mechanism transfers a
managed username to operator ownership.

Because `mysql_users` is keyed by username while MySQL permits multiple
`user@host` rows:

- Identical active variants may be collapsed.
- Conflicting credentials or security policies fail that username closed and
  appear in status.
- A pre-existing operator-owned username wins a collision. The plugin
  preserves it and reports that the topology user could not be materialized.

The primary MySQL 8.4 path is `caching_sha2_password`. ProxySQL validates the
imported verifier through full authentication, learns the credential required
for backend pooling, and keeps the learned cleartext only in the existing
runtime credential cache. Supported native-password flows use ProxySQL's
existing hash-learning path. Unsupported authentication plugins remain
inactive and are reported; the plugin never pretends that an unusable account
was synchronized successfully.

Password/account changes produce a complete new managed-user generation.
Failed or partial account reads retain the previous generation.

## Reconciliation

Topology and user synchronization are separate atomic generations:

- A complete effective-topology snapshot replaces rows only in managed
  hostgroups and related managed hostgroup configuration.
- A complete account snapshot updates only plugin-owned users.
- A topology failover is not delayed by an account-query failure.
- A user refresh cannot partially delete a working user set.

Each candidate snapshot is validated before publication. A failed transaction
leaves the previous runtime and persisted generation active.

For ClusterSet, the plugin interprets the selected target, invalidation policy,
read-only target policy, and replica-primary policy before updating stable
writer/reader membership. For ReplicaSet and InnoDB Cluster, metadata
membership is combined with live replication/GR observations.

## Failure behavior

The runtime policy is "last validated metadata, current live health":

- Temporary metadata loss does not immediately stop traffic.
- Persisted topology remains available as the intended membership.
- Native ProxySQL monitoring continues to shun unhealthy or role-invalid
  servers.
- Metadata-derived additions, removals, and ClusterSet target changes pause
  until metadata returns.
- Writes fail when no eligible managed writer exists.
- Read availability during quorum loss or invalidation follows supported Shell
  options.
- A failed user refresh retains the last valid managed-user generation.

At startup, persisted rows can initialize core state, but plugin-managed ports
remain not-ready until the plugin validates topology identity and starts live
monitoring. Admin, port 6033, and unmanaged hostgroups remain independent.

If the plugin stops unexpectedly, core retains the last committed rows and
marks their status stale. An intentional uninstall/removal deletes only
plugin-owned hostgroup rows, users, baseline rules, registration, and secret
material. Unmanaged configuration is preserved.

## Admin and observability

The plugin registers:

- `runtime_mysql_router_status`
- `runtime_mysql_router_topology`
- `runtime_mysql_router_hostgroups`
- `runtime_mysql_router_users`
- `stats_mysql_router_refresh`
- `stats_mysql_router_errors`
- `stats_mysql_router_import`

`runtime_mysql_router_users` never exposes password verifiers, cleartext, or
learned credentials.

Status includes topology type/UUID, metadata version, advertised Router
contract, registration ID, selected ClusterSet target, managed hostgroup IDs,
server/user generations, refresh timestamps, stale duration, user collisions,
unsupported authentication plugins, registration loss, and import warnings.

Prometheus metrics use `proxysql_mysql_router_*` and cover metadata
availability, reconciliation success/failure, topology and user generations,
managed servers by role, writer/target changes, detected drift, unresolved
users, and stale-state duration.

Logs are transition-oriented. Polling does not repeat the same warning each
cycle. A forced-reconciliation Admin command refreshes topology and users but
still publishes only complete validated snapshots.

## Security

- Bootstrap administrator credentials are never persisted.
- Plugin service-account credentials use the core secure-secret service.
- Existing Router keyrings are opened read-only during import.
- Imported application-account verifiers follow normal `mysql_users` storage;
  learned cleartext follows the existing in-memory ProxySQL authentication
  cache and is never exposed through plugin views.
- Account-reading grants are limited to the fields required for supported
  synchronization.
- Unknown/unsupported authentication types fail closed.
- A topology UUID mismatch prevents automatic retargeting.
- Import never executes an external Router key-provider command silently;
  unsupported providers require explicit operator action.

## Testing strategy

### Unit tests

- Metadata schema/capability adapters for 2.2 and newer supported 2.x versions
- Topology-type parsing and topology UUID anchoring
- ClusterSet target/invalidation option translation
- Effective-topology compiler
- Managed-hostgroup allocation, drift detection, and scoped deletion
- Managed-user ownership, removal, release, and collision handling
- Authentication-plugin classification
- `mysqlrouter.conf`, dynamic-state, and keyring import parsing
- Idempotent bootstrap/retry state machine
- Import-report classification

### Integration matrix

Test unmodified MySQL Shell 8.4 and the newest supported Shell against MySQL
8.4 and the newest supported innovation release. The topology matrix includes:

- Single- and multi-member InnoDB Cluster
- Primary failover and quorum loss
- InnoDB Cluster read replicas
- ReplicaSet source change and replica failure
- ClusterSet with primary and replica clusters
- ClusterSet target changes, invalidation, and failover

The functional matrix includes:

- Native bootstrap and idempotent re-bootstrap
- `listRouters()`, `routerOptions()`, `routingOptions()`,
  `setRoutingOption()`, `setupRouterAccount()`, and metadata removal
- 6446 writer routing
- 6447 reader routing and balancing
- 6450 ProxySQL-native reads, writes, locking reads, and transactions
- Coexistence with operator query rules, users, servers, and unmanaged
  hostgroups
- Account creation, rotation, locking, removal, collision, and unsupported
  authentication
- Metadata outage, partial query results, restart recovery, and interrupted
  reconciliation
- Port conflicts and topology UUID mismatch
- Import of default and customized Router configurations
- Keyring import success and unsupported-key-provider recovery
- Adoption of an existing Router metadata identity

### Release acceptance scenario

The defining end-to-end scenario is:

> Stop an existing MySQL Router, import its configuration into ProxySQL, start
> ProxySQL on the same Classic ports, verify the adopted instance through an
> unmodified MySQL Shell, and exercise topology failover plus native ProxySQL
> read/write routing without manually rebuilding servers or users.

## Delivery milestones

### 1. ProxySQL 4.0 chassis

- Compile out the legacy 4.0 bootstrap implementation.
- Add early plugin actions, minimal action services, runtime-ready lifecycle,
  atomic scoped configuration transactions, listener readiness, and secure
  secrets.

### 2. Plugin foundation

- Implement metadata 2.2 negotiation, bootstrap, registration, managed
  hostgroup allocation, Classic interfaces, baseline rules, managed-user sync,
  and Admin/stats surfaces.

### 3. Complete topology support

- Implement InnoDB Cluster/read replicas, ReplicaSet, ClusterSet, and the
  supported 8.4 option translations.

### 4. Existing Router takeover

- Implement configuration, dynamic-state, and keyring import; metadata
  identity adoption; and migration reports.

### 5. Version adapters and hardening

- Add tested newer-2.x adapters, failure injection, upgrade/re-bootstrap tests,
  full Shell/version matrices, documentation, and packaging.

These are internal milestones. The first generally supported release must
include all three topology types and the complete acceptance scenario rather
than exposing an InnoDB-Cluster-only product as the finished feature.

## Primary risks

1. **User synchronization fidelity.** MySQL `user@host` multiplicity and
   authentication-plugin diversity do not map perfectly to `mysql_users`.
   Explicit collision and unsupported-plugin diagnostics are essential.
2. **Metadata evolution.** Schema and Router-configuration capabilities must be
   version adapters, not scattered conditional SQL.
3. **Atomic publication.** Hostgroup membership, monitor role state, and
   persisted configuration must not expose partially reconciled generations.
4. **ClusterSet policy correctness.** Target switching, invalidation, and
   quorum behavior need topology-level integration tests, not only unit tests.
5. **Router keyring interoperability.** Key-provider and file-format variants
   require capability reporting and a secure fallback credential flow.
6. **Plugin ABI timing.** Early actions and late readiness are new chassis
   phases and must be tested with other plugins to avoid lifecycle regressions.

## References

- [MySQL Router 8.4 bootstrap](https://dev.mysql.com/doc/mysql-router/8.4/en/mysql-router-deploying-bootstrapping.html)
- [MySQL Router 8.4 configuration options](https://dev.mysql.com/doc/mysql-router/8.4/en/mysql-router-conf-options.html)
- [MySQL Shell 8.4 Router integration](https://dev.mysql.com/doc/mysql-shell/8.4/en/admin-api-integrating-router.html)
- [MySQL Shell 8.4 registered Routers](https://dev.mysql.com/doc/mysql-shell/8.4/en/registered-routers.html)
- [MySQL Shell 8.4 Router account configuration](https://dev.mysql.com/doc/mysql-shell/8.4/en/configuring-router-user.html)
- `doc/PLUGIN_API.md`
- `doc/plugin-chassis/ABI.md`
- `doc/internal/passthrough_authentication.md`
- `doc/mysqlx/README.md`
- `doc/mysqlx/MYSQL_ROUTER_PARITY.md`
