# ProxySQL architecture overview

Source baseline: `f8ada9117`, investigated 2026-10-18. This is a source-grounded description
of the current implementation, with explicit design questions at the end. It is not a
claim that every observed mechanism is intended architecture or that all behaviors were
runtime-tested. [Product invariants](../../agents/invariants.md) remain the normative
contracts agreed with the maintainer.

## Reading the architecture

This overview explains the product's modules and how they collaborate. The detailed chapters
follow their actual responsibilities rather than giving small facilities the same scope as
the entire traffic runtime:

| Document | Coverage |
| --- | --- |
| [Runtime architecture](RUNTIME-ARCHITECTURE.md) | Protocols, workers, sessions, authentication, query analysis/policy, transaction/error handling, statements and cache execution |
| [Backend management](BACKEND-MANAGEMENT.md) | Hostgroups, server selection, local/shared pools, capacity, multiplexing, monitors, topology and discovery |
| [Administration and statistics](ADMINISTRATION-AND-STATISTICS.md) | Configuration, persistence, Cluster synchronization, management interfaces, live statistics, history, logs and metrics |
| [Visual guide](VISUAL-GUIDE.md) | Responsibility, execution, state, lifecycle and end-to-end sequence diagrams |
| [Project layout](PROJECT-LAYOUT.md) | Where those responsibilities live, build composition, dependency roles and authoritative development guides |
| [Verification record](VERIFICATION.md) | Source-review coverage, cross-review corrections, document/diagram checks and limits |

A capability, a C++ class, a thread and a storage representation are different things.
For example, the Statistics module owns historical storage and sampling functions, while
live measurements are produced by many runtime modules. Similarly, a Hostgroup Manager is
a shared runtime owner, not a single thread through which all database traffic passes.

## System context

ProxySQL terminates database client connections and speaks supported database protocols to
backend servers. It maintains its own frontend sessions, applies identity and query policy,
manages backend resources, and returns protocol responses. Backend databases execute SQL
and own their database transactions, locks, storage and replication.

A frontend connection does not imply a dedicated backend connection. A request may be answered
locally or from cache, and eligible backend connections may be reused across frontend sessions.
When transaction or backend-local state requires affinity, the runtime retains the association.

Operators and management tools change configuration through supported management interfaces.
ProxySQL Cluster synchronizes supported configuration between instances; it does not coordinate
their client sessions, transaction execution or connection ownership. Application-side instance
selection and deployment failover are separate from that configuration synchronization.

MySQL and PostgreSQL have parallel module families. Shared templates reduce duplication,
but protocol capabilities, authentication mechanisms, transaction handling and backend drivers
must be described per protocol where they differ. Optional interfaces and plugins extend the
product; they do not make every capability present in every build.

## Module architecture

### Protocol transport and result handling

Protocol workers drive nonblocking connections and streams. Protocol modules encode/decode
handshakes, commands and responses; data streams own network buffering and I/O state;
connection objects maintain backend protocol progress and session-related backend state.
Framing, result buffering/streaming, TLS and compression are part of these conversations.
They are distinct from deciding the query's destination or policy.

The MySQL side includes `MySQL_Protocol`, `MySQL_Data_Stream`, `MySQL_Connection` and
result-set/framing code. PostgreSQL has `PgSQL_Protocol`, `PgSQL_Data_Stream`,
`PgSQL_Connection`, extended-query messages and backend-protocol support. The applicable
PostgreSQL builds/runtime settings select libpq or native backend handling; the frontend
and backend authentication exchanges are not one transparent forwarded handshake.

Sources: [MySQL protocol](../../../lib/MySQL_Protocol.cpp),
[MySQL streams](../../../lib/mysql_data_stream.cpp),
[MySQL connections](../../../lib/mysql_connection.cpp),
[PostgreSQL protocol](../../../lib/PgSQL_Protocol.cpp),
[PostgreSQL connections](../../../lib/PgSQL_Connection.cpp).

### Workers and session execution

`MySQL_Thread` and `PgSQL_Thread` each drive many sessions from an event loop. Sessions are
state machines, not an OS thread per application connection. They combine protocol handling,
query policy, frontend state, backend borrowing and result progress into the execution of
an operation. Optional idle workers allow inactive sessions to be suspended and transferred
back to active workers; worker ownership is therefore not permanent session affinity.

A Session is the main execution orchestrator. It consumes Query Processor output, chooses
local/cache/backend paths, establishes required backend state, advances protocol work, and
handles completion, cancellation, retries and cleanup. It can retain multiple backend
associations and keeps transaction/session affinity separate from a single current request.

The event loops use ordinary `poll()` paths with conditional idle `epoll` handling. Libev is
used by other activities, including GTID-related work; it is not a universal description of
worker execution. Worker-local configuration and rule copies avoid repeatedly accessing all
shared configuration on the traffic path.

Sources: [MySQL worker](../../../lib/MySQL_Thread.cpp),
[PostgreSQL worker](../../../lib/PgSQL_Thread.cpp),
[base session](../../../include/Base_Session.h),
[MySQL Session](../../../lib/MySQL_Session.cpp),
[PostgreSQL Session](../../../lib/PgSQL_Session.cpp).

### Authentication, identity and account policy

Authentication comprises runtime account stores, frontend protocol negotiation and verification,
backend authentication, and supported external/provider integrations. These responsibilities
cooperate but are not interchangeable.

`MySQL_Authentication` and `PgSQL_Authentication` hold applied frontend/backend account
records, credential material, account policy and connection accounting. Account attributes
influence execution: TLS requirements, default hostgroup, transaction persistence, connection
limits, forwarding policy and, where supported, schema policy. Editable user tables are a
configuration representation; runtime authentication reads the installed stores.

Protocol/session code performs frontend wire authentication. Supported mechanisms and secret
requirements differ: MySQL native-password/caching-SHA2 and optional mechanisms are not
PostgreSQL MD5/SCRAM. Backend connections authenticate separately with their applicable
identity and credentials. Supported LDAP mappings, MySQL passthrough verification/cache and
v4.0 AWS IAM token/provider paths introduce distinct identity flows. Admin/stats-interface
credentials also use runtime authentication facilities with tier-dependent scope handling.

TLS and account authentication have related but distinct jobs. A successful encrypted
connection does not itself authorize a database identity. Database object permissions remain
backend responsibilities. Query-level firewall and SQL-injection controls belong to query
policy and execution, rather than the account store.

Sources and mechanism/tier qualifications: [runtime authentication chapter](RUNTIME-ARCHITECTURE.md),
[MySQL account store](../../../include/MySQL_Authentication.hpp),
[PostgreSQL account store](../../../include/PgSQL_Authentication.h),
[backend policy](../../../lib/MySQL_Backend_Auth.cpp).

### Query Processor: analysis, programmable policy and accounting

The Query Processor is a major subsystem rather than merely a hostgroup router. The shared
template is specialized for MySQL and PostgreSQL, with protocol-specific analysis and output.

| Responsibility | What the subsystem provides |
| --- | --- |
| Query characterization | Supported normalization/tokenization, digest identity/text, command classification and query annotations |
| Rule matching | User/schema, frontend/listener attributes, digest and SQL-pattern predicates; configured matching engines |
| Evaluation control | Ordered rules, input/output flags, chaining/iteration, terminating apply, weighted flag selection and fast-routing lookup |
| Transformation/local outcomes | Rewritten query text and policy-requested local error/OK responses |
| Execution policy | Destination, freshness constraints, cache controls, delay, timeout, retries, connection/multiplexing controls and logging decisions |
| Query admission | Firewall whitelist policy and related SQL-injection configuration, integrated with Session checks |
| Measurement | Rule hits, command counters/timing and query-digest aggregation, retrieval/reset and memory management |

The output is consumed by Session and backend services. Setting a cache TTL does not itself
look up or store results. Setting retry policy does not bypass transaction/progress guards.
Likewise, a field in the shared output structure does not establish support in both protocols:
MySQL Session implements mirroring; the inspected PostgreSQL consumer warns and ignores mirror
outputs. MySQL has additional GTID-related policy and supported fast-forward transitions.

Sources: [shared processor](../../../lib/Query_Processor.cpp),
[policy output](../../../include/query_processor.h),
[MySQL specialization](../../../include/MySQL_Query_Processor.h),
[PostgreSQL specialization](../../../include/PgSQL_Query_Processor.h).
The [runtime chapter](RUNTIME-ARCHITECTURE.md) maps policy outputs to enforcement consumers.

### Backend selection, connection pools and multiplexing

Hostgroup Managers own runtime hostgroup/server objects and shared pools. Server selection
and connection compatibility are different decisions: first find an eligible backend resource,
then find or establish a connection usable for the frontend's identity, options and state.
Workers also maintain local reusable connection caches. Local caching and shared-pool
accounting must be understood together, rather than depicted as two independent resource pools.

Eligibility reflects configured backend status/capacity, operational health and topology,
selection policy and supported freshness constraints. Reuse additionally depends on liveness,
transaction state, protocol completion and session-state compatibility. Two compatible frontends
can reuse a backend without a reset. State differences can be synchronized where supported;
backend-local dependencies can pin the connection. Reset is a distinct recovery/cleanup path.

A server's ONLINE/SHUNNED/OFFLINE statuses are not connection states or a required linear
progression. Server status can change while connections are in use. Admission, retention,
return, draining and destruction have different decisions, and active transactions constrain
what may be retried or lent to another frontend.

Sources: [shared hostgroup infrastructure](../../../lib/Base_HostGroups_Manager.cpp),
[MySQL HGM](../../../lib/MySQL_HostGroups_Manager.cpp),
[MySQL selection](../../../lib/MyHGC.cpp),
[connection-fit selection](../../../lib/MySrvConnList.cpp),
[PostgreSQL HGM](../../../lib/PgSQL_HostGroups_Manager.cpp).
See [backend management](BACKEND-MANAGEMENT.md) for algorithms, capacity and protocol differences.

### Monitoring and topology integration

Monitors perform connect/health, role and replication-condition observations according to the
supported protocol/topology. They retain observation history and request operational changes
through Hostgroup Manager actions. Hostgroup management owns resource selection and pools;
monitoring is not a second pool owner.

MySQL monitoring includes ordinary replication and supported Galera, Group Replication and
Aurora/RDS-specific behavior. PostgreSQL has its own monitoring scheduler and health/role/lag
logic; MySQL topology algorithms should not be assigned to it by analogy. DNS, discovery and
optional locality/provider services supply additional inputs with their own lifetimes.

Monitoring is one producer of operational backend state. Administration applies configured
state; traffic failures can also affect availability. A difference between operational server
state and editable configuration is therefore not, by itself, evidence of corruption.

Sources: [MySQL Monitor](../../../lib/MySQL_Monitor.cpp),
[PostgreSQL Monitor](../../../lib/PgSQL_Monitor.cpp),
[discovery](../../../lib/ProxySQL_ServerDiscovery.cpp),
[DNS](../../../lib/DNS_Cache.cpp), and [backend chapter](BACKEND-MANAGEMENT.md).

### Query cache and statement resources

Query caches store result data; connection pools store reusable backend sessions. Query policy
supplies caching controls, while Session applies operation/state eligibility and performs
lookup/store. A cache hit can avoid backend borrowing entirely. Cache keys and ownership must
be established from the actual implementation, not inferred from query-digest statistics.
Expiration, memory limits and background purging are cache responsibilities.

Prepared-statement managers retain shared statement metadata, with frontend/backend-local
maps representing protocol identities and lifetimes. MySQL binary prepared statements and
PostgreSQL prepared statements/portals require different treatment. Statement preparation,
execution, metadata caching, backend association and cleanup interact with pooling but are
not equivalent to pinning every prepared operation forever.

Sources: [shared cache](../../../lib/Query_Cache.cpp),
[MySQL cache](../../../lib/MySQL_Query_Cache.cpp),
[PostgreSQL cache](../../../lib/PgSQL_Query_Cache.cpp),
[MySQL statements](../../../lib/MySQL_PreparedStatement.cpp),
[PostgreSQL statements](../../../lib/PgSQL_PreparedStatement.cpp), and
[runtime chapter](RUNTIME-ARCHITECTURE.md).

### Administration, configuration and synchronization

Admin provides SQL management execution, configuration schemas, bootstrap/upgrade, variable
handling and installation into runtime owners. Supporting HTTP/REST/web facilities and the
external scheduler are related management modules with their own execution paths. The
SQLite3 server is a separate optional protocol server; it should not be treated as a synonym
for the Admin configuration database.

Configuration has distinct representations and operations:

| Representation | Authority and transition |
| --- | --- |
| Configuration-file/bootstrap input | Startup input under its supported precedence and mode; not the live execution store |
| Editable MEMORY tables | Administrative configuration to be installed or persisted |
| Persistent DISK database | Persisted configuration; copying it and applying runtime state are separate operations |
| Applied runtime owners | HGM, Auth, Query Processor, thread handlers and other installed service state |
| Published representations | Runtime tables/resultsets, metadata and worker views derived through the owner's publication path |

Worker variables, query rules and backend state have different publication/refresh mechanisms.
There is no source basis for treating every LOAD as one simultaneous global switch. Supported
managed/bootstrap paths also mean that ordinary SQL LOAD is not the only possible runtime writer.

Cluster belongs within configuration administration. Peers compare per-family checksums,
versions/epochs and configured thresholds, fetch supported datasets and apply them locally.
Persistence on receipt is separately configurable. Some server datasets are retained published
resultsets, distinct from fresh queries of editable configuration. Their publication and pointer
lifetime still require the actual owner's access protocol. Configuration synchronization is
not consensus, leader-based execution coordination or query/session replication.
Runtime-only server pulls can install directly in HGM; configuration materialization for
persistence is a separate path. MEMORY is not a mandatory intermediate for every pull.

Sources: [Admin](../../../lib/ProxySQL_Admin.cpp),
[bootstrap](../../../lib/Admin_Bootstrap.cpp),
[variables](../../../lib/Admin_FlushVariables.cpp),
[Cluster](../../../lib/ProxySQL_Cluster.cpp), and
[administration chapter](ADMINISTRATION-AND-STATISTICS.md).

### Statistics, history, logs and metrics

Statistics is a concrete module and a broader product capability with multiple cooperating
owners. It must not disappear into a generic mention of observability.

| Part | Responsibility |
| --- | --- |
| Runtime instrumentation | Workers, HGM, Auth, QP, caches, monitors and other modules retain their own counters/observations |
| Query statistics | QP command counters, rule hits and digest aggregates characterize executed traffic and policy |
| Admin SQL statistics | Demand-driven projections expose live activity, pools, users, digests, statements, errors and other owners; some access paths reset or drain data |
| `ProxySQL_Statistics` | Internal memory/disk statistics connections, sampling timers, historical tables, aggregation and scheduled persistence |
| Protocol loggers | Query events, audit, file/buffer management and supported export/drain paths |
| Metrics export | Module metrics refreshed/exposed through Admin/Prometheus registry and exposer paths |
| Optional TSDB/FFTO | Time-series sampling/history/dashboard and traffic observation, subject to tier and feature support |

A live counter, a resettable digest entry, a SQL projection, a buffered event, a file record
and a historical sample have different lifetimes. Admin can expose or persist data without
becoming the execution-state owner. The Admin service loop schedules several statistics
activities; the Statistics class does not imply one dedicated statistics thread per task.
Protocol history/scheduling coverage is not uniformly symmetric.

Sources: [Statistics](../../../lib/ProxySQL_Statistics.cpp),
[Statistics interface](../../../include/ProxySQL_Statistics.hpp),
[Admin statistics](../../../lib/ProxySQL_Admin_Stats.cpp),
[digest aggregation](../../../lib/QP_query_digest_stats.cpp),
[MySQL logger](../../../lib/MySQL_Logger.cpp),
[PostgreSQL logger](../../../lib/PgSQL_Logger.cpp), and
[statistics chapter](ADMINISTRATION-AND-STATISTICS.md).

## Cross-module execution and state ownership

The runtime combines thread-local execution with shared managers and publication/copy paths.
It is neither a collection of isolated workers nor one globally locked state machine.

| Execution context | Role and collaboration |
| --- | --- |
| Serving main thread | Runtime construction, orchestration, worker-heartbeat watchdog and teardown/reload |
| Protocol workers / optional idle workers | Session progress, local configuration/rules, I/O and local pool reuse |
| Admin listener / client handlers | Management execution, scheduler/statistics periodic work and SQL exposure |
| Monitor execution | Protocol/topology-specific checks and operational HGM actions |
| HGM background work | Connection maintenance and supported GTID activity |
| Cache purge thread | Shared background purging for protocol query caches |
| Cluster peer threads | Peer metadata observation and local configuration synchronization |
| Plugin-owned activity | Optional listeners, workers, controllers and management work through supported interfaces |

Shared ownership makes access/lifetime protocols important; it does not justify arbitrary
additional locks. Conversely, a precomputed copy does not remove the need to establish its
lifetime. Logical separation does not prove complete implementation isolation: current Session
paths can use Admin SQLite for some local responses. Such coupling should be described as
observed implementation and classified before imposing a cleaner intended layering.

## Process lifecycle and product composition

### Supervision, runtime generations and readiness

An optional angel process supervises the serving child. The serving main thread's watchdog is
a different mechanism. In-process STOP/START and reload/restart can destroy and reconstruct
runtime modules without creating a new process. A process-global pointer can therefore refer
to an object whose lifetime is only one runtime generation.

Startup has distinct conditions: object construction, schema materialization, configuration
installation, worker registration/readiness, extension availability and public admission.
The implementation's call order contains both necessary dependencies and incidental sequencing.
The architecture should ratify dependency reasons rather than canonize every adjacent init call.

Verified dependencies include schema declaration before materialization, borrowed services
before full-service plugin callbacks, worker registration before startup-barrier release,
and stopping/draining users before provider destruction. Partial startup must be cancellable:
workers created before listener startup must still be released and joined on failure.

Current plugin init/start failure aborts startup, while a `runtime_ready` failure logs degraded
readiness and allows listener startup. A readiness callback name is not proof of an admission
policy. Shutdown drains Admin clients and retires plugins while dependencies remain, releases
bootstrap waits, joins execution and destroys modules. Active plugin-manager borrowers have
pinning/unpublication protection; other leases/controllers need their own supported contract.

Sources: [main orchestration](../../../src/main.cpp),
[startup gate](../../../include/ProxySQL_StartupGate.h),
[plugin manager](../../../lib/ProxySQL_PluginManager.cpp), and
[execution evidence](../../internal/architecture-execution-evidence.md).

### Tiers and extensions

The same source builds distinct product compositions. The top-level Makefile defines
`PROXYSQL40 -> PROXYSQL31 -> FFTO + TSDB + ED25519`. Stable is the default core tier;
Innovative enables the stated additions; the v4.0 tier adds the dynamic plugin chassis.
Presence in the repository does not imply presence in every binary.

Shipped plugin families include mysqlx, duckdb, genai and mysql_router. Their schemas,
commands, listeners, query hooks and management adapters have different integration
roles. Plugin lifecycle includes discovery/CLI registration, optional schema declaration,
Admin materialization, supported early actions, init, start, runtime-ready work and stop.
Use these named stages rather than stale phase counts. Stop pairs with successful init,
even if start subsequently fails.

| Plugin family | Product contribution and actual integration |
| --- | --- |
| mysqlx | Additional X Protocol listeners/workers with plugin-owned configuration and Admin schema/commands; it is not the core MySQL worker presented under another port. |
| duckdb | Embedded DuckDB execution through independent MySQL/PostgreSQL-protocol listeners, plugin-owned engine/listener lifetime and variable/command integration. This path executes in an embedded engine rather than an external backend. |
| genai | MCP/GenAI-related services, schema discovery/vector/LLM integration and anomaly-detection query hooks that can deny selected simple queries; the plugin owns those optional services and their startup. |
| mysql_router | Router-compatible bootstrap/configuration and runtime reconciliation using the applicable core configuration services and runtime-ready integration. |

Sources: [mysqlx lifecycle](../../../plugins/mysqlx/src/mysqlx_plugin.cpp),
[DuckDB lifecycle](../../../plugins/duckdb/src/duckdb_plugin.cpp) and [guide](../../duckdb/index.md),
[GenAI lifecycle](../../../plugins/genai/src/plugin_main.cpp),
[Router integration](../../../plugins/mysql_router/src/plugin.cpp).
The detailed optional product documents remain separate from the core architecture. Available
discovery/metadata-provider interfaces without an in-tree installer are explicitly identified
as such in the backend chapter; their declaration is not evidence of a shipped provider.

Supported plugin table registration is distinct from the removed server-module machinery.
History `4e957ac3f` removed the latter because no shipped plugin used it; the ABI retains a
rejecting compatibility slot. That slot is not evidence of an operational extension path.
Core/plugin contracts and Stable isolation remain constrained by product invariants.

Sources: [tier/build selection](../../../Makefile),
[plugin descriptor/services](../../../include/ProxySQL_Plugin.h),
[manager](../../../include/ProxySQL_PluginManager.h), and [plugin sources](../../../plugins).

## Design questions requiring maintainer intent

These are bounded gaps between source evidence and intended architecture, not a list of
new mechanisms to implement:

- **Visibility guarantees:** what operator-facing consistency is promised across independently
  published configuration families and worker-local refresh points?
- **Dependency intent:** which startup relationships are required service dependencies, and
  which are historical sequencing that can change without altering a contract?
- **Admission policy:** which optional capability failures must prevent serving, and which
  intentionally permit degraded operation?
- **Accepted coupling:** which cross-area accesses are supported services and which are debt
  to remove before claiming strict layering?
- **Extension quiescence:** what admission/draining contract applies to each callback, provider
  lease and plugin-owned execution context?

These questions supplement a full module architecture; they are not its substitute.

## Corrections to the September 2025 baseline

The refreshed collection retains the earlier breadth while removing unsupported diagrams or
claims: universal four-thread digest processing, lock-free digest maps, a transparent relayed
PostgreSQL authentication exchange, Cluster leader/push coordination, one mandatory server-status
progression, and generic query-cache keys derived from digest statistics. It also updates build
tiers, native PostgreSQL handling, shipped plugins and the concrete Statistics/history model.
Where capability or behavior was not established, the detailed chapter states the qualification.
