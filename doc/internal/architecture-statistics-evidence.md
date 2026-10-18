# Architecture evidence: statistics, telemetry, and supporting capabilities

Investigated 2026-10-18 on `docs/invariants-expansion`.
This records source-observed responsibilities, not newly ratified contracts.
Source inspection only; no runtime tests were executed.

## Statistics is an architectural capability with multiple cooperating owners

ProxySQL does not have one universal statistics store or one module that owns all
measurements. The `ProxySQL_Statistics` class is a concrete subsystem, while the
broader statistics capability includes runtime instrumentation, SQL projections,
historical persistence, event logging, and metrics exposition.
Collapsing these into a passing reference to “observability” loses responsibilities
that affect runtime cost, state lifetime, concurrency, and administrative behavior.

| Part | Responsibility and ownership | Evidence |
| --- | --- | --- |
| Runtime producers | Workers, Hostgroup Managers, authentication managers, query processors, caches, monitors, loggers, and Admin retain measurements associated with the state/work they own. | [Module metrics refresh](../../lib/ProxySQL_Admin.cpp#L2970), [SQL global aggregation](../../lib/ProxySQL_Admin_Stats.cpp#L584) |
| Admin statistics projection | Materializes SQL-visible tables by asking runtime owners for data; exposes current activity, pools, users, query rules, digests, errors, prepared statements, caches, TLS, and peer metadata. | [Schema inventory](../../lib/Admin_Bootstrap.cpp#L1037), [refresh dispatch](../../lib/ProxySQL_Admin.cpp#L1416), [projection implementation](../../lib/ProxySQL_Admin_Stats.cpp#L584) |
| `ProxySQL_Statistics` | Owns internal statistics database connections, historical sampling/storage, CPU/memory samples, time series aggregation, and timers that support scheduled persistence. | [Class](../../include/ProxySQL_Statistics.hpp#L112), [construction](../../lib/ProxySQL_Statistics.cpp#L138), [historical schema](../../lib/ProxySQL_Statistics.cpp#L274) |
| Query digest aggregation | Query processors own digest maps and accumulated execution measurements. Admin extracts these for SQL visibility and persistence; the SQL table is not the live execution accumulator. | [Concurrency and lifetime](../../include/query_processor.h#L62), [digest API](../../include/query_processor.h#L523), [MySQL projection](../../lib/ProxySQL_Admin_Stats.cpp#L2021) |
| Protocol event/audit loggers | Own event construction, buffering, file output/rotation, audit streams, and buffered event export into SQL/history storage. | [MySQL logger](../../include/MySQL_Logger.hpp#L323), [PostgreSQL logger](../../include/PgSQL_Logger.hpp#L232) |
| Prometheus exposition | Admin's serial exposer invokes module refresh; module metrics populate the shared registry. This is a separate exposure path from SQL projections. | [Refresh and exposer construction](../../lib/ProxySQL_Admin.cpp#L2970) |
| Optional TSDB | Samples the Prometheus registry, persists labelled points, downsamples, applies retention, and optionally records separate reachability probes. Compile-time and runtime enabled. | [TSDB API](../../include/ProxySQL_Statistics.hpp#L219), [sampler](../../lib/ProxySQL_Statistics.cpp#L1913), [probes](../../lib/ProxySQL_Statistics.cpp#L2046) |

“Owner” here describes responsibility for the data, not an assertion that a single
class performs every update or that an entire cross-module observation is atomic.

## SQL-visible statistics are projections, with operation-specific semantics

Admin constructs its in-memory statistics database separately from its monitor
connection and disk history connection. The persistent statistics file is also
opened by `ProxySQL_Statistics`; object ownership and storage-file identity are
therefore separate questions.
[Admin database initialization](../../lib/Admin_Bootstrap.cpp#L828),
[statistics database initialization](../../lib/ProxySQL_Statistics.cpp#L138).

Admin attaches monitor and historical databases into its SQL access surfaces.
`stats_history` gives access to persistent history; it is not another name for the
current in-memory runtime counters.
[Attachments](../../lib/Admin_Bootstrap.cpp#L1168).

Admin refresh dispatch inspects requested statistics tables and asks the relevant
owner to populate their projections. The digest and digest-reset paths explicitly
differ. A statistics SELECT must not universally be assumed to read an inert,
continuously maintained database snapshot.
[Refresh selection](../../lib/ProxySQL_Admin.cpp#L1518),
[digest refresh/reset dispatch](../../lib/ProxySQL_Admin.cpp#L1807).

The schema inventory itself demonstrates the breadth of the capability:

- Current client activity and sessions (`processlist`, PostgreSQL `stat_activity`).
- Used/free backend connections and per-hostgroup pool behavior.
- Query-rule hits, command counters, digest aggregates, and errors.
- Authentication/user usage, client-host caches, and passthrough authentication.
- Prepared-statement inventory and memory metrics.
- TLS certificates, process/global status, and peer synchronization metrics.
- Query event buffers and optional time-series status.

These are representations of several owning subsystems, rather than evidence
that Admin owns all the operational state being represented.
[MySQL/PGSQL table definitions](../../lib/Admin_Bootstrap.cpp#L1037).

## Historical sampling and scheduling

The Admin service loop invokes statistics timers and samples runtime owners for
connection/status and query-cache data. It also schedules digest persistence,
event-buffer drains, CPU/memory sampling, and optional TSDB maintenance.
These operations run from that loop; the presence of a statistics class does not
imply a dedicated statistics thread for each sampling concern.
[Periodic work](../../lib/ProxySQL_Admin.cpp#L2747).

`ProxySQL_Statistics::init()` creates historical connection, status-variable,
query-cache, CPU/memory, digest, and query-event schemas, plus optional TSDB tables.
Several older historical series have hour/day aggregates. This is a storage and
history role beyond exposing instantaneous counters.
[Historical schemas](../../lib/ProxySQL_Statistics.cpp#L274),
[hourly/daily sampling example](../../lib/ProxySQL_Statistics.cpp#L810).

The inspected periodic digest dump explicitly invokes the MySQL digest path.
Although PostgreSQL historical digest schemas and export APIs exist, that does not
establish that every schedule or setting is symmetric across protocols.
[Periodic digest dump](../../lib/ProxySQL_Admin.cpp#L2787),
[PostgreSQL history schema](../../lib/ProxySQL_Statistics.cpp#L309).

## Data lifetimes are materially different

| Data | Lifetime / transition |
| --- | --- |
| Active sessions and pool entries | Change as live execution proceeds; their SQL representation is an observation. |
| Runtime counters | Retained by the producer, with counter-specific reset/reload behavior; not uniformly persistent. |
| Query digest entries | Aggregated in runtime maps, with explicit extraction, reset, purge, and history export operations. |
| Query-event circular buffers | Bounded retained events; draining transfers ownership and clears buffered events. |
| File event/audit logs | Logger-managed output with configured files/rotation, distinct from SQL event history. |
| Historical SQLite rows | Disk-backed samples/dumps, distinct from producer lifetime and current-state projections. |
| TSDB samples | Timestamped metric/label/value rows with explicit downsampling and retention policy. |

[Digest ownership](../../include/query_processor.h#L62),
[MySQL event-buffer drain](../../include/MySQL_Logger.hpp#L282),
[PostgreSQL event-buffer drain](../../include/PgSQL_Logger.hpp#L207),
[TSDB downsampling](../../lib/ProxySQL_Statistics.cpp#L1588),
[TSDB retention](../../lib/ProxySQL_Statistics.cpp#L1641).

The optional TSDB monitor makes TCP reachability probes for historical telemetry.
Its existence does not make it the owner of normal database health/role decisions;
those responsibilities belong to the protocol monitor and backend management flow.
[TSDB probe implementation](../../lib/ProxySQL_Statistics.cpp#L1992).

## Other runtime capabilities that a complete architecture inventory must retain

The source inventory exposes additional substantial responsibilities. This list is
an inventory for decomposition, not a proposed equal-sized top-level hierarchy:

| Capability | Representative source owners |
| --- | --- |
| Frontend authentication and user policy | [MySQL Authentication](../../include/MySQL_Authentication.hpp#L83), [PostgreSQL Authentication](../../include/PgSQL_Authentication.h#L63) |
| Backend authentication and credential providers | [MySQL backend auth](../../lib/MySQL_Backend_Auth.cpp), [AWS IAM provider](../../lib/Aws_Iam_Provider.cpp), [passthrough cache](../../lib/MySQL_Passthrough_Auth_Cache.cpp) |
| Protocol handling, framing, and result delivery | [MySQL protocol](../../lib/MySQL_Protocol.cpp), [PostgreSQL protocol](../../lib/PgSQL_Protocol.cpp), [MySQL framing](../../lib/MySQLResultsetFramer.cpp), [PostgreSQL framing](../../lib/PgSQLResponseFramer.cpp) |
| Frontend session and transaction state | [MySQL session](../../lib/MySQL_Session.cpp), [PostgreSQL session](../../lib/PgSQL_Session.cpp), [transaction state](../../lib/TransactionState.cpp) |
| Query interpretation and policy | [Shared processor](../../lib/Query_Processor.cpp), [MySQL processor](../../lib/MySQL_Query_Processor.cpp), [PostgreSQL processor](../../lib/PgSQL_Query_Processor.cpp) |
| Backend selection, pooling, and health integration | [Base HGM](../../lib/Base_HostGroups_Manager.cpp), [MySQL HGM](../../lib/MySQL_HostGroups_Manager.cpp), [PostgreSQL HGM](../../lib/PgSQL_HostGroups_Manager.cpp) |
| Prepared-statement management | [MySQL statement metadata](../../include/MySQL_Prepared_Stmt_info.h), [PostgreSQL extended messages](../../lib/PgSQL_Extended_Query_Message.cpp) |
| Query caching | [Shared cache](../../lib/Query_Cache.cpp), [MySQL cache](../../lib/MySQL_Query_Cache.cpp), [PostgreSQL cache](../../lib/PgSQL_Query_Cache.cpp) |
| Discovery, name resolution, and locality | [Server discovery](../../lib/ProxySQL_ServerDiscovery.cpp), [DNS cache](../../lib/DNS_Cache.cpp), [AWS locality](../../lib/Aws_Locality_Manager.cpp) |
| Replication/causal position tracking | [GTID support](../../lib/proxysql_gtid.cpp), [GTID server data](../../include/GTID_Server_Data.h) |
| SQL, HTTP, and REST administration surfaces | [Admin](../../lib/ProxySQL_Admin.cpp), [HTTP server](../../lib/ProxySQL_HTTP_Server.cpp), [REST API](../../lib/ProxySQL_Restapi.cpp) |
| Statistics, query events, audit, and metrics history | The owners and flows established above. |

A useful architecture must decompose traffic serving into these responsibilities
before discussing narrow implementation rules. Counting a source file or class is
not sufficient evidence for promoting it to an architectural peer of the entire
traffic-serving runtime.
